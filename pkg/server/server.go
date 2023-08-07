// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"
	grpc "google.golang.org/grpc"

	"github.com/k0kubun/pp"
	"github.com/nttcom/pola/internal/pkg/table"
)

type Server struct {
	sessionList []*Session
	ted         *table.LsTed
	logger      *zap.Logger
}

type PceOptions struct {
	PcepAddr  string
	PcepPort  string
	GrpcAddr  string
	GrpcPort  string
	TedEnable bool
}

func NewPce(o *PceOptions, logger *zap.Logger, tedElemsChan chan []table.TedElem) ServerError {
	s := &Server{logger: logger}
	if o.TedEnable {
		s.ted = &table.LsTed{
			ID:    1,
			Nodes: map[uint32]map[string]*table.LsNode{},
		}

		// Update TED
		go func() {
			for {
				tedElems := <-tedElemsChan
				ted := &table.LsTed{
					ID:    s.ted.ID,
					Nodes: map[uint32]map[string]*table.LsNode{},
				}
				ted.Update(tedElems)
				s.ted = ted
				logger.Info("Update TED")
			}
		}()
	}

	errChan := make(chan ServerError)
	go func() {
		if err := s.Serve(o.PcepAddr, o.PcepPort); err != nil {
			errChan <- ServerError{
				Server: "pcep",
				Error:  err,
			}
		}
	}()

	go func() {
		grpcServer := grpc.NewServer()
		apiServer := NewAPIServer(s, grpcServer)
		if err := apiServer.Serve(o.GrpcAddr, o.GrpcPort); err != nil {
			errChan <- ServerError{
				Server: "grpc",
				Error:  err,
			}
		}
	}()

	session := NewSession(0, logger)
	for {
		// cisco の session
		if session = s.SearchSession(netip.MustParseAddr("10.100.0.2")); session != nil {
			break
		}
	}

	srPolicy := table.SRPolicy{
		PlspID: 3,
		Name:   "sr-policy",
		SegmentList: []table.Segment{
			table.NewSegmentSRMPLS(10000),
		},
		SrcAddr:    netip.MustParseAddr("10.100.0.2"),
		DstAddr:    netip.MustParseAddr("10.100.0.1"),
		Color:      1000,
		Preference: 10,
	}
	srPolicy2 := table.SRPolicy{
		PlspID: 4,
		Name:   "sr-policy2",
		SegmentList: []table.Segment{
			table.NewSegmentSRMPLS(20000),
		},
		SrcAddr:    netip.MustParseAddr("10.100.0.2"),
		DstAddr:    netip.MustParseAddr("10.100.0.1"),
		Color:      2000,
		Preference: 10,
	}

	session.RequestSRPolicyCreated(srPolicy)
	session.RequestSRPolicyCreated(srPolicy2)
	pp.Println("!!!!!!!!!!!!!!!!! add sr policy !!!!!!!!!!!!!!!!")
	time.Sleep(30 * time.Second)
	if err := session.RequestSRPolicyDeleted(srPolicy); err != nil {
		pp.Println("sendDeleteLsp srPolicy Error")
		pp.Println(err)
	}
	if err := session.RequestSRPolicyDeleted(srPolicy2); err != nil {
		pp.Println("sendDeleteLsp srPolicy2 Error")
		pp.Println(err)
	}
	pp.Println("!!!!!!!!!!!!!!!!! delete sr policy !!!!!!!!!!!!!!!!")

	serverError := <-errChan
	return serverError
}

func (s *Server) Serve(address string, port string) error {
	localAddr, err := netip.ParseAddrPort(address + ":" + port)
	if err != nil {
		return err
	}
	s.logger.Info("PCEP listen", zap.String("listenInfo", localAddr.String()))
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(localAddr))
	if err != nil {
		return err
	}
	defer l.Close()

	sessionID := uint8(1)
	for {
		ss := NewSession(sessionID, s.logger)
		ss.tcpConn, err = l.AcceptTCP()
		if err != nil {
			return err
		}
		peerAddrPort, err := netip.ParseAddrPort(ss.tcpConn.RemoteAddr().String())
		if err != nil {
			return err
		}
		ss.peerAddr = peerAddrPort.Addr()
		s.sessionList = append(s.sessionList, ss)
		go func() {
			ss.Established()
			s.closeSession(ss)
			s.logger.Info("Close PCEP session", zap.String("session", ss.peerAddr.String()))
		}()
		sessionID++
	}
}

func (s *Server) closeSession(session *Session) {
	session.tcpConn.Close()

	// Remove Session List
	for i, v := range s.sessionList {
		if v.sessionID == session.sessionID {
			s.sessionList[i] = s.sessionList[len(s.sessionList)-1]
			s.sessionList = s.sessionList[:len(s.sessionList)-1]
			break
		}
	}
}

func (s *Server) SearchSession(peerAddr netip.Addr) *Session {
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr == peerAddr && pcepSession.isSynced {
			return pcepSession
		}
	}
	return nil
}

// SRPolicies returns a map of registered SR Policy with key sessionAddr
func (s *Server) SRPolicies() map[netip.Addr][]table.SRPolicy {
	srPolicies := make(map[netip.Addr][]table.SRPolicy)
	for _, ss := range s.sessionList {
		if ss.isSynced {
			srPolicies[ss.peerAddr] = ss.srPolicies
		}
	}
	return srPolicies
}
