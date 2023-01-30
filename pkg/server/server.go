// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net"
	"net/netip"

	"go.uber.org/zap"
	grpc "google.golang.org/grpc"

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
	var s *Server
	if o.TedEnable {
		s = &Server{
			ted: &table.LsTed{
				Id:    1,
				Nodes: map[uint32]map[string]*table.LsNode{},
			},
		}

		// Update Ted
		go func() {
			for {
				tedElems := <-tedElemsChan
				s.ted = &table.LsTed{
					Id:    s.ted.Id,
					Nodes: map[uint32]map[string]*table.LsNode{},
				}

				for _, tedElem := range tedElems {
					tedElem.UpdateTed(s.ted)
				}
				logger.Info("Update TED")
			}
		}()
	} else {
		s = &Server{
			ted: nil,
		}
	}

	s.logger = logger
	errChan := make(chan ServerError)
	// Start PCEP listen
	go func() {
		if err := s.Serve(o.PcepAddr, o.PcepPort); err != nil {
			errChan <- ServerError{
				Server: "pcep",
				Error:  err,
			}
		}
	}()
	// Start gRPC listen
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
	sessionId := uint8(1)
	for {
		ss := NewSession(sessionId, s.logger)
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
		sessionId += 1
	}
}

func (s *Server) closeSession(session *Session) {
	session.tcpConn.Close()

	// Remove Session List
	for i, v := range s.sessionList {
		if v.sessionId == session.sessionId {
			s.sessionList[i] = s.sessionList[len(s.sessionList)-1]
			s.sessionList = s.sessionList[:len(s.sessionList)-1]
			break
		}
	}
}

func (s *Server) SearchSession(peerAddr netip.Addr) *Session {
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr == peerAddr {
			if !pcepSession.isSynced {
				break
			}
			return pcepSession
		}
	}
	return nil
}

// return registered SR Policy map with key sessionAddr
func (s *Server) SRPolicies() map[netip.Addr][]table.SRPolicy {
	srPolicies := map[netip.Addr][]table.SRPolicy{}
	for _, ss := range s.sessionList {
		srPolicies[ss.peerAddr] = ss.srPolicies
	}
	return srPolicies
}
