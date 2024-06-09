// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net"
	"net/netip"
	"strconv"

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
	USidMode  bool
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
				logger.Debug("Update TED")
			}
		}()
	}

	errChan := make(chan ServerError)
	go func() {
		if err := s.Serve(o.PcepAddr, o.PcepPort, o.USidMode); err != nil {
			errChan <- ServerError{
				Server: "pcep",
				Error:  err,
			}
		}
	}()

	go func() {
		grpcServer := grpc.NewServer()
		apiServer := NewAPIServer(s, grpcServer, o.USidMode, logger)
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

func (s *Server) Serve(address string, port string, usidMode bool) error {
	a, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	localAddr := netip.AddrPortFrom(a, uint16(p))

	s.logger.Info("Start listening on PCEP port", zap.String("address", localAddr.String()))
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(localAddr))
	if err != nil {
		return err
	}
	defer l.Close()

	sessionID := uint8(1)
	for {
		tcpConn, err := l.AcceptTCP()
		if err != nil {
			return err
		}
		peerAddrPort, err := netip.ParseAddrPort(tcpConn.RemoteAddr().String())
		if err != nil {
			return err
		}
		ss := NewSession(sessionID, peerAddrPort.Addr(), tcpConn, s.logger)
		ss.logger.Info("Start PCEP session")

		s.sessionList = append(s.sessionList, ss)
		go func() {
			ss.Established()
			s.closeSession(ss)
			ss.logger.Info("Close PCEP session")
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

// SearchSession returns a struct pointer of (Synced) session.
// if not exist, return nil
func (s *Server) SearchSession(peerAddr netip.Addr, onlySynced bool) *Session {
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr == peerAddr {
			if !(onlySynced) || pcepSession.isSynced {
				return pcepSession
			}
		}
	}
	return nil
}

// SRPolicies returns a map of registered SR Policy with key sessionAddr
func (s *Server) SRPolicies() map[netip.Addr][]*table.SRPolicy {
	srPolicies := make(map[netip.Addr][]*table.SRPolicy)
	for _, ss := range s.sessionList {
		if ss.isSynced {
			srPolicies[ss.peerAddr] = ss.srPolicies
		}
	}
	return srPolicies
}
