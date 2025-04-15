// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"

	"go.uber.org/zap"
	grpc "google.golang.org/grpc"

	"github.com/nttcom/pola/internal/pkg/table"
)

type Server struct {
	sessionList []*Session
	ted         *table.LsTED
	logger      *zap.Logger
}

type PCEOptions struct {
	PCEPAddr  string
	PCEPPort  string
	GRPCAddr  string
	GRPCPort  string
	TEDEnable bool
	USidMode  bool
}

func NewPCE(o *PCEOptions, logger *zap.Logger, tedElemsChan chan []table.TEDElem) ServerError {
	s := &Server{logger: logger}
	if o.TEDEnable {
		s.ted = &table.LsTED{
			ID:    1,
			Nodes: map[uint32]map[string]*table.LsNode{},
		}

		// Update TED
		go func() {
			for {
				tedElems := <-tedElemsChan
				ted := &table.LsTED{
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
		if err := s.Serve(o.PCEPAddr, o.PCEPPort, o.USidMode); err != nil {
			errChan <- ServerError{
				Server: "pcep",
				Error:  err,
			}
		}
	}()

	go func() {
		grpcServer := grpc.NewServer()
		apiServer := NewAPIServer(s, grpcServer, o.USidMode, logger)
		if err := apiServer.Serve(o.GRPCAddr, o.GRPCPort); err != nil {
			errChan <- ServerError{
				Server: "grpc",
				Error:  err,
			}
		}
	}()

	serverError := <-errChan
	logger.Error("Server encountered an error", zap.String("server", serverError.Server), zap.Error(serverError.Error))
	return serverError
}

func (s *Server) Serve(address string, port string, usidMode bool) error {
	a, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("failed to parse address %s: %w", address, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("failed to convert port %s: %w", port, err)
	}
	if p > math.MaxUint16 {
		return errors.New("invalid PCEP listen port")
	}
	localAddr := netip.AddrPortFrom(a, uint16(p))

	s.logger.Info("start listening on PCEP port", zap.String("address", localAddr.String()))
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(localAddr))
	if err != nil {
		return fmt.Errorf("failed to listen on PCEP port %s: %w", localAddr.String(), err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			s.logger.Warn("failed to close PCEP listener", zap.Error(err))
		}
	}()

	sessionID := uint8(1)
	for {
		tcpConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("failed to accept TCP connection: %w", err)
		}
		peerAddrPort, err := netip.ParseAddrPort(tcpConn.RemoteAddr().String())
		if err != nil {
			return fmt.Errorf("failed to parse remote address %s: %w", tcpConn.RemoteAddr().String(), err)
		}
		ss := NewSession(sessionID, peerAddrPort.Addr(), tcpConn, s.logger)
		ss.logger.Info("start PCEP session")

		s.sessionList = append(s.sessionList, ss)
		go func() {
			ss.Established()
			s.closeSession(ss)
			ss.logger.Info("close PCEP session")
		}()
		sessionID++
	}
}

func (s *Server) closeSession(session *Session) {
	if err := session.tcpConn.Close(); err != nil {
		s.logger.Warn("failed to close TCP connection", zap.Error(err))
	}

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
// If not exist, return nil
func (s *Server) SearchSession(peerAddr netip.Addr, onlySynced bool) *Session {
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr == peerAddr {
			if !onlySynced || pcepSession.isSynced {
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
