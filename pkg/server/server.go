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
	"slices"
	"strconv"
	"sync"

	"go.uber.org/zap"
	grpc "google.golang.org/grpc"

	"github.com/nttcom/pola/pkg/table"
)

type Server struct {
	sessionMu   sync.RWMutex // guards sessionList; written from the PCEP accept/close goroutines, read from gRPC handler goroutines.
	sessionList []*Session
	tedMu       sync.RWMutex // guards ted; written from the TED-update goroutine, read from gRPC handler goroutines.
	ted         *table.LsTED
	logger      *zap.Logger
	asn         uint32
}

// TED returns the current TED snapshot. Safe for concurrent use with setTED.
func (s *Server) TED() *table.LsTED {
	s.tedMu.RLock()
	defer s.tedMu.RUnlock()
	return s.ted
}

func (s *Server) setTED(ted *table.LsTED) {
	s.tedMu.Lock()
	defer s.tedMu.Unlock()
	s.ted = ted
}

type PCEOptions struct {
	PCEPAddr  string
	PCEPPort  string
	GRPCAddr  string
	GRPCPort  string
	TEDEnable bool
	USidMode  bool
	ASN       uint32
}

func NewPCE(o *PCEOptions, logger *zap.Logger, tedElemsChan chan []table.TEDElem) Error {
	s := &Server{
		logger: logger,
		asn:    o.ASN,
	}
	if o.TEDEnable {
		s.setTED(&table.LsTED{
			Nodes: map[string]*table.LsNode{},
		})

		// Update TED
		go func() {
			for {
				tedElems := <-tedElemsChan
				ted := &table.LsTED{
					Nodes: map[string]*table.LsNode{},
				}
				ted.Update(tedElems, o.ASN)
				s.setTED(ted)
				logger.Debug("Update TED")
			}
		}()
	}

	errChan := make(chan Error)
	go func() {
		if err := s.Serve(o.PCEPAddr, o.PCEPPort, o.USidMode); err != nil {
			errChan <- Error{
				Server: "pcep",
				Error:  err,
			}
		}
	}()

	go func() {
		grpcServer := grpc.NewServer()
		apiServer := NewAPIServer(s, grpcServer, o.USidMode, logger)
		if err := apiServer.Serve(o.GRPCAddr, o.GRPCPort); err != nil {
			errChan <- Error{
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
	if p < 0 || p > math.MaxUint16 {
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
		ss := NewSession(sessionID, peerAddrPort.Addr(), tcpConn, s.logger, s.TED(), s.asn)
		ss.logger.Info("start PCEP session")

		s.sessionMu.Lock()
		s.sessionList = append(s.sessionList, ss)
		s.sessionMu.Unlock()
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
	session.clearSRPolicyIntents()

	// Remove Session List
	s.sessionMu.Lock()
	for i, v := range s.sessionList {
		if v.sessionID == session.sessionID {
			s.sessionList[i] = s.sessionList[len(s.sessionList)-1]
			s.sessionList = s.sessionList[:len(s.sessionList)-1]
			break
		}
	}
	s.sessionMu.Unlock()
}

// SearchSession returns a struct pointer of (Synced) session.
// If not exist, return nil
func (s *Server) SearchSession(peerAddr netip.Addr, onlySynced bool) *Session {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr == peerAddr {
			if !onlySynced || pcepSession.IsSynced() {
				return pcepSession
			}
		}
	}
	return nil
}

// Sessions returns a snapshot copy of the current session list, safe for concurrent use.
func (s *Server) Sessions() []*Session {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	return slices.Clone(s.sessionList)
}

// SRPolicies returns a map of registered SR Policy with key sessionAddr
func (s *Server) SRPolicies() map[netip.Addr][]*table.SRPolicy {
	s.sessionMu.RLock()
	sessions := slices.Clone(s.sessionList)
	s.sessionMu.RUnlock()

	srPolicies := make(map[netip.Addr][]*table.SRPolicy)
	for _, ss := range sessions {
		if ss.IsSynced() {
			srPolicies[ss.peerAddr] = ss.SRPolicies()
		}
	}
	return srPolicies
}
