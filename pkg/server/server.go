// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
	grpc "google.golang.org/grpc"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

// Maximum time to wait for the PCEP Close message during shutdown.
const defaultShutdownSendCloseTimeout = 2 * time.Second

type Server struct {
	sessionMu   sync.RWMutex // guards sessionList
	sessionList []*Session
	tedMu       sync.RWMutex // guards ted
	ted         *table.LsTED
	logger      *zap.Logger
	asn         uint32

	listenerMu sync.Mutex // guards listener and closed
	listener   tcpListener
	closed     bool // set by Shutdown; suppresses Serve/AcceptTCP errors

	shutdownSendCloseTimeout time.Duration // zero uses the default
}

type tcpListener interface {
	AcceptTCP() (*net.TCPConn, error)
	Close() error
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

// NewPCE starts the PCEP and gRPC servers and blocks until they stop.
// It returns an error if either server exits with a failure.
func NewPCE(ctx context.Context, o *PCEOptions, logger *zap.Logger, tedElemsChan chan []table.TEDElem) Error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s := &Server{
		logger: logger,
		asn:    o.ASN,
	}
	if o.TEDEnable {
		s.setTED(&table.LsTED{
			Nodes: map[string]*table.LsNode{},
		})
		go s.syncTEDLoop(ctx, tedElemsChan, o.ASN, logger)
	}

	grpcServer := grpc.NewServer()
	apiServer := NewAPIServer(s, grpcServer, o.USidMode, logger)

	type result struct {
		server string
		err    error
	}
	resultChan := make(chan result, 2)

	go func() {
		resultChan <- result{server: "pcep", err: s.Serve(o.PCEPAddr, o.PCEPPort)}
	}()

	go func() {
		resultChan <- result{server: "grpc", err: apiServer.Serve(o.GRPCAddr, o.GRPCPort)}
	}()

	go s.awaitShutdown(ctx, logger, grpcServer.GracefulStop)

	// Wait for both servers to stop before returning the first error.
	var firstErr Error
	for range 2 {
		r := <-resultChan
		if r.err == nil {
			continue
		}
		logger.Error("Server encountered an error", zap.String("server", r.server), zap.Error(r.err))
		if firstErr.Error == nil {
			firstErr = Error{Server: r.server, Error: r.err}
			cancel()
		}
	}
	return firstErr
}

func (s *Server) syncTEDLoop(ctx context.Context, tedElemsChan <-chan []table.TEDElem, asn uint32, logger *zap.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case tedElems, ok := <-tedElemsChan:
			if !ok {
				return
			}
			ted := &table.LsTED{
				Nodes: map[string]*table.LsNode{},
			}
			ted.Update(tedElems, asn)
			s.setTED(ted)
			logger.Debug("Update TED")
		}
	}
}

func (s *Server) Serve(address string, port string) error {
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

	s.listenerMu.Lock()
	if s.closed {
		// Shutdown ran before Serve started listening; don't accept anything.
		s.listenerMu.Unlock()
		return l.Close()
	}
	s.listener = l
	s.listenerMu.Unlock()

	defer func() {
		s.listenerMu.Lock()
		s.listener = nil
		s.listenerMu.Unlock()
		if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.logger.Warn("failed to close PCEP listener", zap.Error(err))
		}
	}()

	sessionID := uint8(1)
	for {
		tcpConn, err := l.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("failed to accept TCP connection: %w", err)
		}
		peerAddrPort, err := netip.ParseAddrPort(tcpConn.RemoteAddr().String())
		if err != nil {
			return fmt.Errorf("failed to parse remote address %s: %w", tcpConn.RemoteAddr().String(), err)
		}

		ss := s.registerSession(tcpConn, sessionID, peerAddrPort.Addr())
		sessionID++
		if ss == nil {
			continue
		}
		ss.logger.Info("start PCEP session")
		go func() {
			ss.Established()
			s.closeSession(ss)
			ss.logger.Info("close PCEP session")
		}()
	}
}

func (s *Server) registerSession(tcpConn *net.TCPConn, sessionID uint8, peerAddr netip.Addr) *Session {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	if s.closed {
		if err := tcpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.logger.Warn("failed to close TCP connection accepted after shutdown", zap.Error(err))
		}
		return nil
	}

	ss := NewSession(sessionID, peerAddr, tcpConn, s.logger, s.TED(), s.asn)
	s.sessionMu.Lock()
	s.sessionList = append(s.sessionList, ss)
	s.sessionMu.Unlock()
	return ss
}

func (s *Server) awaitShutdown(ctx context.Context, logger *zap.Logger, stopGRPC func()) {
	<-ctx.Done()
	logger.Info("shutdown requested, stopping PCE server")
	if err := s.Shutdown(); err != nil {
		logger.Warn("failed to shut down PCEP server", zap.Error(err))
	}
	stopGRPC()
}

// Shutdown stops accepting connections and gracefully closes established sessions.
func (s *Server) Shutdown() error {
	s.listenerMu.Lock()
	s.closed = true
	l := s.listener
	s.sessionMu.RLock()
	sessions := slices.Clone(s.sessionList)
	s.sessionMu.RUnlock()
	s.listenerMu.Unlock()

	var err error
	if l != nil {
		if err = l.Close(); errors.Is(err, net.ErrClosed) {
			err = nil
		}
	}

	var wg sync.WaitGroup
	for _, ss := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.gracefulCloseSession(ss)
		}()
	}
	wg.Wait()

	return err
}

// Sends a PCEP Close message with a bounded wait before force-closing the session.
func (s *Server) gracefulCloseSession(ss *Session) {
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		if sendErr := ss.SendClose(pcep.CloseReasonNoExplanationProvided); sendErr != nil {
			s.logger.Warn("failed to send PCEP close message during shutdown", zap.Error(sendErr))
		}
	}()

	timeout := s.shutdownSendCloseTimeout
	if timeout <= 0 {
		timeout = defaultShutdownSendCloseTimeout
	}
	select {
	case <-sendDone:
	case <-time.After(timeout):
		s.logger.Warn("timed out sending PCEP close message during shutdown", zap.String("session", ss.peerAddr.String()))
	}

	s.closeSession(ss)
}

func (s *Server) closeSession(session *Session) {
	if err := session.tcpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Warn("failed to close TCP connection", zap.Error(err))
	}
	session.clearSRPolicyIntents()

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
