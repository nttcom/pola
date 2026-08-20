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

const defaultShutdownSendCloseTimeout = 2 * time.Second

// Server manages PCEP sessions and server lifecycle.
type Server struct {
	sessionMu                sync.RWMutex
	sessionList              []*Session
	sessionIDs               sessionIDAllocator
	tedMu                    sync.RWMutex
	ted                      *table.LsTED
	logger                   *zap.Logger
	asn                      uint32
	localKeepalive           uint8
	localDeadTimer           uint8
	keepaliveRangeEnabled    bool
	minKeepalive             uint8
	maxKeepalive             uint8
	allowNegotiation         bool
	listenerMu               sync.Mutex
	listener                 tcpListener
	closed                   bool
	shutdownSendCloseTimeout time.Duration
	peerStatsMu              sync.Mutex
	peerStats                map[netip.Addr]*peerSetupStats
}

// peerSetupStats counts session establishment outcomes per peer.
// Entries outlive individual Session objects.
type peerSetupStats struct {
	ok   uint64
	fail uint64
}

// sessionIDAllocator allocates session IDs per peer.
// IDs advance across reconnects so a new session does not immediately reuse
// the previous session's ID.
type sessionIDAllocator struct {
	mu   sync.Mutex
	next map[netip.Addr]uint8
}

func (a *sessionIDAllocator) allocate(peerAddr netip.Addr) uint8 {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.next == nil {
		a.next = make(map[netip.Addr]uint8)
	}

	id := a.next[peerAddr]
	a.next[peerAddr] = id + 1
	return id
}

type tcpListener interface {
	AcceptTCP() (*net.TCPConn, error)
	Close() error
}

// TED returns the current TED snapshot.
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

// PCEOptions contains configuration options for the PCE server.
type PCEOptions struct {
	PCEPAddr         string
	PCEPPort         string
	GRPCAddr         string
	GRPCPort         string
	TEDEnable        bool
	USidMode         bool
	ASN              uint32
	Keepalive        *uint8
	DeadTimer        *uint8
	MinKeepalive     *uint8
	MaxKeepalive     *uint8
	AllowNegotiation *bool
}

func resolveKeepaliveRange(minKeepalive, maxKeepalive *uint8) (lo, hi uint8, enabled bool) {
	if minKeepalive == nil && maxKeepalive == nil {
		return 0, 0, false
	}
	hi = math.MaxUint8
	if minKeepalive != nil {
		lo = *minKeepalive
	}
	if maxKeepalive != nil {
		hi = *maxKeepalive
	}
	return lo, hi, true
}

func resolveLocalTimers(keepalive, deadTimer *uint8) (uint8, uint8) {
	localKeepalive := defaultLocalKeepalive
	if keepalive != nil {
		localKeepalive = *keepalive
	}
	if deadTimer != nil {
		return localKeepalive, *deadTimer
	}
	if localKeepalive == 0 {
		return 0, 0
	}
	return localKeepalive, pcep.DeadTimerFor(localKeepalive)
}

// NewPCE starts the PCEP and gRPC servers.
func NewPCE(ctx context.Context, o *PCEOptions, logger *zap.Logger, tedElemsChan chan []table.TEDElem) Error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	localKeepalive, localDeadTimer := resolveLocalTimers(o.Keepalive, o.DeadTimer)
	minKeepalive, maxKeepalive, keepaliveRangeEnabled := resolveKeepaliveRange(o.MinKeepalive, o.MaxKeepalive)
	allowNegotiation := o.AllowNegotiation == nil || *o.AllowNegotiation
	s := &Server{
		logger:                logger,
		asn:                   o.ASN,
		localKeepalive:        localKeepalive,
		localDeadTimer:        localDeadTimer,
		keepaliveRangeEnabled: keepaliveRangeEnabled,
		minKeepalive:          minKeepalive,
		maxKeepalive:          maxKeepalive,
		allowNegotiation:      allowNegotiation,
	}
	if o.TEDEnable {
		s.setTED(&table.LsTED{
			Nodes: map[string]*table.LsNode{},
		})
		go s.syncTEDLoop(ctx, tedElemsChan, o.ASN)
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

	go s.awaitShutdown(ctx, grpcServer.GracefulStop)

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

func (s *Server) syncTEDLoop(ctx context.Context, tedElemsChan <-chan []table.TEDElem, asn uint32) {
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
			s.logger.Debug("Update TED")
		}
	}
}

// Serve starts the PCEP server on the specified address and port.
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

		ss := s.registerSession(tcpConn, peerAddrPort.Addr())
		if ss == nil {
			continue
		}
		ss.logger.Info("start PCEP session")
		go func() {
			if err := ss.Established(); err != nil {
				s.recordSetupResult(ss.peerAddr, false)
			}
			s.closeSession(ss)
			ss.logger.Info("close PCEP session")
		}()
	}
}

func (s *Server) registerSession(conn net.Conn, peerAddr netip.Addr) *Session {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	if s.closed {
		s.closeRejectedConn(conn, "accepted after shutdown")
		return nil
	}

	ted := s.TED()

	s.sessionMu.Lock()
	if slices.ContainsFunc(s.sessionList, func(ss *Session) bool { return ss.peerAddr == peerAddr }) {
		s.sessionMu.Unlock()
		s.recordSetupResult(peerAddr, false)
		s.rejectSecondSession(conn, peerAddr)
		return nil
	}
	sessionID := s.sessionIDs.allocate(peerAddr)
	localOpen := OpenParams{SessionID: sessionID, Keepalive: s.localKeepalive, DeadTimer: s.localDeadTimer}
	ss := NewSession(localOpen, peerAddr, conn, s.logger, ted, s.asn)
	ss.keepaliveRangeEnabled = s.keepaliveRangeEnabled
	ss.minKeepalive = s.minKeepalive
	ss.maxKeepalive = s.maxKeepalive
	ss.allowNegotiation = s.allowNegotiation
	ss.onEstablished = func() { s.recordSetupResult(peerAddr, true) }
	s.sessionList = append(s.sessionList, ss)
	s.sessionMu.Unlock()
	return ss
}

func (s *Server) rejectSecondSession(conn net.Conn, peerAddr netip.Addr) {
	s.logger.Warn("rejecting second PCEP session attempt from peer", zap.String("peer", peerAddr.String()))

	pcerrMessage := pcep.NewPCErrMessage(pcepErrorTypeSecondSessionAttempt, pcepErrorValueSecondSessionAttempt, nil)
	if byteMessage, err := pcerrMessage.Serialize(); err != nil {
		s.logger.Warn("failed to serialize PCErr for second session attempt", zap.Error(err))
	} else if _, err := conn.Write(byteMessage); err != nil {
		s.logger.Warn("failed to send PCErr for second session attempt", zap.Error(err))
	}

	s.closeRejectedConn(conn, "second PCEP session attempt from peer")
}

func (s *Server) closeRejectedConn(conn net.Conn, why string) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Warn("failed to close rejected TCP connection",
			zap.String("reason", why), zap.Error(err))
	}
}

func (s *Server) awaitShutdown(ctx context.Context, stopGRPC func()) {
	<-ctx.Done()
	s.logger.Info("shutdown requested, stopping PCE server")
	if err := s.Shutdown(); err != nil {
		s.logger.Warn("failed to shut down PCEP server", zap.Error(err))
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
		wg.Go(func() {
			s.gracefulCloseSession(ss)
		})
	}
	wg.Wait()

	return err
}

// gracefulCloseSession sends Close with a bounded wait before closing the connection.
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
	if i := slices.Index(s.sessionList, session); i >= 0 {
		s.sessionList[i] = s.sessionList[len(s.sessionList)-1]
		s.sessionList = s.sessionList[:len(s.sessionList)-1]
	}
	s.sessionMu.Unlock()
}

// SearchSession returns the session for the given peer address.
func (s *Server) SearchSession(peerAddr netip.Addr) *Session {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	for _, pcepSession := range s.sessionList {
		if pcepSession.peerAddr == peerAddr {
			return pcepSession
		}
	}
	return nil
}

// Sessions returns a copy of the current session list.
func (s *Server) Sessions() []*Session {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	return slices.Clone(s.sessionList)
}

func (s *Server) recordSetupResult(addr netip.Addr, ok bool) {
	s.peerStatsMu.Lock()
	defer s.peerStatsMu.Unlock()
	if s.peerStats == nil {
		s.peerStats = make(map[netip.Addr]*peerSetupStats)
	}
	stats, exists := s.peerStats[addr]
	if !exists {
		stats = &peerSetupStats{}
		s.peerStats[addr] = stats
	}
	if ok {
		stats.ok++
	} else {
		stats.fail++
	}
}

// PeerSetupStats returns cumulative session establishment outcomes for addr.
// Counters persist across session teardown to match RFC 9826 sess-setup-ok/fail.
func (s *Server) PeerSetupStats(addr netip.Addr) (ok, fail uint64) {
	s.peerStatsMu.Lock()
	defer s.peerStatsMu.Unlock()
	if stats, exists := s.peerStats[addr]; exists {
		return stats.ok, stats.fail
	}
	return 0, 0
}
