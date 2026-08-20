// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/nttcom/pola/pkg/table"
)

func TestServer_Serve_InvalidInputRejected(t *testing.T) {
	tests := []struct {
		name    string
		address string
		port    string
	}{
		{name: "invalid address", address: "not-an-ip", port: "4189"},
		{name: "invalid port", address: "127.0.0.1", port: "notaport"},
		{name: "negative port", address: "127.0.0.1", port: "-1"},
		{name: "port out of range", address: "127.0.0.1", port: "70000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{logger: zap.NewNop()}
			assert.Error(t, s.Serve(tt.address, tt.port))
		})
	}
}

func TestServer_Serve_ListenFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	t.Cleanup(func() {
		assert.NoError(t, ln.Close(), "failed to close listener")
	})

	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	s := &Server{logger: zap.NewNop()}
	require.ErrorContains(t, s.Serve(addr, port), "failed to listen on PCEP port")
}

func TestServer_Serve_AcceptsConnectionAndUntracksOnClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close(), "failed to release the reserved port")

	s := &Server{logger: zap.NewNop()}
	go func() { _ = s.Serve(addr, port) }()
	t.Cleanup(func() { assert.NoError(t, s.Shutdown()) })

	var client net.Conn
	require.Eventually(t, func() bool {
		c, dialErr := net.DialTimeout("tcp", net.JoinHostPort(addr, port), 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		client = c
		return true
	}, 2*time.Second, 10*time.Millisecond, "expected to dial the PCEP listener once it starts")
	t.Cleanup(func() {
		_ = client.Close()
	})

	require.Eventually(t, func() bool {
		return len(s.Sessions()) == 1
	}, 2*time.Second, 10*time.Millisecond, "expected the accepted connection to be tracked as a session")

	require.NoError(t, client.Close())

	require.Eventually(t, func() bool {
		return len(s.Sessions()) == 0
	}, 2*time.Second, 10*time.Millisecond, "expected the session to be untracked once the PCEP session ended")
}

func TestServer_Shutdown_ClosesListenerAndStopsServe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close(), "failed to release the reserved port")

	s := &Server{logger: zap.NewNop()}
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- s.Serve(addr, port) }()

	require.Eventually(t, func() bool {
		conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(addr, port), 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond, "expected the PCEP listener to accept connections before shutdown")

	require.NoError(t, s.Shutdown(), "Shutdown should close the listener without error")

	select {
	case err := <-serveErrCh:
		require.NoError(t, err, "Serve should return cleanly once the listener is closed")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Serve to return after Shutdown closed the listener")
	}

	_, dialErr := net.DialTimeout("tcp", net.JoinHostPort(addr, port), 100*time.Millisecond)
	assert.Error(t, dialErr, "expected the listener to no longer accept connections after Shutdown")
}

func TestServer_Shutdown_BeforeServeStillReturnsCleanly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close(), "failed to release the reserved port")

	s := &Server{logger: zap.NewNop()}
	require.NoError(t, s.Shutdown(), "Shutdown before Serve starts should be a no-op that succeeds")

	require.NoError(t, s.Serve(addr, port), "Serve should return cleanly if Shutdown already ran")

	_, dialErr := net.DialTimeout("tcp", net.JoinHostPort(addr, port), 100*time.Millisecond)
	assert.Error(t, dialErr, "expected Serve not to accept connections after an earlier Shutdown")
}

func TestServer_Shutdown_LogsWarnOnSendCloseFailure(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{sessionList: []*Session{ss}, logger: zap.New(core)}

	require.NoError(t, s.Shutdown())

	assert.Len(t, logs.FilterMessage("failed to send PCEP close message during shutdown").All(), 1)
	assert.Empty(t, s.Sessions())
}

func TestServer_Shutdown_ClosesActiveSessions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close(), "failed to release the reserved port")

	s := &Server{logger: zap.NewNop()}
	go func() { _ = s.Serve(addr, port) }()

	var client net.Conn
	require.Eventually(t, func() bool {
		c, dialErr := net.DialTimeout("tcp", net.JoinHostPort(addr, port), 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		client = c
		return true
	}, 2*time.Second, 10*time.Millisecond, "expected to dial the PCEP listener once it starts")
	t.Cleanup(func() { _ = client.Close() })

	require.Eventually(t, func() bool {
		return len(s.Sessions()) == 1
	}, 2*time.Second, 10*time.Millisecond, "expected the accepted connection to be tracked as a session")

	require.NoError(t, s.Shutdown())

	assert.Empty(t, s.Sessions(), "expected Shutdown to close and untrack the active session")
}

func TestServer_CloseSession_SuppressesWarnOnAlreadyClosedConnection(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})
	require.NoError(t, server.Close(), "failed to pre-close server connection")

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{sessionList: []*Session{ss}, logger: zap.New(core)}

	s.closeSession(ss)

	assert.Empty(t, logs.FilterMessage("failed to close TCP connection").All(),
		"a double close (Shutdown racing the session's own close) should not be logged as a failure")
	assert.Empty(t, s.Sessions())
}

func TestServer_CloseSession_LogsWarnOnOtherCloseFailure(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil), closeErr: errors.New("boom")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{sessionList: []*Session{ss}, logger: zap.New(core)}

	s.closeSession(ss)

	assert.Len(t, logs.FilterMessage("failed to close TCP connection").All(), 1)
	assert.Empty(t, s.Sessions())
}

func TestNewPCE_ReturnsTaggedError(t *testing.T) {
	tests := []struct {
		name       string
		o          *PCEOptions
		wantServer string
	}{
		{
			name: "PCEP failure reported",
			o: &PCEOptions{
				PCEPAddr: "not-an-ip", // fail before listening
				PCEPPort: "0",
				GRPCAddr: "127.0.0.1",
				GRPCPort: "0",
			},
			wantServer: "pcep",
		},
		{
			name: "gRPC failure reported",
			o: &PCEOptions{
				PCEPAddr: "127.0.0.1",
				PCEPPort: "0",
				GRPCAddr: "not-an-ip", // fail before listening
				GRPCPort: "0",
			},
			wantServer: "grpc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errCh := make(chan Error, 1)
			go func() { errCh <- NewPCE(context.Background(), tt.o, zap.NewNop(), make(chan []table.TEDElem)) }()

			select {
			case err := <-errCh:
				assert.Equal(t, tt.wantServer, err.Server)
				require.Error(t, err.Error)
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for NewPCE to report an error")
			}
		})
	}
}

func TestNewPCE_TEDEnabledUpdatesTEDOnElemsReceived(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	tedElemsChan := make(chan []table.TEDElem, 1)
	o := &PCEOptions{
		PCEPAddr:  "127.0.0.1",
		PCEPPort:  "0",
		GRPCAddr:  "127.0.0.1",
		GRPCPort:  "0",
		TEDEnable: true,
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan Error, 1)
	go func() { errCh <- NewPCE(ctx, o, zap.New(core), tedElemsChan) }()

	tedElemsChan <- []table.TEDElem{}

	require.Eventually(t, func() bool {
		return len(logs.FilterMessage("Update TED").All()) > 0
	}, 2*time.Second, 10*time.Millisecond, "expected the TED update goroutine to run")

	cancel()

	select {
	case err := <-errCh:
		assert.Empty(t, err.Server)
		require.NoError(t, err.Error)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NewPCE to shut down after context cancellation")
	}
}

// TestNewPCE_WaitsForBothServersBeforeReturning ensures NewPCE waits for both servers to stop before returning.
func TestNewPCE_WaitsForBothServersBeforeReturning(t *testing.T) {
	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	grpcAddr, grpcPort, err := net.SplitHostPort(grpcLn.Addr().String())
	require.NoError(t, err)
	require.NoError(t, grpcLn.Close(), "failed to release the reserved port")

	o := &PCEOptions{
		PCEPAddr: "not-an-ip", // fails before listening, well before gRPC would stop on its own
		PCEPPort: "0",
		GRPCAddr: grpcAddr,
		GRPCPort: grpcPort,
	}

	errCh := make(chan Error, 1)
	go func() { errCh <- NewPCE(context.Background(), o, zap.NewNop(), make(chan []table.TEDElem)) }()

	select {
	case err := <-errCh:
		assert.Equal(t, "pcep", err.Server)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NewPCE to report an error")
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(grpcAddr, grpcPort))
	if assert.NoError(t, err, "expected the gRPC listener to be released by the time NewPCE returns") {
		assert.NoError(t, ln.Close())
	}
}

func TestNewPCE_ContextCancelShutsDownCleanly(t *testing.T) {
	o := &PCEOptions{
		PCEPAddr: "127.0.0.1",
		PCEPPort: "0",
		GRPCAddr: "127.0.0.1",
		GRPCPort: "0",
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan Error, 1)
	go func() { errCh <- NewPCE(ctx, o, zap.NewNop(), make(chan []table.TEDElem)) }()

	// Give both servers a moment to start listening before requesting shutdown.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		assert.Empty(t, err.Server)
		require.NoError(t, err.Error)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NewPCE to shut down after context cancellation")
	}
}

type fakeListener struct {
	closeErr error
}

func (l *fakeListener) AcceptTCP() (*net.TCPConn, error) { <-make(chan struct{}); return nil, nil }
func (l *fakeListener) Close() error                     { return l.closeErr }

func TestServer_Shutdown_TreatsRepeatCloseAsNoError(t *testing.T) {
	s := &Server{logger: zap.NewNop(), listener: &fakeListener{closeErr: net.ErrClosed}}

	assert.NoError(t, s.Shutdown(), "a listener already closed elsewhere should not fail Shutdown")
}

func TestServer_Shutdown_PropagatesOtherListenerCloseError(t *testing.T) {
	wantErr := errors.New("boom")
	s := &Server{logger: zap.NewNop(), listener: &fakeListener{closeErr: wantErr}}

	assert.ErrorIs(t, s.Shutdown(), wantErr)
}

func TestServer_AwaitShutdown_LogsWarnOnShutdownError(t *testing.T) {
	wantErr := errors.New("boom")
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{logger: zap.New(core), listener: &fakeListener{closeErr: wantErr}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stopped := false
	done := make(chan struct{})
	go func() {
		s.awaitShutdown(ctx, func() { stopped = true })
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for awaitShutdown to return")
	}

	assert.Len(t, logs.FilterMessage("failed to shut down PCEP server").All(), 1)
	assert.True(t, stopped, "expected the gRPC server to be stopped even when Shutdown fails")
}

func TestServer_SyncTEDLoop_AppliesReceivedElems(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	tedElemsChan := make(chan []table.TEDElem, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.syncTEDLoop(ctx, tedElemsChan, 65000)
		close(done)
	}()

	tedElemsChan <- []table.TEDElem{}

	require.Eventually(t, func() bool {
		return s.TED() != nil
	}, 2*time.Second, 10*time.Millisecond, "expected the received TED elements to be applied")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for syncTEDLoop to return after context cancellation")
	}
}

func TestServer_SyncTEDLoop_ExitsWhenChannelClosed(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	tedElemsChan := make(chan []table.TEDElem)

	done := make(chan struct{})
	go func() {
		s.syncTEDLoop(context.Background(), tedElemsChan, 65000)
		close(done)
	}()

	close(tedElemsChan)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for syncTEDLoop to return after the channel closed")
	}
}

func TestServer_RegisterSession_ClosesConnWhenAlreadyShutdown(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { _ = client.Close() })

	s := &Server{logger: zap.NewNop(), closed: true}
	ss := s.registerSession(server, netip.MustParseAddr("10.0.255.1"))

	assert.Nil(t, ss, "expected registerSession to reject a connection accepted after Shutdown")
	assert.Empty(t, s.Sessions())

	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF, "expected the connection accepted after shutdown to be closed immediately")
}

func TestServer_CloseRejectedConn_LogsNonClosedError(t *testing.T) {
	wantErr := errors.New("boom")
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{logger: zap.New(core)}

	s.closeRejectedConn(&fakeConn{closeErr: wantErr}, "test reason")

	entries := logs.FilterMessage("failed to close rejected TCP connection").All()
	require.Len(t, entries, 1)
	assert.Equal(t, "test reason", entries[0].ContextMap()["reason"])
}

func TestServer_CloseRejectedConn_ErrClosedIsNotLogged(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{logger: zap.New(core)}

	s.closeRejectedConn(&fakeConn{closeErr: net.ErrClosed}, "test reason")

	assert.Empty(t, logs.All(), "an already-closed connection must not be logged as a failure")
}

func TestServer_RegisterSession_AppendsWhenNotShutdown(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	s := &Server{logger: zap.NewNop()}
	ss := s.registerSession(server, netip.MustParseAddr("10.0.255.1"))

	require.NotNil(t, ss)
	assert.Equal(t, []*Session{ss}, s.Sessions())

	s.closeSession(ss)
}

func TestServer_RegisterSession_RejectsSecondSessionFromSamePeer(t *testing.T) {
	peerAddr := netip.MustParseAddr("10.0.255.1")
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{logger: zap.New(core)}

	server1, client1 := newTCPConnPair(t)
	t.Cleanup(func() { _ = client1.Close() })
	ss1 := s.registerSession(server1, peerAddr)
	require.NotNil(t, ss1)

	server2, client2 := newTCPConnPair(t)
	t.Cleanup(func() { _ = client2.Close() })
	ss2 := s.registerSession(server2, peerAddr)

	assert.Nil(t, ss2, "a second session with the same peer must not be accepted")
	assert.Equal(t, []*Session{ss1}, s.Sessions(), "the existing session must be preserved")
	assert.Len(t, logs.FilterMessage("rejecting second PCEP session attempt from peer").All(), 1)

	require.NoError(t, client2.SetReadDeadline(time.Now().Add(2*time.Second)))
	pcerrMessage := readPCErrMessage(t, client2)
	require.Len(t, pcerrMessage.Errors, 1)
	assert.Equal(t, uint8(9), pcerrMessage.Errors[0].ErrorType)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorValue)

	_, err := client2.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "expected the rejected connection to be closed")

	s.closeSession(ss1)
}

func TestServer_RegisterSession_RejectSecondSession_LogsWarnOnSendFailure(t *testing.T) {
	peerAddr := netip.MustParseAddr("10.0.255.1")
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{logger: zap.New(core)}

	server1, client1 := newTCPConnPair(t)
	t.Cleanup(func() { _ = client1.Close() })
	ss1 := s.registerSession(server1, peerAddr)
	require.NotNil(t, ss1)

	conn2 := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss2 := s.registerSession(conn2, peerAddr)

	assert.Nil(t, ss2, "a second session with the same peer must not be accepted")
	assert.Len(t, logs.FilterMessage("failed to send PCErr for second session attempt").All(), 1)

	s.closeSession(ss1)
}

func TestServer_RegisterSession_SessionIDSequenceIsPerPeer(t *testing.T) {
	s := &Server{logger: zap.NewNop()}

	server1, client1 := newTCPConnPair(t)
	t.Cleanup(func() { _ = client1.Close() })
	ss1 := s.registerSession(server1, netip.MustParseAddr("10.0.255.1"))
	require.NotNil(t, ss1)
	assert.Zero(t, ss1.localSessionID)

	server2, client2 := newTCPConnPair(t)
	t.Cleanup(func() { _ = client2.Close() })
	ss2 := s.registerSession(server2, netip.MustParseAddr("10.0.255.2"))
	require.NotNil(t, ss2)
	assert.Zero(t, ss2.localSessionID, "each peer has its own SID sequence")

	s.closeSession(ss1)
	s.closeSession(ss2)
}

func TestServer_CloseSession_MatchesByIdentityNotIDValue(t *testing.T) {
	connA := &fakeConn{r: bytes.NewReader(nil)}
	connB := &fakeConn{r: bytes.NewReader(nil)}
	ssA := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), connA, zap.NewNop(), nil, 0)
	ssB := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.2"), connB, zap.NewNop(), nil, 0)
	s := &Server{logger: zap.NewNop(), sessionList: []*Session{ssA, ssB}}

	s.closeSession(ssA)

	assert.Equal(t, []*Session{ssB}, s.Sessions(), "expected only the closed session's own instance to be removed")
}

func TestSessionIDAllocator_IncrementsByOneAndWraps(t *testing.T) {
	peerAddr := netip.MustParseAddr("10.0.255.1")
	var a sessionIDAllocator

	for want := range math.MaxUint8 + 1 {
		assert.Equal(t, uint8(want), a.allocate(peerAddr))
	}

	assert.Zero(t, a.allocate(peerAddr), "the sequence wraps back to zero after 255")
}

func TestSessionIDAllocator_SequenceIsIndependentPerPeer(t *testing.T) {
	peerA := netip.MustParseAddr("10.0.255.1")
	peerB := netip.MustParseAddr("10.0.255.2")
	var a sessionIDAllocator

	for want := range uint8(3) {
		assert.Equal(t, want, a.allocate(peerA))
	}

	assert.Zero(t, a.allocate(peerB), "peer B's sequence must not be advanced by peer A")
}

// blockingWriteConn simulates a peer that stopped reading.
type blockingWriteConn struct {
	r       io.Reader
	unblock chan struct{}
	once    sync.Once
}

func (c *blockingWriteConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *blockingWriteConn) Write(_ []byte) (int, error) {
	<-c.unblock
	return 0, net.ErrClosed
}

func (c *blockingWriteConn) Close() error {
	c.once.Do(func() { close(c.unblock) })
	return nil
}

func (c *blockingWriteConn) LocalAddr() net.Addr              { return nil }
func (c *blockingWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *blockingWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestServer_Shutdown_BoundsBlockedSendClose(t *testing.T) {
	conn := &blockingWriteConn{r: bytes.NewReader(nil), unblock: make(chan struct{})}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	core, logs := observer.New(zap.WarnLevel)
	s := &Server{
		sessionList:              []*Session{ss},
		logger:                   zap.New(core),
		shutdownSendCloseTimeout: 50 * time.Millisecond,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		assert.NoError(t, s.Shutdown())
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the SendClose timeout elapsed, despite the blocked write")
	}

	assert.Len(t, logs.FilterMessage("timed out sending PCEP close message during shutdown").All(), 1)
	assert.Empty(t, s.Sessions(), "expected the session to be force-closed and untracked despite the blocked write")
}

func TestResolveLocalTimers(t *testing.T) {
	ptr := func(v uint8) *uint8 { return &v }

	tests := []struct {
		name          string
		keepalive     *uint8
		deadTimer     *uint8
		wantKeepalive uint8
		wantDeadTimer uint8
	}{
		{"unset uses defaults", nil, nil, 30, 120},
		{"a configured keepalive derives a 4x dead timer", ptr(10), nil, 10, 40},
		{"keepalive of zero derives a dead timer of zero", ptr(0), nil, 0, 0},
		{"both configured are used verbatim", ptr(5), ptr(60), 5, 60},
		{"a configured dead timer of zero is honored", ptr(30), ptr(0), 30, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keepalive, deadTimer := resolveLocalTimers(tt.keepalive, tt.deadTimer)
			assert.Equal(t, tt.wantKeepalive, keepalive)
			assert.Equal(t, tt.wantDeadTimer, deadTimer)
		})
	}
}

func TestResolveKeepaliveRange(t *testing.T) {
	ptr := func(v uint8) *uint8 { return &v }

	tests := []struct {
		name        string
		min         *uint8
		max         *uint8
		wantLo      uint8
		wantHi      uint8
		wantEnabled bool
	}{
		{"both unset disables the check", nil, nil, 0, 0, false},
		{"only a minimum caps the upper bound at the widest value", ptr(10), nil, 10, math.MaxUint8, true},
		{"only a maximum leaves the lower bound at zero", nil, ptr(60), 0, 60, true},
		{"both set are used verbatim", ptr(10), ptr(60), 10, 60, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lo, hi, enabled := resolveKeepaliveRange(tt.min, tt.max)
			assert.Equal(t, tt.wantLo, lo)
			assert.Equal(t, tt.wantHi, hi)
			assert.Equal(t, tt.wantEnabled, enabled)
		})
	}
}
