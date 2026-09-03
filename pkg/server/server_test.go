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

	"github.com/nttcom/pola/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

const (
	invalidHost      = "not-an-ip"
	testLoopbackAddr = "127.0.0.1"
)

func TestServer_Serve_InvalidInputRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		port    string
	}{
		{name: "invalid address", address: invalidHost, port: "4189"},
		{name: "invalid port", address: testLoopbackAddr, port: "notaport"},
		{name: "negative port", address: testLoopbackAddr, port: "-1"},
		{name: "port out of range", address: testLoopbackAddr, port: "70000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Server{logger: logger.NewNop()}
			assert.Error(t, s.Serve(tt.address, tt.port))
		})
	}
}

func TestServer_Serve_ListenFailure(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	t.Cleanup(func() {
		assert.NoError(t, ln.Close(), "failed to close listener")
	})

	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	s := &Server{logger: logger.NewNop()}
	require.ErrorContains(t, s.Serve(addr, port), "failed to listen on PCEP port")
}

func TestServer_Serve_AcceptsConnectionAndUntracksOnClose(t *testing.T) {
	t.Parallel()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "failed to open the PCEP listener")

	s := &Server{logger: logger.NewNop()}
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- s.serve(ln) }()
	t.Cleanup(func() {
		assert.NoError(t, s.Shutdown())
		select {
		case err := <-serveErrCh:
			assert.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Error("serve did not return after Shutdown")
		}
	})

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
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
	t.Parallel()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "failed to open the PCEP listener")
	addr := ln.Addr().String()

	s := &Server{logger: logger.NewNop()}
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- s.serve(ln) }()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err, "expected the PCEP listener to accept connections before shutdown")
	require.NoError(t, conn.Close())

	require.NoError(t, s.Shutdown(), "Shutdown should close the listener without error")

	select {
	case err := <-serveErrCh:
		require.NoError(t, err, "serve should return cleanly once the listener is closed")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for serve to return after Shutdown closed the listener")
	}

	_, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	assert.Error(t, dialErr, "expected the listener to no longer accept connections after Shutdown")
}

func TestServer_Shutdown_BeforeServeStillReturnsCleanly(t *testing.T) {
	t.Parallel()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "failed to open the PCEP listener")
	addr := ln.Addr().String()

	s := &Server{logger: logger.NewNop()}
	require.NoError(t, s.Shutdown(), "Shutdown before serve starts should be a no-op that succeeds")

	require.NoError(t, s.serve(ln), "serve should return cleanly if Shutdown already ran")

	_, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	assert.Error(t, dialErr, "expected serve not to accept connections after an earlier Shutdown")
}

func TestServer_Shutdown_LogsWarnOnSendCloseFailure(t *testing.T) {
	t.Parallel()

	conn := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, logger.NewNop(), nil, 0)
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{sessionList: []*Session{ss}, logger: lg}

	require.NoError(t, s.Shutdown())

	assert.Len(t, logs.FilterByMessage("failed to send PCEP close message during shutdown"), 1)
	assert.Empty(t, s.Sessions())
}

func TestServer_Shutdown_ClosesActiveSessions(t *testing.T) {
	t.Parallel()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "failed to open the PCEP listener")

	s := &Server{logger: logger.NewNop()}
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- s.serve(ln) }()
	t.Cleanup(func() {
		select {
		case err := <-serveErrCh:
			assert.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Error("serve did not return after Shutdown")
		}
	})

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})

	require.Eventually(t, func() bool {
		return len(s.Sessions()) == 1
	}, 2*time.Second, 10*time.Millisecond, "expected the accepted connection to be tracked as a session")

	require.NoError(t, s.Shutdown())

	assert.Empty(t, s.Sessions(), "expected Shutdown to close and untrack the active session")
}

func TestServer_CloseSession_SuppressesWarnOnAlreadyClosedConnection(t *testing.T) {
	t.Parallel()

	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})
	require.NoError(t, server.Close(), "failed to pre-close server connection")

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, logger.NewNop(), nil, 0)
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{sessionList: []*Session{ss}, logger: lg}

	s.closeSession(ss)

	assert.Empty(t, logs.FilterByMessage("failed to close TCP connection"),
		"a double close (Shutdown racing the session's own close) should not be logged as a failure")
	assert.Empty(t, s.Sessions())
}

func TestServer_CloseSession_LogsWarnOnOtherCloseFailure(t *testing.T) {
	t.Parallel()

	conn := &fakeConn{r: bytes.NewReader(nil), closeErr: errors.New("boom")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, logger.NewNop(), nil, 0)
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{sessionList: []*Session{ss}, logger: lg}

	s.closeSession(ss)

	assert.Len(t, logs.FilterByMessage("failed to close TCP connection"), 1)
	assert.Empty(t, s.Sessions())
}

func TestValidatePCEOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		o       *PCEOptions
		wantErr bool
	}{
		{name: "nil options rejected", o: nil, wantErr: true},
		{name: "Keepalive=0/DeadTimer=0 OK", o: &PCEOptions{Keepalive: new(uint8(0)), DeadTimer: new(uint8(0))}, wantErr: false},
		{name: "Keepalive=0/DeadTimer>0 rejected", o: &PCEOptions{Keepalive: new(uint8(0)), DeadTimer: new(uint8(1))}, wantErr: true},
		{name: "DeadTimer<Keepalive rejected", o: &PCEOptions{Keepalive: new(uint8(30)), DeadTimer: new(uint8(29))}, wantErr: true},
		{name: "DeadTimer==Keepalive rejected", o: &PCEOptions{Keepalive: new(uint8(30)), DeadTimer: new(uint8(30))}, wantErr: true},
		{name: "DeadTimer>Keepalive OK", o: &PCEOptions{Keepalive: new(uint8(30)), DeadTimer: new(uint8(31))}, wantErr: false},
		{name: "Keepalive=255 with default DeadTimer rejected", o: &PCEOptions{Keepalive: new(uint8(255))}, wantErr: true},
		{name: "MinKeepalive==MaxKeepalive OK", o: &PCEOptions{MinKeepalive: new(uint8(30)), MaxKeepalive: new(uint8(30))}, wantErr: false},
		{name: "MinKeepalive>MaxKeepalive rejected", o: &PCEOptions{MinKeepalive: new(uint8(31)), MaxKeepalive: new(uint8(30))}, wantErr: true},
		{name: "no options set is OK", o: &PCEOptions{}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePCEOptions(tt.o)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewPCE_NilOptionsReturnsConfigErrorWithoutPanicking(t *testing.T) {
	t.Parallel()

	err := NewPCE(context.Background(), nil, logger.NewNop(), make(chan []table.TEDElem))
	assert.Equal(t, "config", err.Server)
	require.Error(t, err.Error)
}

func TestNewPCE_InvalidTimerConfigRejectedBeforeListening(t *testing.T) {
	t.Parallel()

	// A direct NewPCE caller (bypassing internal/config's own validation)
	// must not be able to start a PCE with an invalid timer configuration.
	o := &PCEOptions{
		PCEPAddr:  testLoopbackAddr,
		PCEPPort:  "0",
		GRPCAddr:  testLoopbackAddr,
		GRPCPort:  "0",
		Keepalive: new(uint8(0)),
		DeadTimer: new(uint8(1)),
	}

	err := NewPCE(context.Background(), o, logger.NewNop(), make(chan []table.TEDElem))
	assert.Equal(t, "config", err.Server)
	require.Error(t, err.Error)
}

func TestNewPCE_ReturnsTaggedError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		o          *PCEOptions
		wantServer string
	}{
		{
			name: "PCEP failure reported",
			o: &PCEOptions{
				PCEPAddr: invalidHost, // fail before listening
				PCEPPort: "0",
				GRPCAddr: testLoopbackAddr,
				GRPCPort: "0",
			},
			wantServer: "pcep",
		},
		{
			name: "gRPC failure reported",
			o: &PCEOptions{
				PCEPAddr: testLoopbackAddr,
				PCEPPort: "0",
				GRPCAddr: invalidHost, // fail before listening
				GRPCPort: "0",
			},
			wantServer: "grpc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			errCh := make(chan Error, 1)
			go func() { errCh <- NewPCE(context.Background(), tt.o, logger.NewNop(), make(chan []table.TEDElem)) }()

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
	t.Parallel()

	lg, logs := logger.NewRecorder(logger.LevelDebug)
	tedElemsChan := make(chan []table.TEDElem, 1)
	o := &PCEOptions{
		PCEPAddr:  testLoopbackAddr,
		PCEPPort:  "0",
		GRPCAddr:  testLoopbackAddr,
		GRPCPort:  "0",
		TEDEnable: true,
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan Error, 1)
	go func() { errCh <- NewPCE(ctx, o, lg, tedElemsChan) }()

	tedElemsChan <- []table.TEDElem{}

	require.Eventually(t, func() bool {
		return len(logs.FilterByMessage("Update TED")) > 0
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
	t.Parallel()

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	grpcAddr, grpcPort, err := net.SplitHostPort(grpcLn.Addr().String())
	require.NoError(t, err)
	require.NoError(t, grpcLn.Close(), "failed to release the reserved port")

	o := &PCEOptions{
		PCEPAddr: invalidHost, // fails before listening, well before gRPC would stop on its own
		PCEPPort: "0",
		GRPCAddr: grpcAddr,
		GRPCPort: grpcPort,
	}

	errCh := make(chan Error, 1)
	go func() { errCh <- NewPCE(context.Background(), o, logger.NewNop(), make(chan []table.TEDElem)) }()

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
	t.Parallel()

	o := &PCEOptions{
		PCEPAddr: testLoopbackAddr,
		PCEPPort: "0",
		GRPCAddr: testLoopbackAddr,
		GRPCPort: "0",
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan Error, 1)
	go func() { errCh <- NewPCE(ctx, o, logger.NewNop(), make(chan []table.TEDElem)) }()

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
	t.Parallel()

	s := &Server{logger: logger.NewNop(), listener: &fakeListener{closeErr: net.ErrClosed}}

	assert.NoError(t, s.Shutdown(), "a listener already closed elsewhere should not fail Shutdown")
}

func TestServer_Shutdown_PropagatesOtherListenerCloseError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	s := &Server{logger: logger.NewNop(), listener: &fakeListener{closeErr: wantErr}}

	assert.ErrorIs(t, s.Shutdown(), wantErr)
}

func TestServer_AwaitShutdown_LogsWarnOnShutdownError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{logger: lg, listener: &fakeListener{closeErr: wantErr}}

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

	assert.Len(t, logs.FilterByMessage("failed to shut down PCEP server"), 1)
	assert.True(t, stopped, "expected the gRPC server to be stopped even when Shutdown fails")
}

func TestServer_SyncTEDLoop_AppliesReceivedElems(t *testing.T) {
	t.Parallel()

	s := &Server{logger: logger.NewNop()}
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
	t.Parallel()

	s := &Server{logger: logger.NewNop()}
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
	t.Parallel()

	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})

	s := &Server{logger: logger.NewNop(), closed: true}
	ss := s.registerSession(server, netip.MustParseAddr("10.0.255.1"))

	assert.Nil(t, ss, "expected registerSession to reject a connection accepted after Shutdown")
	assert.Empty(t, s.Sessions())

	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF, "expected the connection accepted after shutdown to be closed immediately")
}

func TestServer_CloseRejectedConn_LogsNonClosedError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{logger: lg}

	s.closeRejectedConn(&fakeConn{closeErr: wantErr}, "test reason")

	entries := logs.FilterByMessage("failed to close rejected TCP connection")
	require.Len(t, entries, 1)
	assert.Equal(t, "test reason", entries[0].Fields["reason"])
}

func TestServer_CloseRejectedConn_ErrClosedIsNotLogged(t *testing.T) {
	t.Parallel()

	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{logger: lg}

	s.closeRejectedConn(&fakeConn{closeErr: net.ErrClosed}, "test reason")

	assert.Empty(t, logs.All(), "an already-closed connection must not be logged as a failure")
}

func TestServer_RegisterSession_AppendsWhenNotShutdown(t *testing.T) {
	t.Parallel()

	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})

	s := &Server{logger: logger.NewNop()}
	ss := s.registerSession(server, netip.MustParseAddr("10.0.255.1"))

	require.NotNil(t, ss)
	assert.Equal(t, []*Session{ss}, s.Sessions())

	s.closeSession(ss)
}

func TestServer_RegisterSession_RejectsSecondSessionFromSamePeer(t *testing.T) {
	t.Parallel()

	peerAddr := netip.MustParseAddr("10.0.255.1")
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{logger: lg}

	server1, client1 := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client1.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})
	ss1 := s.registerSession(server1, peerAddr)
	require.NotNil(t, ss1)

	server2, client2 := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client2.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})
	ss2 := s.registerSession(server2, peerAddr)

	assert.Nil(t, ss2, "a second session with the same peer must not be accepted")
	assert.Equal(t, []*Session{ss1}, s.Sessions(), "the existing session must be preserved")
	assert.Len(t, logs.FilterByMessage("rejecting second PCEP session attempt from peer"), 1)

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
	t.Parallel()

	peerAddr := netip.MustParseAddr("10.0.255.1")
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{logger: lg}

	server1, client1 := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client1.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})
	ss1 := s.registerSession(server1, peerAddr)
	require.NotNil(t, ss1)

	conn2 := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss2 := s.registerSession(conn2, peerAddr)

	assert.Nil(t, ss2, "a second session with the same peer must not be accepted")
	assert.Len(t, logs.FilterByMessage("failed to send PCErr for second session attempt"), 1)

	s.closeSession(ss1)
}

func TestServer_RegisterSession_SessionIDSequenceIsPerPeer(t *testing.T) {
	t.Parallel()

	s := &Server{logger: logger.NewNop()}

	server1, client1 := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client1.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})
	ss1 := s.registerSession(server1, netip.MustParseAddr("10.0.255.1"))
	require.NotNil(t, ss1)
	assert.Zero(t, ss1.localSessionID)

	server2, client2 := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client2.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})
	ss2 := s.registerSession(server2, netip.MustParseAddr("10.0.255.2"))
	require.NotNil(t, ss2)
	assert.Zero(t, ss2.localSessionID, "each peer has its own SID sequence")

	s.closeSession(ss1)
	s.closeSession(ss2)
}

func TestServer_CloseSession_MatchesByIdentityNotIDValue(t *testing.T) {
	t.Parallel()

	connA := &fakeConn{r: bytes.NewReader(nil)}
	connB := &fakeConn{r: bytes.NewReader(nil)}
	ssA := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), connA, logger.NewNop(), nil, 0)
	ssB := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.2"), connB, logger.NewNop(), nil, 0)
	s := &Server{logger: logger.NewNop(), sessionList: []*Session{ssA, ssB}}

	s.closeSession(ssA)

	assert.Equal(t, []*Session{ssB}, s.Sessions(), "expected only the closed session's own instance to be removed")
}

func TestSessionIDAllocator_IncrementsByOneAndWraps(t *testing.T) {
	t.Parallel()

	peerAddr := netip.MustParseAddr("10.0.255.1")
	var a sessionIDAllocator

	for want := range math.MaxUint8 + 1 {
		assert.Equal(t, uint8(want), a.allocate(peerAddr))
	}

	assert.Zero(t, a.allocate(peerAddr), "the sequence wraps back to zero after 255")
}

func TestSessionIDAllocator_SequenceIsIndependentPerPeer(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	conn := &blockingWriteConn{r: bytes.NewReader(nil), unblock: make(chan struct{})}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, logger.NewNop(), nil, 0)
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{
		sessionList:              []*Session{ss},
		logger:                   lg,
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

	assert.Len(t, logs.FilterByMessage("timed out sending PCEP close message during shutdown"), 1)
	assert.Empty(t, s.Sessions(), "expected the session to be force-closed and untracked despite the blocked write")
}

func TestResolveLocalTimers(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			keepalive, deadTimer := resolveLocalTimers(tt.keepalive, tt.deadTimer)
			assert.Equal(t, tt.wantKeepalive, keepalive)
			assert.Equal(t, tt.wantDeadTimer, deadTimer)
		})
	}
}

func TestParseRemoteAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func() *net.TCPConn
		wantErr bool
	}{
		{
			name: "valid address",
			setup: func() *net.TCPConn {
				server, client := newTCPConnPair(t)
				t.Cleanup(func() {
					_ = client.Close()
				})
				return server
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tcpConn := tt.setup()
			defer tcpConn.Close()

			addr, err := parseRemoteAddr(tcpConn)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.True(t, addr.IsValid())
			}
		})
	}
}

func TestResolveKeepaliveRange(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			lo, hi, enabled := resolveKeepaliveRange(tt.min, tt.max)
			assert.Equal(t, tt.wantLo, lo)
			assert.Equal(t, tt.wantHi, hi)
			assert.Equal(t, tt.wantEnabled, enabled)
		})
	}
}

func TestServer_HandleAccept_WhenRegisterSessionReturnsNil(t *testing.T) {
	t.Parallel()

	server1, client1 := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client1.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})

	tcpAddr, ok := server1.RemoteAddr().(*net.TCPAddr)
	require.True(t, ok)
	peerAddr := netip.MustParseAddr(tcpAddr.IP.String())
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{logger: lg}

	ss1 := s.registerSession(server1, peerAddr)
	require.NotNil(t, ss1)

	server2, client2 := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client2.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("cleanup close: %v", err)
		}
	})

	err := s.handleAccept(server2)

	require.NoError(t, err, "handleAccept should return nil when registerSession rejects a duplicate peer")
	assert.Len(t, s.Sessions(), 1, "expected only the first session to remain")
	assert.Len(t, logs.FilterByMessage("rejecting second PCEP session attempt from peer"), 1,
		"expected rejection log for duplicate peer")

	s.closeSession(ss1)
}

// acceptOnceThenClosedListener makes the first AcceptTCP call report a closed listener.
type acceptOnceThenClosedListener struct {
	closeErr error
}

func (l *acceptOnceThenClosedListener) AcceptTCP() (*net.TCPConn, error) {
	return nil, net.ErrClosed
}

func (l *acceptOnceThenClosedListener) Close() error { return l.closeErr }

type acceptErrListener struct {
	acceptErr error
}

func (l *acceptErrListener) AcceptTCP() (*net.TCPConn, error) { return nil, l.acceptErr }
func (l *acceptErrListener) Close() error                     { return nil }

func TestServer_Serve_AcceptErrorPropagated(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("accept boom")
	s := &Server{logger: logger.NewNop()}

	err := s.serve(&acceptErrListener{acceptErr: wantErr})

	require.ErrorIs(t, err, wantErr)
	assert.ErrorContains(t, err, "failed to accept TCP connection")
}

func TestServer_Serve_ListenerCloseErrorLogged(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("listener close failed")
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	s := &Server{logger: lg}

	err := s.serve(&acceptOnceThenClosedListener{closeErr: wantErr})

	require.NoError(t, err, "serve should return nil once AcceptTCP reports the listener closed")
	entries := logs.FilterByMessage("failed to close PCEP listener")
	require.Len(t, entries, 1)
	assert.Nil(t, s.listener, "listener must be cleared once serve returns")
}
