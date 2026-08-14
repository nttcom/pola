// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"net"
	"net/netip"
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
		_, dialErr := net.DialTimeout("tcp", net.JoinHostPort(addr, port), 100*time.Millisecond)
		return dialErr == nil
	}, 2*time.Second, 10*time.Millisecond, "expected the PCEP listener to accept connections before shutdown")

	require.NoError(t, s.Shutdown(), "Shutdown should close the listener without error")

	select {
	case err := <-serveErrCh:
		assert.NoError(t, err, "Serve should return cleanly once the listener is closed")
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

func TestServer_CloseSession_LogsWarnOnCloseFailure(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})
	require.NoError(t, server.Close(), "failed to pre-close server connection")

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
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
				assert.Error(t, err.Error)
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
		PCEPAddr:  "not-an-ip", // fail before listening
		PCEPPort:  "0",
		GRPCAddr:  "127.0.0.1",
		GRPCPort:  "0",
		TEDEnable: true,
	}

	errCh := make(chan Error, 1)
	go func() { errCh <- NewPCE(context.Background(), o, zap.New(core), tedElemsChan) }()

	tedElemsChan <- []table.TEDElem{}

	require.Eventually(t, func() bool {
		return len(logs.FilterMessage("Update TED").All()) > 0
	}, 2*time.Second, 10*time.Millisecond, "expected the TED update goroutine to run")

	select {
	case err := <-errCh:
		assert.Equal(t, "pcep", err.Server)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NewPCE to report an error")
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
		assert.NoError(t, err.Error)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NewPCE to shut down after context cancellation")
	}
}
