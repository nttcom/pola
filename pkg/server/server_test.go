// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
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
			go func() { errCh <- NewPCE(tt.o, zap.NewNop(), make(chan []table.TEDElem)) }()

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
	go func() { errCh <- NewPCE(o, zap.New(core), tedElemsChan) }()

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
