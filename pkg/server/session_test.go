// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"go.uber.org/zap"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

// newTCPConnPair returns a connected TCP connection pair over loopback.
func newTCPConnPair(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("failed to close listener: %v", err)
		}
	})

	serverCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- conn.(*net.TCPConn)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	select {
	case server := <-serverCh:
		return server, clientConn.(*net.TCPConn)
	case err := <-errCh:
		t.Fatalf("failed to accept connection: %v", err)
		return nil, clientConn.(*net.TCPConn)
	}
}

// newTestStateReport builds a PCRpt state report for an SR-MPLS policy with an explicit path.
func newTestStateReport(t *testing.T, plspID uint32, srpID uint32) *pcep.StateReport {
	t.Helper()

	sr, err := pcep.NewStateReport()
	if err != nil {
		t.Fatalf("failed to create state report: %v", err)
	}

	sr.SrpObject.SrpID = srpID
	sr.LSPObject.PlspID = plspID
	sr.LSPObject.Name = "pe01-policy1"
	sr.LSPObject.SrcAddr = netip.MustParseAddr("10.255.0.1")
	sr.LSPObject.DstAddr = netip.MustParseAddr("10.255.0.2")
	sr.LSPObject.OFlag = 0x02

	for _, sid := range []uint32{16002, 16003} {
		subobj, err := pcep.NewSREroSubobject(table.NewSegmentSRMPLS(sid))
		if err != nil {
			t.Fatalf("failed to create SR ERO subobject: %v", err)
		}
		sr.EroObject.EroSubobjects = append(sr.EroObject.EroSubobjects, subobj)
	}

	return sr
}

// A PCC may report an SR Policy on its own (SRP-ID 0), which asks the PCE to compute a path.
// With the TED disabled the PCE cannot compute anything, but that must not fail the state report:
// doing so used to tear down the PCEP session and made the PCC reconnect in a loop.
func TestHandleStateReportWithoutTED(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy reported by the PCC was not registered")
	}
	if policy.Name != sr.LSPObject.Name {
		t.Errorf("policy name: got %q, want %q", policy.Name, sr.LSPObject.Name)
	}
	if len(policy.SegmentList) != 2 {
		t.Errorf("segment list length: got %d, want 2", len(policy.SegmentList))
	}
}

// The same report with the R-Flag set removes the SR Policy instead of registering it.
func TestHandleStateReportRemove(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	sr.LSPObject.RFlag = true
	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	if _, found := ss.SearchSRPolicy(sr.LSPObject.PlspID); found {
		t.Error("SR Policy is still registered after being reported as removed")
	}
}

func TestReceiveOpenSeparatesPccAndPolaCapabilities(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close server connection: %v", err)
		}
	})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client connection: %v", err)
		}
	})

	// The PCC advertises Color Capability support but not LSP Update Capability.
	pccCaps := []pcep.CapabilityInterface{
		&pcep.StatefulPCECapability{
			LSPUpdateCapability: false,
			ColorCapability:     true,
		},
	}
	openMessage, err := pcep.NewOpenMessage(1, 30, pccCaps)
	if err != nil {
		t.Fatalf("failed to create open message: %v", err)
	}
	byteOpenMessage, err := openMessage.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize open message: %v", err)
	}
	if _, err := client.Write(byteOpenMessage); err != nil {
		t.Fatalf("failed to write open message: %v", err)
	}

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	if err := ss.ReceiveOpen(); err != nil {
		t.Fatalf("ReceiveOpen returned an error: %v", err)
	}

	if !reflect.DeepEqual(ss.receivedPccCapabilities, pccCaps) {
		t.Errorf("receivedPccCapabilities: got %+v, want %+v", ss.receivedPccCapabilities, pccCaps)
	}

	wantPolaCaps := pcep.PolaCapability(pccCaps)
	if !reflect.DeepEqual(ss.advertisedCapabilities, wantPolaCaps) {
		t.Errorf("advertisedCapabilities: got %+v, want %+v", ss.advertisedCapabilities, wantPolaCaps)
	}

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.TLVs = append(sr.LSPObject.TLVs, &pcep.Color{Color: 100})
	color, _ := ss.resolveColorPreference(sr)
	if color != 100 {
		t.Errorf("resolveColorPreference did not detect Color Capability from receivedPccCapabilities: got color %d, want 100", color)
	}

	receivedCap := ss.receivedPccCapabilities[0].(*pcep.StatefulPCECapability)
	polaCap := ss.advertisedCapabilities[0].(*pcep.StatefulPCECapability)
	if receivedCap == polaCap {
		t.Error("receivedPccCapabilities and advertisedCapabilities share the same StatefulPCECapability instance")
	}
	if receivedCap.LSPUpdateCapability == polaCap.LSPUpdateCapability {
		t.Error("expected received and advertised StatefulPCECapability to diverge, got identical LSPUpdateCapability")
	}
}
