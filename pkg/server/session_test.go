// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

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
