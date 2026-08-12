// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	pb "github.com/nttcom/pola/api/pola/v1"
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

// A PCC may report an SR Policy with SRP-ID 0 even when TED is unavailable.
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

func TestSRPolicies_SnapshotSegmentListIsIndependent(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	policies := ss.SRPolicies()
	if len(policies) != 1 || len(policies[0].SegmentList) == 0 {
		t.Fatalf("expected one SR Policy with a non-empty segment list, got %+v", policies)
	}

	want := policies[0].SegmentList[0]
	policies[0].SegmentList[0] = table.NewSegmentSRMPLS(99999)

	got, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy reported by the PCC was not registered")
	}
	if !reflect.DeepEqual(got.SegmentList[0], want) {
		t.Errorf("mutating the snapshot's SegmentList changed the session's SR Policy: got %v, want %v", got.SegmentList[0], want)
	}
}

func TestSRPolicies_SnapshotSRv6StructureIsIndependent(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	srv6Seg := table.NewSegmentSRv6(netip.MustParseAddr("2001:db8:1005::"))
	srv6Seg.Structure = table.SIDStructureBytes{32, 16, 0, 80}
	ss.srPolicies = append(ss.srPolicies, table.NewSRPolicy(1, "pe01-policy1", []table.Segment{srv6Seg}, netip.MustParseAddr("10.255.0.1"), netip.MustParseAddr("10.255.0.2"), 0, 0, 0, table.PolicyUp))

	policies := ss.SRPolicies()
	if len(policies) != 1 || len(policies[0].SegmentList) == 0 {
		t.Fatalf("expected one SR Policy with a non-empty segment list, got %+v", policies)
	}

	snapshotSeg, ok := policies[0].SegmentList[0].(table.SegmentSRv6)
	if !ok {
		t.Fatalf("segment type: got %T, want table.SegmentSRv6", policies[0].SegmentList[0])
	}
	snapshotSeg.Structure[0] = 99

	got, found := ss.SearchSRPolicy(1)
	if !found {
		t.Fatal("SR Policy was not registered")
	}
	gotSeg, ok := got.SegmentList[0].(table.SegmentSRv6)
	if !ok {
		t.Fatalf("segment type: got %T, want table.SegmentSRv6", got.SegmentList[0])
	}
	if !reflect.DeepEqual(gotSeg.Structure, table.SIDStructureBytes{32, 16, 0, 80}) {
		t.Errorf("mutating the snapshot's SegmentSRv6.Structure changed the session's SR Policy: got %v", gotSeg.Structure)
	}
}

func TestSRPolicyIntent_AttachedOnCreationBySRPID(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 7)

	ss.rememberSRPolicyIntent(7, table.PolicyTypeDynamic, table.TEMetric)

	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy reported by the PCC was not registered")
	}
	if policy.Type != table.PolicyTypeDynamic {
		t.Errorf("policy type: got %q, want %q", policy.Type, table.PolicyTypeDynamic)
	}
	if policy.Metric != table.TEMetric {
		t.Errorf("policy metric: got %v, want %v", policy.Metric, table.TEMetric)
	}
}

// A policy update must also replace the recorded type and metric, using the intent
// keyed by the SRP-ID of the update request.
func TestSRPolicyIntent_AttachedOnUpdateBySRPID(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	ss.rememberSRPolicyIntent(1, table.PolicyTypeExplicit, table.UnspecifiedMetric)
	sr := newTestStateReport(t, 1, 1)
	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy reported by the PCC was not registered")
	}
	if policy.Type != table.PolicyTypeExplicit || policy.Metric != table.UnspecifiedMetric {
		t.Fatalf("initial policy intent: got (%q, %v), want (%q, %v)", policy.Type, policy.Metric, table.PolicyTypeExplicit, table.UnspecifiedMetric)
	}

	// A PCRpt for the same PLSP-ID takes the update path and must pick up the new intent.
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)
	sr2 := newTestStateReport(t, 1, 2)
	if err := ss.handleStateReport(sr2, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	policy, found = ss.SearchSRPolicy(sr2.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy reported by the PCC was not registered")
	}
	if policy.Type != table.PolicyTypeDynamic {
		t.Errorf("policy type after update: got %q, want %q", policy.Type, table.PolicyTypeDynamic)
	}
	if policy.Metric != table.TEMetric {
		t.Errorf("policy metric after update: got %v, want %v", policy.Metric, table.TEMetric)
	}
}

func TestSRPolicyIntent_UnknownWhenNeverRemembered(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy reported by the PCC was not registered")
	}
	if policy.Type != "" {
		t.Errorf("policy type: got %q, want unset", policy.Type)
	}
	if policy.Metric != table.UnspecifiedMetric {
		t.Errorf("policy metric: got %v, want UnspecifiedMetric", policy.Metric)
	}
}

func TestSRPolicyIntent_IndependentPerSRPID(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	ss.rememberSRPolicyIntent(1, table.PolicyTypeExplicit, table.UnspecifiedMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)

	// SRP-ID 2's PCRpt arrives first and must only consume intent 2.
	srB := newTestStateReport(t, 20, 2)
	if err := ss.handleStateReport(srB, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}
	policyB, found := ss.SearchSRPolicy(srB.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy for SRP-ID 2 was not registered")
	}
	if policyB.Type != table.PolicyTypeDynamic || policyB.Metric != table.TEMetric {
		t.Errorf("policy for SRP-ID 2: got (%q, %v), want (%q, %v)", policyB.Type, policyB.Metric, table.PolicyTypeDynamic, table.TEMetric)
	}
	ss.srPolicyIntentsMu.Lock()
	_, ok := ss.srPolicyIntents[1]
	ss.srPolicyIntentsMu.Unlock()
	if !ok {
		t.Error("intent for SRP-ID 1 must survive consuming SRP-ID 2's intent")
	}

	// SRP-ID 1's PCRpt arrives second and must consume only intent 1.
	srA := newTestStateReport(t, 10, 1)
	if err := ss.handleStateReport(srA, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}
	policyA, found := ss.SearchSRPolicy(srA.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy for SRP-ID 1 was not registered")
	}
	if policyA.Type != table.PolicyTypeExplicit || policyA.Metric != table.UnspecifiedMetric {
		t.Errorf("policy for SRP-ID 1: got (%q, %v), want (%q, %v)", policyA.Type, policyA.Metric, table.PolicyTypeExplicit, table.UnspecifiedMetric)
	}
}

func TestSRPolicyIntent_UnsolicitedPCRptDoesNotConsume(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)

	sr := newTestStateReport(t, 1, 0)
	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	if !found {
		t.Fatal("SR Policy reported by the PCC was not registered")
	}
	if policy.Type != "" {
		t.Errorf("policy type: got %q, want unset (unsolicited PCRpt must not consume an intent)", policy.Type)
	}

	if _, ok := ss.takeSRPolicyIntent(1); !ok {
		t.Error("intent for SRP-ID 1 must remain after an unrelated unsolicited PCRpt")
	}
}

func TestSRPolicyIntent_ClearedOnRFlagDelete(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	// Create the policy unsolicited so its creation does not consume the intent below.
	sr := newTestStateReport(t, 1, 0)
	if err := ss.handleStateReport(sr, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	ss.rememberSRPolicyIntent(5, table.PolicyTypeDynamic, table.TEMetric)

	del := newTestStateReport(t, 1, 5)
	del.LSPObject.RFlag = true
	if err := ss.handleStateReport(del, pcep.NewPCRptMessage()); err != nil {
		t.Fatalf("handleStateReport returned an error: %v", err)
	}

	if _, found := ss.SearchSRPolicy(del.LSPObject.PlspID); found {
		t.Error("SR Policy is still registered after being reported as removed")
	}
	if _, ok := ss.takeSRPolicyIntent(5); ok {
		t.Error("intent for SRP-ID 5 was not removed after an R-Flag PCRpt")
	}
}

func TestHandlePCErr_ForgetsReportedSRPIDIntents(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	pcerrMessage, err := pcep.NewPCErrMessage(1, 1, nil)
	if err != nil {
		t.Fatalf("failed to create PCErr message: %v", err)
	}
	pcerrMessage.SRPs = []*pcep.SrpObject{{SrpID: 1}}

	ss.handlePCErr(pcerrMessage)

	if _, ok := ss.takeSRPolicyIntent(1); ok {
		t.Error("intent for SRP-ID 1 was not removed after a PCErr reporting it")
	}
	if _, ok := ss.takeSRPolicyIntent(2); !ok {
		t.Error("intent for SRP-ID 2 must survive a PCErr that does not report it")
	}
}

// A failed PCEP send must not leave an intent waiting for a PCRpt that will never arrive.
func TestSendSRPolicyRequest_ForgetsIntentOnSendFailure(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client connection: %v", err)
		}
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.isSynced = true
	wantSRPID := ss.srpIDHead

	// Close the PCEP-side connection so the send inside sendSRPolicyRequest fails.
	if err := server.Close(); err != nil {
		t.Fatalf("failed to close server connection: %v", err)
	}

	pce := &Server{sessionList: []*Session{ss}}
	apiServer := &APIServer{pce: pce, logger: zap.NewNop()}

	dstAddr := netip.MustParseAddr("10.255.0.2")
	req := &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			PcepSessionAddr: ss.peerAddr.AsSlice(),
			DstAddr:         dstAddr.AsSlice(),
			Color:           100,
			PolicyName:      "test-policy",
			Type:            pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
		},
		DisablePathCompute: true,
	}

	if err := sendSRPolicyRequest(apiServer, req, nil, netip.MustParseAddr("10.255.0.1"), dstAddr, true); err == nil {
		t.Fatal("expected sendSRPolicyRequest to fail once the connection is closed")
	}

	if _, ok := ss.takeSRPolicyIntent(wantSRPID); ok {
		t.Error("srPolicyIntents entry was not removed after a failed send")
	}
}

// Closing a session must clear its remembered SR Policy intents.
func TestCloseSession_ClearsSRPolicyIntents(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client connection: %v", err)
		}
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)

	s := &Server{sessionList: []*Session{ss}, logger: zap.NewNop()}
	s.closeSession(ss)

	if len(ss.srPolicyIntents) != 0 {
		t.Errorf("srPolicyIntents was not cleared on session close: %+v", ss.srPolicyIntents)
	}
}

// Concurrent SendPCUpdate/SendPCInitiate calls must never allocate the same SRP-ID,
// and every allocated SRP-ID must have exactly one intent registered for it.
func TestConcurrentSRPolicyRequestsAllocateUniqueSRPIDs(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close server connection: %v", err)
		}
	})

	// Drain everything the server writes so sends never block on a full socket buffer.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client connection: %v", err)
		}
		<-done
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	const goroutines = 20
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			srPolicy := table.SRPolicy{
				Name:    "concurrent-test",
				SrcAddr: netip.MustParseAddr("10.255.0.1"),
				DstAddr: netip.MustParseAddr("10.255.0.2"),
				Color:   uint32(i),
				Type:    table.PolicyTypeDynamic,
				Metric:  table.TEMetric,
			}
			var err error
			if i%2 == 0 {
				err = ss.SendPCUpdate(srPolicy)
			} else {
				err = ss.RequestSRPolicyCreated(srPolicy)
			}
			errCh <- err
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Errorf("send returned an error: %v", err)
		}
	}

	ss.srPolicyIntentsMu.Lock()
	gotIntents := len(ss.srPolicyIntents)
	ss.srPolicyIntentsMu.Unlock()
	if gotIntents != goroutines {
		t.Errorf("srPolicyIntents count: got %d, want %d (SRP-IDs must not collide)", gotIntents, goroutines)
	}
	if ss.srpIDHead != uint32(1+goroutines) {
		t.Errorf("srpIDHead: got %d, want %d", ss.srpIDHead, uint32(1+goroutines))
	}
}

func TestAllocateSRPID_SkipsReservedValues(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDHead = math.MaxUint32 - 1

	for i, want := range []uint32{math.MaxUint32 - 1, 1, 2} {
		got, err := ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
		if err != nil {
			t.Fatalf("allocation %d: unexpected error: %v", i, err)
		}
		if got == 0 || got == math.MaxUint32 {
			t.Fatalf("allocation %d: got reserved SRP-ID %d", i, got)
		}
		if got != want {
			t.Errorf("allocation %d: got %d, want %d", i, got, want)
		}
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

func TestSweepExpiredSRPolicyIntents_RemovesExpired(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srPolicyIntentsMu.Lock()
	ss.srPolicyIntents = map[uint32]srPolicyIntent{
		1: {polType: table.PolicyTypeDynamic, metric: table.TEMetric, expiresAt: time.Now().Add(-time.Second)},
	}
	ss.srPolicyIntentsMu.Unlock()

	ss.sweepExpiredSRPolicyIntents()

	if _, ok := ss.takeSRPolicyIntent(1); ok {
		t.Error("expired intent was not removed by the sweeper")
	}
}

func TestSweepExpiredSRPolicyIntents_KeepsUnexpired(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srPolicyIntentsMu.Lock()
	ss.srPolicyIntents = map[uint32]srPolicyIntent{
		1: {polType: table.PolicyTypeDynamic, metric: table.TEMetric, expiresAt: time.Now().Add(time.Hour)},
	}
	ss.srPolicyIntentsMu.Unlock()

	ss.sweepExpiredSRPolicyIntents()

	if _, ok := ss.takeSRPolicyIntent(1); !ok {
		t.Error("unexpired intent was removed by the sweeper")
	}
}

func TestSweepExpiredSRPolicyIntents_KeepsUnrelatedIntent(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	if _, ok := ss.takeSRPolicyIntent(1); !ok {
		t.Fatal("expected intent 1 to be present before consuming it")
	}

	ss.sweepExpiredSRPolicyIntents()

	if _, ok := ss.takeSRPolicyIntent(2); !ok {
		t.Error("sweep must not remove an unrelated intent still within its TTL")
	}
}

func TestIntentSweep_RunsInBackgroundAndStopsCleanly(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srPolicyIntentTTL = 10 * time.Millisecond
	ss.sweepInterval = 5 * time.Millisecond

	ss.startIntentSweep()
	defer ss.stopIntentSweep()

	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)

	deadline := time.Now().Add(2 * time.Second)
	for ss.srPolicyIntentExists(1) {
		if time.Now().After(deadline) {
			t.Fatal("intent was not swept in the background within the deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestIntentSweep_StopsCleanly(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.startIntentSweep()

	done := make(chan struct{})
	go func() {
		ss.stopIntentSweep()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopIntentSweep did not return; the sweep goroutine may have leaked")
	}
}

func TestIntentSweep_ConcurrentWithIntentConsumption(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srPolicyIntentTTL = 5 * time.Millisecond
	ss.sweepInterval = 2 * time.Millisecond
	ss.startIntentSweep()
	defer ss.stopIntentSweep()

	var wg sync.WaitGroup
	for i := uint32(1); i <= 20; i++ {
		wg.Add(1)
		go func(srpID uint32) {
			defer wg.Done()
			ss.rememberSRPolicyIntent(srpID, table.PolicyTypeDynamic, table.TEMetric)
			time.Sleep(time.Millisecond)
			ss.takeSRPolicyIntent(srpID)
		}(i)
	}
	wg.Wait()
}

func TestNextUnusedSRPID_SkipsUsedAcrossWraparound(t *testing.T) {
	used := map[uint32]bool{1: true, 2: true, 4: true}
	got, _, err := nextUnusedSRPID(4, 5, func(id uint32) bool { return used[id] })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 3 {
		t.Errorf("got %d, want 3 (SRP-IDs 4, 1 and 2 are in use and must be skipped)", got)
	}
}

func TestNextUnusedSRPID_ErrorsWhenExhausted(t *testing.T) {
	used := map[uint32]bool{1: true, 2: true, 3: true, 4: true}
	if _, _, err := nextUnusedSRPID(1, 5, func(id uint32) bool { return used[id] }); err == nil {
		t.Fatal("expected an error when every non-reserved SRP-ID is in use")
	}
}

func TestAllocateSRPID_SkipsInUseIDsOnWraparound(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDHead = math.MaxUint32 - 1

	// Pre-occupy SRP-ID 1 so the wraparound scan must skip over it.
	ss.rememberSRPolicyIntent(1, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	got, err := ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
	if err != nil || got != math.MaxUint32-1 {
		t.Fatalf("allocation 1: got (%d, %v), want (%d, nil)", got, err, uint32(math.MaxUint32-1))
	}

	got, err = ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
	if err != nil {
		t.Fatalf("allocation 2: unexpected error: %v", err)
	}
	if got != 2 {
		t.Errorf("allocation 2: got %d, want 2 (SRP-ID 1 is still in use and must be skipped)", got)
	}
	if _, ok := ss.takeSRPolicyIntent(2); !ok {
		t.Error("allocateSRPID must register an intent for the SRP-ID it returns")
	}
}

// concurrentSendCase defines a PCEP message send used by the concurrent-send test.
type concurrentSendCase struct {
	name string
	send func(ss *Session, i int) error
}

var concurrentSendCases = []concurrentSendCase{
	{
		name: "SendKeepalive",
		send: func(ss *Session, i int) error { return ss.SendKeepalive() },
	},
	{
		name: "SendOpen",
		send: func(ss *Session, i int) error { return ss.SendOpen() },
	},
	{
		name: "SendClose",
		send: func(ss *Session, i int) error {
			return ss.SendClose(pcep.CloseReasonNoExplanationProvided)
		},
	},
	{
		name: "SendPCUpdate",
		send: func(ss *Session, i int) error {
			return ss.SendPCUpdate(table.SRPolicy{
				Name:    "concurrent-send-test",
				SrcAddr: netip.MustParseAddr("10.255.0.1"),
				DstAddr: netip.MustParseAddr("10.255.0.2"),
				Type:    table.PolicyTypeDynamic,
				Metric:  table.TEMetric,
			})
		},
	},
	{
		name: "RequestSRPolicyCreated",
		send: func(ss *Session, i int) error {
			return ss.RequestSRPolicyCreated(table.SRPolicy{
				Name:    "concurrent-send-test",
				SrcAddr: netip.MustParseAddr("10.255.0.1"),
				DstAddr: netip.MustParseAddr("10.255.0.2"),
				Color:   uint32(i),
				Type:    table.PolicyTypeDynamic,
				Metric:  table.TEMetric,
			})
		},
	},
}

func sendConcurrentPCEPMessages(t *testing.T, ss *Session, goroutines int) {
	t.Helper()

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := concurrentSendCases[i%len(concurrentSendCases)]
			errCh <- c.send(ss, i)
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Errorf("send returned an error: %v", err)
		}
	}
}

// readPCEPMessage reads and validates one PCEP message.
func readPCEPMessage(r io.Reader) error {
	headerBytes := make([]byte, pcep.CommonHeaderLength)
	if _, err := io.ReadFull(r, headerBytes); err != nil {
		return err
	}

	var header pcep.CommonHeader
	if err := header.DecodeFromBytes(headerBytes); err != nil {
		return fmt.Errorf("failed to decode a PCEP common header; sends may have interleaved: %w", err)
	}

	bodyLen := int(header.MessageLength) - int(pcep.CommonHeaderLength)
	if bodyLen == 0 {
		return nil
	}
	_, err := io.ReadFull(r, make([]byte, bodyLen))
	return err
}

// startPCEPFramingValidator validates PCEP message framing in the background.
func startPCEPFramingValidator(r io.Reader, wantCount int) <-chan error {
	result := make(chan error, 1)

	go func() {
		for i := 0; i < wantCount; i++ {
			if err := readPCEPMessage(r); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()

	return result
}

func TestSendPCEPMessage_ConcurrentSendsDoNotInterleave(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client connection: %v", err)
		}
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	const goroutines = 40

	readerErr := startPCEPFramingValidator(client, goroutines)

	sendConcurrentPCEPMessages(t, ss, goroutines)

	select {
	case err := <-readerErr:
		if err != nil {
			t.Fatalf("reader failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not observe all messages on the wire; sends may have interleaved and corrupted framing")
	}
}

func TestSendPCEPMessage_UnlocksAfterSendFailure(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client connection: %v", err)
		}
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	if err := server.Close(); err != nil {
		t.Fatalf("failed to close server connection: %v", err)
	}

	if err := ss.SendKeepalive(); err == nil {
		t.Fatal("expected SendKeepalive to fail once the connection is closed")
	}

	done := make(chan error, 1)
	go func() {
		done <- ss.SendKeepalive()
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected second SendKeepalive to fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second SendKeepalive blocked; send mutex may not have been released")
	}
}

// TestIsSynced_ConcurrentAccess verifies that setSynced and IsSynced are synchronized.
func TestIsSynced_ConcurrentAccess(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			ss.setSynced()
		}
	}()

	for i := 0; i < 100; i++ {
		ss.IsSynced()
	}
	<-done
}
