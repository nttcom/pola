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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

// newTCPConnPair returns a connected TCP connection pair over loopback.
func newTCPConnPair(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to listen")
	t.Cleanup(func() {
		assert.NoError(t, ln.Close(), "failed to close listener")
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
	require.NoError(t, err, "failed to dial")

	select {
	case server := <-serverCh:
		return server, clientConn.(*net.TCPConn)
	case err := <-errCh:
		require.NoError(t, err, "failed to accept connection")
		return nil, clientConn.(*net.TCPConn)
	}
}

// newTestStateReport builds a PCRpt state report for an SR-MPLS policy with an explicit path.
func newTestStateReport(t *testing.T, plspID uint32, srpID uint32) *pcep.StateReport {
	t.Helper()

	sr, err := pcep.NewStateReport()
	require.NoError(t, err, "failed to create state report")

	sr.SrpObject.SrpID = srpID
	sr.LSPObject.PlspID = plspID
	sr.LSPObject.Name = "pe01-policy1"
	sr.LSPObject.SrcAddr = netip.MustParseAddr("10.255.0.1")
	sr.LSPObject.DstAddr = netip.MustParseAddr("10.255.0.2")
	sr.LSPObject.OFlag = 0x02

	for _, sid := range []uint32{16002, 16003} {
		subobj, err := pcep.NewSREroSubobject(table.NewSegmentSRMPLS(sid))
		require.NoError(t, err, "failed to create SR ERO subobject")
		sr.EroObject.EroSubobjects = append(sr.EroObject.EroSubobjects, subobj)
	}

	return sr
}

// A PCC may report an SR Policy with SRP-ID 0 even when TED is unavailable.
func TestHandleStateReportWithoutTED(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, sr.LSPObject.Name, policy.Name)
	assert.Len(t, policy.SegmentList, 2)
}

func TestSRPolicies_SnapshotSegmentListIsIndependent(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policies := ss.SRPolicies()
	require.Len(t, policies, 1)
	require.NotEmpty(t, policies[0].SegmentList)

	want := policies[0].SegmentList[0]
	policies[0].SegmentList[0] = table.NewSegmentSRMPLS(99999)

	got, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, want, got.SegmentList[0], "mutating the snapshot's SegmentList changed the session's SR Policy")
}

func TestSRPolicies_SnapshotSRv6StructureIsIndependent(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	srv6Seg := table.NewSegmentSRv6(netip.MustParseAddr("2001:db8:1005::"))
	srv6Seg.Structure = table.SIDStructureBytes{32, 16, 0, 80}
	ss.srPolicies = append(ss.srPolicies, table.NewSRPolicy(1, "pe01-policy1", []table.Segment{srv6Seg}, netip.MustParseAddr("10.255.0.1"), netip.MustParseAddr("10.255.0.2"), 0, 0, 0, table.PolicyUp))

	policies := ss.SRPolicies()
	require.Len(t, policies, 1)
	require.NotEmpty(t, policies[0].SegmentList)

	snapshotSeg, ok := policies[0].SegmentList[0].(table.SegmentSRv6)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRv6", policies[0].SegmentList[0])
	snapshotSeg.Structure[0] = 99

	got, found := ss.SearchSRPolicy(1)
	require.True(t, found, "SR Policy was not registered")
	gotSeg, ok := got.SegmentList[0].(table.SegmentSRv6)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRv6", got.SegmentList[0])
	assert.Equal(t, table.SIDStructureBytes{32, 16, 0, 80}, gotSeg.Structure,
		"mutating the snapshot's SegmentSRv6.Structure changed the session's SR Policy")
}

func TestSRPolicyIntent_AttachedOnCreationBySRPID(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 7)

	ss.rememberSRPolicyIntent(7, table.PolicyTypeDynamic, table.TEMetric)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, table.PolicyTypeDynamic, policy.Type)
	assert.Equal(t, table.TEMetric, policy.Metric)
}

func TestSRPolicyIntent_AttachedOnUpdateBySRPID(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	ss.rememberSRPolicyIntent(1, table.PolicyTypeExplicit, table.UnspecifiedMetric)
	sr := newTestStateReport(t, 1, 1)
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	require.Equal(t, table.PolicyTypeExplicit, policy.Type, "initial policy intent")
	require.Equal(t, table.UnspecifiedMetric, policy.Metric, "initial policy intent")

	// A PCRpt for the same PLSP-ID takes the update path and must pick up the new intent.
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)
	sr2 := newTestStateReport(t, 1, 2)
	require.NoError(t, ss.handleStateReport(sr2, pcep.NewPCRptMessage()))

	policy, found = ss.SearchSRPolicy(sr2.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, table.PolicyTypeDynamic, policy.Type, "policy type after update")
	assert.Equal(t, table.TEMetric, policy.Metric, "policy metric after update")
}

func TestSRPolicyIntent_UnknownWhenNeverRemembered(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, table.PolicyType(""), policy.Type, "policy type should be unset")
	assert.Equal(t, table.UnspecifiedMetric, policy.Metric)
}

func TestSRPolicyIntent_IndependentPerSRPID(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	ss.rememberSRPolicyIntent(1, table.PolicyTypeExplicit, table.UnspecifiedMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)

	// SRP-ID 2's PCRpt arrives first and must only consume intent 2.
	srB := newTestStateReport(t, 20, 2)
	require.NoError(t, ss.handleStateReport(srB, pcep.NewPCRptMessage()))
	policyB, found := ss.SearchSRPolicy(srB.LSPObject.PlspID)
	require.True(t, found, "SR Policy for SRP-ID 2 was not registered")
	assert.Equal(t, table.PolicyTypeDynamic, policyB.Type, "policy for SRP-ID 2")
	assert.Equal(t, table.TEMetric, policyB.Metric, "policy for SRP-ID 2")

	ss.srPolicyIntentsMu.Lock()
	_, ok := ss.srPolicyIntents[1]
	ss.srPolicyIntentsMu.Unlock()
	assert.True(t, ok, "intent for SRP-ID 1 must survive consuming SRP-ID 2's intent")

	// SRP-ID 1's PCRpt arrives second and must consume only intent 1.
	srA := newTestStateReport(t, 10, 1)
	require.NoError(t, ss.handleStateReport(srA, pcep.NewPCRptMessage()))
	policyA, found := ss.SearchSRPolicy(srA.LSPObject.PlspID)
	require.True(t, found, "SR Policy for SRP-ID 1 was not registered")
	assert.Equal(t, table.PolicyTypeExplicit, policyA.Type, "policy for SRP-ID 1")
	assert.Equal(t, table.UnspecifiedMetric, policyA.Metric, "policy for SRP-ID 1")
}

func TestSRPolicyIntent_UnsolicitedPCRptDoesNotConsume(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)

	sr := newTestStateReport(t, 1, 0)
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, table.PolicyType(""), policy.Type, "unsolicited PCRpt must not consume an intent")

	_, ok := ss.takeSRPolicyIntent(1)
	assert.True(t, ok, "intent for SRP-ID 1 must remain after an unrelated unsolicited PCRpt")
}

func TestSRPolicyIntent_ClearedOnRFlagDelete(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	// Create the policy unsolicited so its creation does not consume the intent below.
	sr := newTestStateReport(t, 1, 0)
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	ss.rememberSRPolicyIntent(5, table.PolicyTypeDynamic, table.TEMetric)

	del := newTestStateReport(t, 1, 5)
	del.LSPObject.RFlag = true
	require.NoError(t, ss.handleStateReport(del, pcep.NewPCRptMessage()))

	_, found := ss.SearchSRPolicy(del.LSPObject.PlspID)
	assert.False(t, found, "SR Policy is still registered after being reported as removed")

	_, ok := ss.takeSRPolicyIntent(5)
	assert.False(t, ok, "intent for SRP-ID 5 was not removed after an R-Flag PCRpt")
}

func TestHandlePCErr_ForgetsReportedSRPIDIntents(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	pcerrMessage, err := pcep.NewPCErrMessage(1, 1, nil)
	require.NoError(t, err, "failed to create PCErr message")
	pcerrMessage.SRPs = []*pcep.SrpObject{{SrpID: 1}}

	ss.handlePCErr(pcerrMessage)

	_, ok := ss.takeSRPolicyIntent(1)
	assert.False(t, ok, "intent for SRP-ID 1 was not removed after a PCErr reporting it")

	_, ok = ss.takeSRPolicyIntent(2)
	assert.True(t, ok, "intent for SRP-ID 2 must survive a PCErr that does not report it")
}

// A failed PCEP send must not leave an intent waiting for a PCRpt that will never arrive.
func TestSendSRPolicyRequest_ForgetsIntentOnSendFailure(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.isSynced = true
	wantSRPID := ss.srpIDHead

	// Close the PCEP-side connection so the send inside sendSRPolicyRequest fails.
	require.NoError(t, server.Close(), "failed to close server connection")

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

	err := sendSRPolicyRequest(apiServer, req, nil, netip.MustParseAddr("10.255.0.1"), dstAddr, true)
	require.Error(t, err, "expected sendSRPolicyRequest to fail once the connection is closed")

	_, ok := ss.takeSRPolicyIntent(wantSRPID)
	assert.False(t, ok, "srPolicyIntents entry was not removed after a failed send")
}

// Closing a session must clear its remembered SR Policy intents.
func TestCloseSession_ClearsSRPolicyIntents(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)

	s := &Server{sessionList: []*Session{ss}, logger: zap.NewNop()}
	s.closeSession(ss)

	assert.Empty(t, ss.srPolicyIntents, "srPolicyIntents was not cleared on session close")
}

// Concurrent SendPCUpdate/SendPCInitiate calls must never allocate the same SRP-ID,
// and every allocated SRP-ID must have exactly one intent registered for it.
func TestConcurrentSRPolicyRequestsAllocateUniqueSRPIDs(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
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
		assert.NoError(t, client.Close(), "failed to close client connection")
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
		assert.NoError(t, err)
	}

	ss.srPolicyIntentsMu.Lock()
	gotIntents := len(ss.srPolicyIntents)
	ss.srPolicyIntentsMu.Unlock()
	assert.Equal(t, goroutines, gotIntents, "SRP-IDs must not collide")
	assert.Equal(t, uint32(1+goroutines), ss.srpIDHead)
}

func TestAllocateSRPID_SkipsReservedValues(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDHead = math.MaxUint32 - 1

	for i, want := range []uint32{math.MaxUint32 - 1, 1, 2} {
		got, err := ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
		require.NoErrorf(t, err, "allocation %d", i)
		require.NotContainsf(t, []uint32{0, math.MaxUint32}, got, "allocation %d: got reserved SRP-ID", i)
		assert.Equalf(t, want, got, "allocation %d", i)
	}
}

// The same report with the R-Flag set removes the SR Policy instead of registering it.
func TestHandleStateReportRemove(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	sr.LSPObject.RFlag = true
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	_, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	assert.False(t, found, "SR Policy is still registered after being reported as removed")
}

func TestReceiveOpenSeparatesPccAndPolaCapabilities(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	// The PCC advertises Color Capability support but not LSP Update Capability.
	pccCaps := []pcep.CapabilityInterface{
		&pcep.StatefulPCECapability{
			LSPUpdateCapability: false,
			ColorCapability:     true,
		},
	}
	openMessage, err := pcep.NewOpenMessage(1, 30, pccCaps)
	require.NoError(t, err, "failed to create open message")
	byteOpenMessage, err := openMessage.Serialize()
	require.NoError(t, err, "failed to serialize open message")
	_, err = client.Write(byteOpenMessage)
	require.NoError(t, err, "failed to write open message")

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	require.NoError(t, ss.ReceiveOpen())

	assert.Equal(t, pccCaps, ss.receivedPccCapabilities)
	assert.Equal(t, pcep.PolaCapability(pccCaps), ss.advertisedCapabilities)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.TLVs = append(sr.LSPObject.TLVs, &pcep.Color{Color: 100})
	color, _ := ss.resolveColorPreference(sr)
	assert.Equal(t, uint32(100), color, "resolveColorPreference did not detect Color Capability from receivedPccCapabilities")

	receivedCap := ss.receivedPccCapabilities[0].(*pcep.StatefulPCECapability)
	polaCap := ss.advertisedCapabilities[0].(*pcep.StatefulPCECapability)
	assert.NotSame(t, receivedCap, polaCap, "receivedPccCapabilities and advertisedCapabilities share the same StatefulPCECapability instance")
	assert.NotEqual(t, receivedCap.LSPUpdateCapability, polaCap.LSPUpdateCapability,
		"expected received and advertised StatefulPCECapability to diverge, got identical LSPUpdateCapability")
}

func TestSweepExpiredSRPolicyIntents_RemovesExpired(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srPolicyIntentsMu.Lock()
	ss.srPolicyIntents = map[uint32]srPolicyIntent{
		1: {polType: table.PolicyTypeDynamic, metric: table.TEMetric, expiresAt: time.Now().Add(-time.Second)},
	}
	ss.srPolicyIntentsMu.Unlock()

	ss.sweepExpiredSRPolicyIntents()

	_, ok := ss.takeSRPolicyIntent(1)
	assert.False(t, ok, "expired intent was not removed by the sweeper")
}

func TestSweepExpiredSRPolicyIntents_KeepsUnexpired(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srPolicyIntentsMu.Lock()
	ss.srPolicyIntents = map[uint32]srPolicyIntent{
		1: {polType: table.PolicyTypeDynamic, metric: table.TEMetric, expiresAt: time.Now().Add(time.Hour)},
	}
	ss.srPolicyIntentsMu.Unlock()

	ss.sweepExpiredSRPolicyIntents()

	_, ok := ss.takeSRPolicyIntent(1)
	assert.True(t, ok, "unexpired intent was removed by the sweeper")
}

func TestSweepExpiredSRPolicyIntents_KeepsUnrelatedIntent(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	_, ok := ss.takeSRPolicyIntent(1)
	require.True(t, ok, "expected intent 1 to be present before consuming it")

	ss.sweepExpiredSRPolicyIntents()

	_, ok = ss.takeSRPolicyIntent(2)
	assert.True(t, ok, "sweep must not remove an unrelated intent still within its TTL")
}

func TestIntentSweep_RunsInBackgroundAndStopsCleanly(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srPolicyIntentTTL = 10 * time.Millisecond
	ss.sweepInterval = 5 * time.Millisecond

	ss.startIntentSweep()
	defer ss.stopIntentSweep()

	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)

	require.Eventually(t, func() bool {
		return !ss.srPolicyIntentExists(1)
	}, 2*time.Second, 5*time.Millisecond, "intent was not swept in the background within the deadline")
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
		require.Fail(t, "stopIntentSweep did not return; the sweep goroutine may have leaked")
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
	require.NoError(t, err)
	assert.Equal(t, uint32(3), got, "SRP-IDs 4, 1 and 2 are in use and must be skipped")
}

func TestNextUnusedSRPID_ErrorsWhenExhausted(t *testing.T) {
	used := map[uint32]bool{1: true, 2: true, 3: true, 4: true}
	_, _, err := nextUnusedSRPID(1, 5, func(id uint32) bool { return used[id] })
	require.Error(t, err, "expected an error when every non-reserved SRP-ID is in use")
}

func TestAllocateSRPID_SkipsInUseIDsOnWraparound(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDHead = math.MaxUint32 - 1

	// Pre-occupy SRP-ID 1 so the wraparound scan must skip over it.
	ss.rememberSRPolicyIntent(1, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	got, err := ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
	require.NoError(t, err, "allocation 1")
	require.Equal(t, uint32(math.MaxUint32-1), got, "allocation 1")

	got, err = ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
	require.NoError(t, err, "allocation 2")
	assert.Equal(t, uint32(2), got, "allocation 2: SRP-ID 1 is still in use and must be skipped")

	_, ok := ss.takeSRPolicyIntent(2)
	assert.True(t, ok, "allocateSRPID must register an intent for the SRP-ID it returns")
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
		assert.NoError(t, err)
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
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	const goroutines = 40

	readerErr := startPCEPFramingValidator(client, goroutines)

	sendConcurrentPCEPMessages(t, ss, goroutines)

	select {
	case err := <-readerErr:
		require.NoError(t, err, "reader failed")
	case <-time.After(5 * time.Second):
		require.Fail(t, "did not observe all messages on the wire; sends may have interleaved and corrupted framing")
	}
}

func TestSendPCEPMessage_UnlocksAfterSendFailure(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	require.NoError(t, server.Close(), "failed to close server connection")

	require.Error(t, ss.SendKeepalive(), "expected SendKeepalive to fail once the connection is closed")

	done := make(chan error, 1)
	go func() {
		done <- ss.SendKeepalive()
	}()

	select {
	case err := <-done:
		require.Error(t, err, "expected second SendKeepalive to fail")
	case <-time.After(2 * time.Second):
		require.Fail(t, "second SendKeepalive blocked; send mutex may not have been released")
	}
}

func TestFindRouterIDFromAddress(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}

	v4Node := table.NewLsNode(0, "router-v4")
	v4Prefix := table.NewLsPrefix(v4Node)
	v4Prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	v4Node.Prefixes = append(v4Node.Prefixes, v4Prefix)
	ted.Nodes[v4Node.RouterID] = v4Node

	v6Node := table.NewLsNode(0, "router-v6")
	v6Prefix := table.NewLsPrefix(v6Node)
	v6Prefix.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	v6Node.Prefixes = append(v6Node.Prefixes, v6Prefix)
	ted.Nodes[v6Node.RouterID] = v6Node

	subnetNode := table.NewLsNode(0, "router-subnet")
	subnetPrefix := table.NewLsPrefix(subnetNode)
	subnetPrefix.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	subnetNode.Prefixes = append(subnetNode.Prefixes, subnetPrefix)
	ted.Nodes[subnetNode.RouterID] = subnetNode

	// No prefixes: only matchable by Router ID.
	idNode := table.NewLsNode(0, "198.51.100.1")
	ted.Nodes[idNode.RouterID] = idNode

	ss := &Session{ted: ted}
	addrIndex := buildAddressRouterIDIndex(ted)

	cases := []struct {
		name    string
		addr    netip.Addr
		want    string
		wantErr bool
	}{
		{"ipv4 prefix", netip.MustParseAddr("192.0.2.10"), "router-v4", false},
		{"ipv6 prefix", netip.MustParseAddr("2001:db8::1"), "router-v6", false},
		{"non-host prefix network address", netip.MustParseAddr("192.0.2.0"), "router-subnet", false},
		{"router id match", netip.MustParseAddr("198.51.100.1"), "198.51.100.1", false},
		{"not found", netip.MustParseAddr("203.0.113.5"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ss.findRouterIDFromAddress(addrIndex, tc.addr)
			if tc.wantErr {
				require.Errorf(t, err, "expected error, got routerID %q", got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractSrcDstRouterIDs(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}

	srcNode := table.NewLsNode(0, "src-router")
	srcPrefix := table.NewLsPrefix(srcNode)
	srcPrefix.Prefix = netip.MustParsePrefix("10.255.0.1/32")
	srcNode.Prefixes = append(srcNode.Prefixes, srcPrefix)
	ted.Nodes[srcNode.RouterID] = srcNode

	dstNode := table.NewLsNode(0, "10.255.0.2")
	ted.Nodes[dstNode.RouterID] = dstNode

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	srcRouterID, dstRouterID, err := ss.extractSrcDstRouterIDs(*sr)
	require.NoError(t, err, "extractSrcDstRouterIDs failed")
	assert.Equal(t, "src-router", srcRouterID)
	assert.Equal(t, "10.255.0.2", dstRouterID)
}

func TestExtractSrcDstRouterIDs_AddressNotFound(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	_, _, err := ss.extractSrcDstRouterIDs(*sr)
	assert.Error(t, err, "expected an error when neither address is present in the TED")
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
