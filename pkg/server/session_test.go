// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"bytes"
	"errors"
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

// fakeConn is a net.Conn test double that can deterministically fail writes.
type fakeConn struct {
	r io.Reader

	mu                 sync.Mutex
	writeCount         int
	failAfter          int // number of successful writes before writeErr is returned; ignored if writeErr is nil.
	writeErr           error
	setReadDeadlineErr error
	closeErr           error
}

func (c *fakeConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCount++
	if c.writeErr != nil && c.writeCount > c.failAfter {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *fakeConn) Close() error                       { return c.closeErr }
func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *fakeConn) SetReadDeadline(t time.Time) error { return c.setReadDeadlineErr }

// newTestStateReport builds a PCRpt state report for an SR-MPLS policy with an explicit path.
func newTestStateReport(t *testing.T, plspID uint32, srpID uint32) *pcep.StateReport {
	t.Helper()

	sr := pcep.NewStateReport()

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

	pcerrMessage := pcep.NewPCErrMessage(1, 1, nil)
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

	err := sendSRPolicyRequest(apiServer, req, nil, netip.MustParseAddr("10.255.0.1"), dstAddr, true, table.UnspecifiedMetric)
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
	openMessage := pcep.NewOpenMessage(1, 30, pccCaps)
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

func TestRememberSRPolicyIntent_IgnoresReservedSRPID(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(0, table.PolicyTypeDynamic, table.TEMetric)
	assert.False(t, ss.srPolicyIntentExists(0))
}

func TestStartIntentSweep_Idempotent(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.startIntentSweep()
	firstStop := ss.sweepStop
	ss.startIntentSweep()
	defer ss.stopIntentSweep()

	assert.True(t, firstStop == ss.sweepStop, "startIntentSweep must not replace an already-running sweeper's stop channel")
}

func TestStopIntentSweep_NoopWhenNeverStarted(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.stopIntentSweep()
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

func TestAllocateSRPID_ErrorsWhenExhausted(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDMax = 3 // valid range is [1, 2]; 0 and 3 are reserved.
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)

	_, err := ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
	assert.Error(t, err, "expected an error when every non-reserved SRP-ID is in use")
}

func TestSendPCInitiate_ErrorsWhenSRPIDExhausted(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDMax = 3
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)

	srPolicy := table.SRPolicy{
		Name:    "srp-id-exhausted",
		SrcAddr: netip.MustParseAddr("10.255.0.1"),
		DstAddr: netip.MustParseAddr("10.255.0.2"),
		Type:    table.PolicyTypeDynamic,
		Metric:  table.TEMetric,
	}

	assert.Error(t, ss.SendPCInitiate(srPolicy, false))
}

func TestSendPCUpdate_ErrorsWhenSRPIDExhausted(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDMax = 3
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)

	srPolicy := table.SRPolicy{
		Name:    "srp-id-exhausted",
		SrcAddr: netip.MustParseAddr("10.255.0.1"),
		DstAddr: netip.MustParseAddr("10.255.0.2"),
		Type:    table.PolicyTypeDynamic,
		Metric:  table.TEMetric,
	}

	assert.Error(t, ss.SendPCUpdate(srPolicy))
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

func TestSearchPlspID_FindsByColorAndEndpoint(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	endpoint := netip.MustParseAddr("10.255.0.2")
	ss.srPolicies = append(ss.srPolicies,
		table.NewSRPolicy(1, "pe01-policy1", nil, netip.MustParseAddr("10.255.0.1"), endpoint, 100, 0, 0, table.PolicyUp),
		table.NewSRPolicy(2, "pe01-policy2", nil, netip.MustParseAddr("10.255.0.1"), netip.MustParseAddr("10.255.0.3"), 200, 0, 0, table.PolicyUp),
	)

	plspID, found := ss.SearchPlspID(100, endpoint)
	require.True(t, found, "SR Policy matching color and endpoint was not found")
	assert.Equal(t, uint32(1), plspID)
}

func TestSearchPlspID_NotFoundWhenColorOrEndpointDiffer(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	endpoint := netip.MustParseAddr("10.255.0.2")
	ss.srPolicies = append(ss.srPolicies,
		table.NewSRPolicy(1, "pe01-policy1", nil, netip.MustParseAddr("10.255.0.1"), endpoint, 100, 0, 0, table.PolicyUp),
	)

	_, found := ss.SearchPlspID(999, endpoint)
	assert.False(t, found, "must not match on endpoint alone when the color differs")

	_, found = ss.SearchPlspID(100, netip.MustParseAddr("10.255.0.9"))
	assert.False(t, found, "must not match on color alone when the endpoint differs")
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
	ted.Nodes["198.51.100.2"] = nil

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
		{"nil node entry", netip.MustParseAddr("198.51.100.2"), "", true},
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

func TestExtractSrcDstRouterIDs_InvalidAddresses(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = netip.Addr{}
	sr.LSPObject.DstAddr = netip.Addr{}

	_, _, err := ss.extractSrcDstRouterIDs(*sr)
	assert.Error(t, err, "expected an error when neither address is valid")
}

func TestExtractSrcDstRouterIDs_DestinationNotFound(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	srcNode := table.NewLsNode(0, "10.255.0.1")
	ted.Nodes[srcNode.RouterID] = srcNode

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)
	sr := newTestStateReport(t, 1, 0)

	_, _, err := ss.extractSrcDstRouterIDs(*sr)
	assert.Error(t, err, "expected an error when the destination address is not present in the TED")
}

func writeMessage(t *testing.T, w io.Writer, message pcep.Message) {
	t.Helper()
	b, err := message.Serialize()
	require.NoError(t, err, "failed to serialize message")
	_, err = w.Write(b)
	require.NoError(t, err, "failed to write message")
}

// writeStateReportMessage writes sr as an unsolicited PCRpt.
func writeStateReportMessage(t *testing.T, w io.Writer, sr *pcep.StateReport) {
	t.Helper()
	sr.LSPObject.TLVs = append(sr.LSPObject.TLVs,
		&pcep.SymbolicPathName{Name: sr.LSPObject.Name},
		pcep.NewIPv4LSPIdentifiers(sr.LSPObject.SrcAddr, sr.LSPObject.DstAddr, sr.LSPObject.LSPID, 0, 0),
	)
	byteSrp, err := sr.SrpObject.Serialize()
	require.NoError(t, err, "failed to serialize SrpObject")
	byteLsp, err := sr.LSPObject.Serialize()
	require.NoError(t, err, "failed to serialize LSPObject")
	byteEro, err := sr.EroObject.Serialize()
	require.NoError(t, err, "failed to serialize EroObject")
	body := append(append(byteSrp, byteLsp...), byteEro...)
	writeRawPCEPMessage(t, w, pcep.MessageTypeReport, body)
}

func writeRawPCEPMessage(t *testing.T, w io.Writer, msgType pcep.MessageType, body []byte) {
	t.Helper()
	header := &pcep.CommonHeader{Version: 1, MessageType: msgType, MessageLength: pcep.CommonHeaderLength + uint16(len(body))}
	_, err := w.Write(append(header.Serialize(), body...))
	require.NoError(t, err, "failed to write PCEP message")
}

func TestOpen_Established_ReturnsWhenOpenFails(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})

	// The peer disconnects before ever sending an Open message.
	require.NoError(t, client.Close(), "failed to close client connection")

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		ss.Established()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after Open failed")
	}
}

func TestEstablished_ReturnsOnCloseMessage(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	openMessage := pcep.NewOpenMessage(1, 30, nil)
	writeMessage(t, client, openMessage)

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		ss.Established()
		close(done)
	}()

	// Reading the Open reply and initial Keepalive ensures Established is in its receive loop.
	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read initial Keepalive")

	closeMessage := pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided)
	writeMessage(t, client, closeMessage)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the peer sent a Close message")
	}
}

func TestEstablished_ZeroKeepaliveDoesNotPanic(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	openMessage := pcep.NewOpenMessage(1, 0, nil)
	writeMessage(t, client, openMessage)

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read initial Keepalive")

	closeMessage := pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided)
	writeMessage(t, client, closeMessage)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the peer sent a Close message")
	}
}

func TestEstablished_ReturnsWhenPeerDisconnectsAbruptly(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})

	openMessage := pcep.NewOpenMessage(1, 30, nil)
	writeMessage(t, client, openMessage)

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read initial Keepalive")

	require.NoError(t, client.Close(), "failed to close client connection")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the peer connection was closed")
	}
}

func TestEstablished_ReturnsWhenPeriodicKeepaliveSendFails(t *testing.T) {
	openMessage := pcep.NewOpenMessage(1, 1, nil) // 1-second keepalive interval
	openBytes, err := openMessage.Serialize()
	require.NoError(t, err)

	// Keep the receive loop blocked until the test finishes.
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, pw.Close(), "failed to close pipe writer")
	})

	// Fail the periodic keepalive send after the Open reply and initial Keepalive.
	conn := &fakeConn{
		r:         io.MultiReader(bytes.NewReader(openBytes), pr),
		failAfter: 2,
		writeErr:  errors.New("write: broken pipe"),
	}

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		ss.Established()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		require.Fail(t, "Established did not return after the periodic keepalive send failed")
	}
}

func TestEstablished_ReturnsWhenInitialKeepaliveSendFails(t *testing.T) {
	openMessage := pcep.NewOpenMessage(1, 30, nil)
	openBytes, err := openMessage.Serialize()
	require.NoError(t, err)

	// The Open reply (write #1) succeeds; the initial Keepalive (write #2) fails.
	conn := &fakeConn{
		r:         bytes.NewReader(openBytes),
		failAfter: 1,
		writeErr:  errors.New("write: broken pipe"),
	}

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		ss.Established()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		require.Fail(t, "Established did not return after the initial keepalive send failed")
	}
}

func TestReceiveOpen_MalformedOpenMessage(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, client *net.TCPConn) (clientClosed bool)
	}{
		{
			name: "PCEP version mismatch",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				header := &pcep.CommonHeader{Version: 2, MessageType: pcep.MessageTypeOpen, MessageLength: pcep.CommonHeaderLength}
				_, err := client.Write(header.Serialize())
				require.NoError(t, err, "failed to write header")
				return false
			},
		},
		{
			name: "unexpected message type",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeKeepalive, MessageLength: pcep.CommonHeaderLength}
				_, err := client.Write(header.Serialize())
				require.NoError(t, err, "failed to write header")
				return false
			},
		},
		{
			name: "MessageLength below CommonHeaderLength",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeOpen, MessageLength: pcep.CommonHeaderLength - 1}
				_, err := client.Write(header.Serialize())
				require.NoError(t, err, "failed to write header")
				return false
			},
		},
		{
			name: "connection closed before the Open object body is read",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeOpen, MessageLength: pcep.CommonHeaderLength + 10}
				_, err := client.Write(header.Serialize())
				require.NoError(t, err, "failed to write header")
				require.NoError(t, client.Close(), "failed to close client connection")
				return true
			},
		},
		{
			name: "Open object has the wrong ObjectClass",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				body := pcep.NewCommonObjectHeader(pcep.ObjectClassClose, pcep.ObjectTypeOpenOpen, pcep.CommonHeaderLength).Serialize()
				header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeOpen, MessageLength: pcep.CommonHeaderLength + uint16(len(body))}
				_, err := client.Write(append(header.Serialize(), body...))
				require.NoError(t, err, "failed to write message")
				return false
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTCPConnPair(t)
			t.Cleanup(func() {
				assert.NoError(t, server.Close(), "failed to close server connection")
			})

			clientClosed := tc.setup(t, client)
			if !clientClosed {
				t.Cleanup(func() {
					assert.NoError(t, client.Close(), "failed to close client connection")
				})
			}

			ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
			assert.Error(t, ss.ReceiveOpen())
		})
	}
}

func TestReceivePCEPMessage_ProcessesMessagesThenReturnsOnClose(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(9, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	keepaliveMessage := pcep.NewKeepaliveMessage()
	writeMessage(t, client, keepaliveMessage)

	sr := newTestStateReport(t, 5, 0)
	writeStateReportMessage(t, client, sr)

	pcerrMessage := pcep.NewPCErrMessage(1, 1, nil)
	pcerrMessage.SRPs = []*pcep.SrpObject{{SrpID: 9}}
	writeMessage(t, client, pcerrMessage)

	// An unrecognized MessageType is logged and skipped rather than treated as an error.
	writeRawPCEPMessage(t, client, pcep.MessageType(0x63), nil)

	closeMessage := pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided)
	writeMessage(t, client, closeMessage)

	require.NoError(t, ss.ReceivePCEPMessage())

	policy, found := ss.SearchSRPolicy(5)
	require.True(t, found, "unsolicited PCRpt was not registered")
	assert.Len(t, policy.SegmentList, 2)

	_, ok := ss.takeSRPolicyIntent(9)
	assert.False(t, ok, "PCErr referencing SRP-ID 9 must forget its intent")
}

// A stalled peer must not block the session goroutine beyond the DeadTimer.
func TestReadCommonHeader_TimesOutOnStalledPeer(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.keepAlive = 1 // shrinks the dead timer to a few seconds so the test stays fast

	_, err := client.Write([]byte{0x20, 0x01}) // half of a 4-byte common header
	require.NoError(t, err)

	start := time.Now()
	_, _, err = ss.readCommonHeader()
	elapsed := time.Since(start)

	require.Error(t, err, "a stalled peer must not block the read indefinitely")
	assert.Less(t, elapsed, 10*time.Second, "read should time out near the negotiated dead timer, not hang")
}

func TestReadDeadline_MatchesAdvertisedDeadTimer(t *testing.T) {
	tests := []struct {
		keepAlive uint8
		want      time.Duration
	}{
		{0, 0},
		{30, 120 * time.Second},
		{65, time.Duration(math.MaxUint8) * time.Second},
	}
	for _, tt := range tests {
		ss := &Session{keepAlive: tt.keepAlive}
		assert.Equal(t, tt.want, ss.readDeadline())
	}
}

func TestReadFullWithDeadline_SetReadDeadlineErrorIsPropagated(t *testing.T) {
	wantErr := errors.New("use of closed network connection")
	conn := &fakeConn{r: bytes.NewReader(nil), setReadDeadlineErr: wantErr}

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	err := ss.readFullWithDeadline(make([]byte, pcep.CommonHeaderLength), ss.messageDeadline())
	assert.ErrorIs(t, err, wantErr, "readFullWithDeadline must surface a failure to set the read deadline instead of attempting the read")
}

func TestReceivePCEPMessage_StateReportHandlingErrorIsLoggedNotFatal(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	sr := newTestStateReport(t, 7, 0)
	byteSrp, err := sr.SrpObject.Serialize()
	require.NoError(t, err, "failed to serialize SrpObject")
	byteLsp, err := sr.LSPObject.Serialize()
	require.NoError(t, err, "failed to serialize LSPObject")
	body := append(byteSrp, byteLsp...) // no ERO object
	writeRawPCEPMessage(t, client, pcep.MessageTypeReport, body)

	closeMessage := pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided)
	writeMessage(t, client, closeMessage)

	require.NoError(t, ss.ReceivePCEPMessage(), "a per-report handling error must not abort the receive loop")

	_, found := ss.SearchSRPolicy(7)
	assert.False(t, found, "a report without a segment list must not be registered")
}

func TestReceivePCEPMessage_Errors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, client *net.TCPConn) (clientClosed bool)
	}{
		{
			name: "connection closed before a header is read",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				require.NoError(t, client.Close(), "failed to close client connection")
				return true
			},
		},
		{
			name: "PCRpt with a malformed StateReport object",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				body := pcep.NewCommonObjectHeader(pcep.ObjectClassLSP, pcep.ObjectTypeLSPLSP, pcep.CommonHeaderLength).Serialize()
				writeRawPCEPMessage(t, client, pcep.MessageTypeReport, body)
				return false
			},
		},
		{
			name: "connection closed before a PCRpt body is read",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeReport, MessageLength: pcep.CommonHeaderLength + 8}
				_, err := client.Write(header.Serialize())
				require.NoError(t, err, "failed to write header")
				require.NoError(t, client.Close(), "failed to close client connection")
				return true
			},
		},
		{
			name: "PCErr message with no PCEP-ERROR object",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				writeRawPCEPMessage(t, client, pcep.MessageTypeError, nil)
				return false
			},
		},
		{
			name: "connection closed before a PCErr body is read",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeError, MessageLength: pcep.CommonHeaderLength + 8}
				_, err := client.Write(header.Serialize())
				require.NoError(t, err, "failed to write header")
				require.NoError(t, client.Close(), "failed to close client connection")
				return true
			},
		},
		{
			name: "Close message body too short to decode",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				writeRawPCEPMessage(t, client, pcep.MessageTypeClose, nil)
				return false
			},
		},
		{
			name: "connection closed before a Close body is read",
			setup: func(t *testing.T, client *net.TCPConn) bool {
				header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeClose, MessageLength: pcep.CommonHeaderLength + 8}
				_, err := client.Write(header.Serialize())
				require.NoError(t, err, "failed to write header")
				require.NoError(t, client.Close(), "failed to close client connection")
				return true
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTCPConnPair(t)
			t.Cleanup(func() {
				assert.NoError(t, server.Close(), "failed to close server connection")
			})

			clientClosed := tc.setup(t, client)
			if !clientClosed {
				t.Cleanup(func() {
					assert.NoError(t, client.Close(), "failed to close client connection")
				})
			}

			ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
			assert.Error(t, ss.ReceivePCEPMessage())
		})
	}
}

func TestReceivePCEPMessage_ShortMessageLengthIsRejected(t *testing.T) {
	for length := uint16(0); length < pcep.CommonHeaderLength; length++ {
		t.Run(fmt.Sprintf("MessageLength=%d", length), func(t *testing.T) {
			server, client := newTCPConnPair(t)
			t.Cleanup(func() {
				assert.NoError(t, server.Close(), "failed to close server connection")
			})
			t.Cleanup(func() {
				assert.NoError(t, client.Close(), "failed to close client connection")
			})

			header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeKeepalive, MessageLength: length}
			_, err := client.Write(header.Serialize())
			require.NoError(t, err, "failed to write header")

			ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
			assert.Error(t, ss.ReceivePCEPMessage())
		})
	}
}

// RFC 5440 §6.3: a Keepalive message consists of the common header only.
func TestReceivePCEPMessage_KeepaliveWithBodyIsRejected(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeKeepalive, MessageLength: pcep.CommonHeaderLength + 4}
	_, err := client.Write(append(header.Serialize(), 0x00, 0x00, 0x00, 0x00))
	require.NoError(t, err, "failed to write keepalive with body")

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	assert.Error(t, ss.ReceivePCEPMessage())
}

func TestReceivePCEPMessage_UnsupportedMessageBodyIsConsumed(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	// Use a valid Close message as the body to catch framing bugs: without consuming
	// the body, it would be parsed as the next message and stop before the PCRpt.
	trap, err := pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided).Serialize()
	require.NoError(t, err, "failed to serialize the message body")
	writeRawPCEPMessage(t, client, pcep.MessageType(0x63), trap)

	writeStateReportMessage(t, client, newTestStateReport(t, 5, 0))
	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))

	require.NoError(t, ss.ReceivePCEPMessage())

	_, found := ss.SearchSRPolicy(5)
	assert.True(t, found, "the PCRpt following an unsupported message was not processed")
}

func TestHandleUnsupportedMessage_ReadBodyErrorIsReturned(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageType(0x63), MessageLength: pcep.CommonHeaderLength + 4}
	assert.Error(t, ss.handleUnsupportedMessage(header, ss.messageDeadline()), "a truncated unsupported message body must be reported")
}

func TestHandleUnsupportedMessage_SendPCErrFailureIsLoggedNotFatal(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageType(0x63), MessageLength: pcep.CommonHeaderLength}
	err := ss.handleUnsupportedMessage(header, ss.messageDeadline())
	assert.NoError(t, err, "a single unsupported message must not close the session even if the PCErr reply fails to send")
}

func TestHandleUnsupportedMessage_SendCloseFailureStillReturnsError(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	ss.maxUnknownMsgs = 0

	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageType(0x63), MessageLength: pcep.CommonHeaderLength}
	err := ss.handleUnsupportedMessage(header, ss.messageDeadline())
	assert.ErrorContains(t, err, "too many unrecognized PCEP messages",
		"the too-many-unknown-messages error must surface even when sending the Close message fails")
}

// RFC 5440 §6.9: close the session when unrecognized messages exceed the allowed rate.
func TestReceivePCEPMessage_TooManyUnknownMessagesClosesSession(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	for i := uint32(0); i <= ss.maxUnknownMsgs; i++ {
		writeRawPCEPMessage(t, client, pcep.MessageType(0x63), nil)
	}

	err := ss.ReceivePCEPMessage()
	require.Error(t, err, "exceeding maxUnknownMsgs must terminate the receive loop")

	for i := uint32(0); i <= ss.maxUnknownMsgs; i++ {
		pcerrMessage := readPCErrMessage(t, client)
		require.Len(t, pcerrMessage.Errors, 1)
		assert.EqualValues(t, 2, pcerrMessage.Errors[0].ErrorType, "expected Error-Type 2 (Capability not supported)")
	}

	closeMessage := readCloseMessage(t, client)
	assert.Equal(t, pcep.CloseReasonTooManyUnrecognizedPCEPMessages, closeMessage.CloseObject.Reason)
}

func TestReceivePCEPMessage_FewUnknownMessagesToleratedWithinWindow(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	for i := uint32(0); i < ss.maxUnknownMsgs; i++ {
		writeRawPCEPMessage(t, client, pcep.MessageType(0x63), nil)
	}
	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))

	require.NoError(t, ss.ReceivePCEPMessage(), "unrecognized messages within the threshold must not close the session")

	for i := uint32(0); i < ss.maxUnknownMsgs; i++ {
		readPCErrMessage(t, client)
	}
}

func readPCErrMessage(t *testing.T, r io.Reader) *pcep.PCErrMessage {
	t.Helper()

	headerBytes := make([]byte, pcep.CommonHeaderLength)
	_, err := io.ReadFull(r, headerBytes)
	require.NoError(t, err, "failed to read common header")

	header := &pcep.CommonHeader{}
	require.NoError(t, header.DecodeFromBytes(headerBytes), "failed to decode common header")
	require.Equal(t, pcep.MessageTypeError, header.MessageType, "expected a PCErr message")

	body := make([]byte, header.MessageLength-pcep.CommonHeaderLength)
	_, err = io.ReadFull(r, body)
	require.NoError(t, err, "failed to read PCErr message body")

	pcerrMessage := &pcep.PCErrMessage{}
	require.NoError(t, pcerrMessage.DecodeFromBytes(body), "failed to decode PCErr message")
	return pcerrMessage
}

func readCloseMessage(t *testing.T, r io.Reader) *pcep.CloseMessage {
	t.Helper()

	headerBytes := make([]byte, pcep.CommonHeaderLength)
	_, err := io.ReadFull(r, headerBytes)
	require.NoError(t, err, "failed to read common header")

	header := &pcep.CommonHeader{}
	require.NoError(t, header.DecodeFromBytes(headerBytes), "failed to decode common header")
	require.Equal(t, pcep.MessageTypeClose, header.MessageType, "expected a Close message")

	body := make([]byte, header.MessageLength-pcep.CommonHeaderLength)
	_, err = io.ReadFull(r, body)
	require.NoError(t, err, "failed to read close message body")

	closeMessage := &pcep.CloseMessage{}
	require.NoError(t, closeMessage.DecodeFromBytes(body), "failed to decode close message")
	return closeMessage
}

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

// RFC 8231 §5.6: an LSP report with the S-Flag is part of state synchronization
// and is registered regardless of PLSP-ID or SRP-ID..
func TestHandleStateReport_Synchronization(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SFlag = true

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(1)
	require.True(t, found, "SR Policy reported during synchronization was not registered")
	assert.Equal(t, sr.LSPObject.Name, policy.Name)
}

func TestHandleStateReport_SynchronizationRegistrationFailure(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SFlag = true
	sr.EroObject = nil

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
}

// RFC 8231 §5.6: PLSP-ID 0 marks the end of state synchronization.
func TestHandleStateReport_FinishSynchronization(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	require.False(t, ss.IsSynced())

	sr := newTestStateReport(t, 0, 0)
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	assert.True(t, ss.IsSynced())
}

func TestHandleStateReport_StatefulPCERequestRegistrationFailure(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 3) // non-zero SRP-ID uses handleStatefulPCERequest
	sr.EroObject = nil

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	_, found := ss.SearchSRPolicy(1)
	assert.False(t, found)
}

func TestHandleStateReport_ReportedSRPolicyRegistrationFailure(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)
	sr.EroObject = nil // no TED available and no explicit path reported

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
}

func TestComputePathFromTED_NoTED(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	_, err := ss.computePathFromTED(*sr)
	assert.Error(t, err)
}

func TestHandleSRPolicyWithPLSPID_ExtractRouterIDsFails(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)
	sr := newTestStateReport(t, 1, 0) // src/dst addresses are absent from the TED

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
}

func TestComputePathFromTED_CSPFFailsWithoutNodeSID(t *testing.T) {
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

	_, err := ss.computePathFromTED(*sr)
	assert.Error(t, err, "CSPF must fail when the headend advertises no Prefix-SID or SRv6 SID")
}

// newLinkedSRMPLSNodes builds two SR-MPLS nodes connected by a link with the given TE metric.
// Each node has a Prefix-SID bound to its address.
func newLinkedSRMPLSNodes(srcAddr, dstAddr netip.Addr, metric uint32) (src, dst *table.LsNode) {
	src = table.NewLsNode(65000, "PE1")
	srcPrefix := table.NewLsPrefix(src)
	srcPrefix.Prefix = netip.PrefixFrom(srcAddr, srcAddr.BitLen())
	srcPrefix.HasSidIndex = true
	srcPrefix.SidIndex = 1
	src.Prefixes = append(src.Prefixes, srcPrefix)
	src.SrgbBegin, src.SrgbEnd = 16000, 23999

	dst = table.NewLsNode(65000, "PE2")
	dstPrefix := table.NewLsPrefix(dst)
	dstPrefix.Prefix = netip.PrefixFrom(dstAddr, dstAddr.BitLen())
	dstPrefix.HasSidIndex = true
	dstPrefix.SidIndex = 2
	dst.Prefixes = append(dst.Prefixes, dstPrefix)
	dst.SrgbBegin, dst.SrgbEnd = 16000, 23999

	link := table.NewLsLink(src, dst)
	link.Metrics = []*table.Metric{table.NewMetric(table.TEMetric, metric)}
	src.AddLink(link)

	return src, dst
}

func newLinkedSRv6Nodes(srcAddr, dstAddr netip.Addr, metric uint32) (src, dst *table.LsNode) {
	src = table.NewLsNode(65000, "PE1-v6")
	srcPrefix := table.NewLsPrefix(src)
	srcPrefix.Prefix = netip.PrefixFrom(srcAddr, srcAddr.BitLen())
	src.Prefixes = append(src.Prefixes, srcPrefix)
	src.SRv6SIDs = []*table.LsSrv6SID{{Sids: []string{"2001:db8::1"}}}

	dst = table.NewLsNode(65000, "PE2-v6")
	dstPrefix := table.NewLsPrefix(dst)
	dstPrefix.Prefix = netip.PrefixFrom(dstAddr, dstAddr.BitLen())
	dst.Prefixes = append(dst.Prefixes, dstPrefix)
	dst.SRv6SIDs = []*table.LsSrv6SID{{Sids: []string{"fe80::2"}}}

	link := table.NewLsLink(src, dst)
	link.Metrics = []*table.Metric{table.NewMetric(table.TEMetric, metric)}
	src.AddLink(link)

	return src, dst
}

func TestHandleSRPolicyWithPLSPID_CreateEroFromSegmentListErrorIsPropagated(t *testing.T) {
	srcAddr := netip.MustParseAddr("10.1.0.1")
	dstAddr := netip.MustParseAddr("10.1.0.2")
	srcNode, dstNode := newLinkedSRv6Nodes(srcAddr, dstAddr, 10)
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{srcNode.RouterID: srcNode, dstNode.RouterID: dstNode}}

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = srcAddr
	sr.LSPObject.DstAddr = dstAddr

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	_, found := ss.SearchSRPolicy(1)
	assert.False(t, found, "SR Policy must not be registered when ERO construction fails")
}

func TestHandleSRPolicyWithPLSPID_ComputesPathFromTED(t *testing.T) {
	srcAddr := netip.MustParseAddr("10.0.0.1")
	dstAddr := netip.MustParseAddr("10.0.0.2")
	srcNode, dstNode := newLinkedSRMPLSNodes(srcAddr, dstAddr, 10)
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{srcNode.RouterID: srcNode, dstNode.RouterID: dstNode}}

	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = srcAddr
	sr.LSPObject.DstAddr = dstAddr

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(1)
	require.True(t, found)
	assert.Equal(t, []table.Segment{table.NewSegmentSRMPLS(16002)}, policy.SegmentList)

	require.NoError(t, readPCEPMessage(client), "expected a PCUpd to be sent for the newly computed policy")
}

// A self-destination produces an empty CSPF path, which SR Policy validation must reject.
func TestHandleSRPolicyWithPLSPID_EmptyComputedPathIsRejected(t *testing.T) {
	selfAddr := netip.MustParseAddr("10.0.0.9")
	node := table.NewLsNode(65000, "PE-self")
	prefix := table.NewLsPrefix(node)
	prefix.Prefix = netip.PrefixFrom(selfAddr, selfAddr.BitLen())
	prefix.HasSidIndex = true
	prefix.SidIndex = 1
	node.Prefixes = append(node.Prefixes, prefix)
	node.SrgbBegin, node.SrgbEnd = 16000, 23999
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node}}

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = selfAddr
	sr.LSPObject.DstAddr = selfAddr

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	_, found := ss.SearchSRPolicy(1)
	assert.False(t, found)
}

func TestHandleSRPolicyWithPLSPID_SendPCUpdateFailureIsPropagated(t *testing.T) {
	srcAddr := netip.MustParseAddr("10.0.0.1")
	dstAddr := netip.MustParseAddr("10.0.0.2")
	srcNode, dstNode := newLinkedSRMPLSNodes(srcAddr, dstAddr, 10)
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{srcNode.RouterID: srcNode, dstNode.RouterID: dstNode}}

	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})
	require.NoError(t, server.Close(), "failed to close server connection")

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = srcAddr
	sr.LSPObject.DstAddr = dstAddr

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	// The policy was registered before the PCUpd send failed.
	_, found := ss.SearchSRPolicy(1)
	assert.True(t, found)
}

func TestSelectMetricType(t *testing.T) {
	cases := []struct {
		name          string
		pccType       pcep.PccType
		hasMetric     bool
		metricObjType uint8
		want          table.MetricType
	}{
		{"T=1 (RFC5440) maps to IGP metric", pcep.RFCCompliant, true, 1, table.IGPMetric},
		{"T=2 (RFC5440) maps to TE metric", pcep.RFCCompliant, true, 2, table.TEMetric},
		{"T=3 (RFC5440 Hop Counts) maps to Hopcount metric", pcep.RFCCompliant, true, 3, table.HopcountMetric},
		{"T=4 (RFC5541 aggregate bandwidth) falls back to TE metric", pcep.RFCCompliant, true, 4, table.TEMetric},
		{"unrecognized T falls back to TE metric", pcep.RFCCompliant, true, 99, table.TEMetric},
		{"no METRIC object, RFC-compliant PCC defaults to TE", pcep.RFCCompliant, false, 0, table.TEMetric},
		{"no METRIC object, Cisco legacy PCC defaults to TE", pcep.CiscoLegacy, false, 0, table.TEMetric},
		{"no METRIC object, Juniper legacy PCC defaults to IGP", pcep.JuniperLegacy, false, 0, table.IGPMetric},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
			ss.pccType = tc.pccType
			sr := *newTestStateReport(t, 1, 0)
			if tc.hasMetric {
				sr.MetricObjects = []*pcep.MetricObject{{MetricType: tc.metricObjType}}
			}
			assert.Equal(t, tc.want, ss.selectMetricType(sr))
		})
	}
}

func TestResolveColorPreference_CiscoLegacy(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.pccType = pcep.CiscoLegacy

	sr := newTestStateReport(t, 1, 0)
	vio, err := pcep.NewVendorInformationObject(pcep.CiscoLegacy, 42, 7)
	require.NoError(t, err)
	sr.VendorInformationObject = vio

	color, preference := ss.resolveColorPreference(sr)
	assert.Equal(t, uint32(42), color)
	assert.Equal(t, uint32(7), preference)
}

func TestResolveColorPreference_AssociationColorTakesPrecedence(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.receivedPccCapabilities = []pcep.CapabilityInterface{&pcep.StatefulPCECapability{ColorCapability: true}}

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.TLVs = append(sr.LSPObject.TLVs, &pcep.Color{Color: 999})
	sr.AssociationObject.TLVs = append(sr.AssociationObject.TLVs,
		pcep.NewExtendedAssociationID(55, netip.Addr{}),
		&pcep.SRPolicyCandidatePathPreference{Preference: 33},
	)

	color, preference := ss.resolveColorPreference(sr)
	assert.Equal(t, uint32(55), color, "Association color must take precedence over the LSP color TLV")
	assert.Equal(t, uint32(33), preference)
}

func TestResolvePolicyState(t *testing.T) {
	cases := []struct {
		name  string
		oflag uint8
		want  table.PolicyState
	}{
		{"DOWN (RFC 8231 Table 2, O=0)", 0x00, table.PolicyDown},
		{"UP (RFC 8231 Table 2, O=1)", 0x01, table.PolicyUp},
		{"ACTIVE (RFC 8231 Table 2, O=2)", 0x02, table.PolicyActive},
		{"GOING-DOWN (RFC 8231 Table 2, O=3, unhandled)", 0x03, table.PolicyUnknown},
		{"GOING-UP (RFC 8231 Table 2, O=4, unhandled)", 0x04, table.PolicyUnknown},
		{"reserved value", 0x07, table.PolicyUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolvePolicyState(tc.oflag))
		})
	}
}

func TestValidateSegmentList_NilEroObject(t *testing.T) {
	sr := *newTestStateReport(t, 1, 0)
	sr.EroObject = nil

	_, err := validateSegmentList(sr)
	assert.Error(t, err)
}

func TestValidateSegmentList_EmptySegmentList(t *testing.T) {
	sr := *newTestStateReport(t, 1, 0)
	sr.EroObject.EroSubobjects = nil

	_, err := validateSegmentList(sr)
	assert.Error(t, err)
}

func TestUpdateOrCreatePolicy_SrcAddrFallsBackToAssociationSrc(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = netip.Addr{}
	sr.AssociationObject.AssocSrc = netip.MustParseAddr("192.0.2.9")

	require.NoError(t, ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 0, 0, table.PolicyUp))

	policy, found := ss.SearchSRPolicy(1)
	require.True(t, found)
	assert.Equal(t, netip.MustParseAddr("192.0.2.9"), policy.SrcAddr)
}

func TestUpdateOrCreatePolicy_InvalidSrcAddr(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = netip.Addr{}

	err := ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 0, 0, table.PolicyUp)
	assert.Error(t, err)
}

func TestUpdateOrCreatePolicy_DstAddrFallsBackToAssociationEndpoint(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.DstAddr = netip.Addr{}
	sr.AssociationObject.TLVs = append(sr.AssociationObject.TLVs,
		pcep.NewExtendedAssociationID(0, netip.MustParseAddr("192.0.2.20")))

	require.NoError(t, ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 0, 0, table.PolicyUp))

	policy, found := ss.SearchSRPolicy(1)
	require.True(t, found)
	assert.Equal(t, netip.MustParseAddr("192.0.2.20"), policy.DstAddr)
}

func TestUpdateOrCreatePolicy_InvalidDstAddr(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.DstAddr = netip.Addr{}

	err := ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 0, 0, table.PolicyUp)
	assert.Error(t, err)
}

// RFC 8231 §7.3: a stale LSP-ID must not overwrite newer state.
func TestUpdateOrCreatePolicy_StaleLSPIDIsIgnored(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.LSPID = 5
	require.NoError(t, ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 10, 20, table.PolicyUp))

	stale := sr
	stale.LSPObject.LSPID = 3
	require.NoError(t, ss.updateOrCreatePolicy(stale, stale.EroObject.ToSegmentList(), 999, 999, table.PolicyDown))

	policy, found := ss.SearchSRPolicy(1)
	require.True(t, found)
	assert.Equal(t, uint16(5), policy.LSPID, "a stale LSP-ID report must not overwrite newer state")
	assert.Equal(t, uint32(10), policy.Color)
	assert.Equal(t, table.PolicyUp, policy.State)
}

// RFC 9603 §4.3.1: F=1 indicates that the NAI is absent.
func TestCreateEroFromSegmentList_SRv6(t *testing.T) {
	seg := table.NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::1"))

	ero, err := createEroFromSegmentList([]table.Segment{seg})
	require.NoError(t, err)

	require.Len(t, ero.EroSubobjects, 1)
	srv6Subobj, ok := ero.EroSubobjects[0].(*pcep.SRv6EroSubobject)
	require.Truef(t, ok, "subobject type: got %T, want *pcep.SRv6EroSubobject", ero.EroSubobjects[0])
	assert.Equal(t, seg, srv6Subobj.ToSegment())
	assert.True(t, srv6Subobj.FFlag, "F-Flag must be set when the segment has no NAI")
	assert.Equal(t, pcep.NAITypeSRv6Absent, srv6Subobj.NAIType)
}

func TestCreateEroFromSegmentList_InvalidSegmentReturnsError(t *testing.T) {
	seg := table.NewSegmentSRMPLS(16002)
	seg.RemoteAddr = netip.MustParseAddr("10.255.0.2") // RemoteAddr without LocalAddr is invalid.

	_, err := createEroFromSegmentList([]table.Segment{seg})
	require.Error(t, err)
}

func TestCreateEroFromSegmentList_SRv6InvalidSegmentReturnsError(t *testing.T) {
	seg := table.NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::1"))
	seg.LocalAddr = netip.MustParseAddr("fe80::1") // link-local adjacency NAI is unsupported.
	seg.RemoteAddr = netip.MustParseAddr("fe80::2")

	_, err := createEroFromSegmentList([]table.Segment{seg})
	require.Error(t, err)
}

type failingMessage struct{}

func (failingMessage) Serialize() ([]uint8, error) {
	return nil, fmt.Errorf("serialize failed")
}

func TestSendPCEPMessage_SerializeErrorIsPropagated(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	assert.Error(t, ss.sendPCEPMessage(failingMessage{}))
}

type unknownSegment struct{}

func (unknownSegment) SidString() string { return "unknown" }

func TestSendPCInitiate_InvalidSegmentTypeIsRejected(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	wantSRPID := ss.srpIDHead
	srPolicy := table.SRPolicy{
		Name:        "bad-segment",
		SrcAddr:     netip.MustParseAddr("10.255.0.1"),
		DstAddr:     netip.MustParseAddr("10.255.0.2"),
		SegmentList: []table.Segment{unknownSegment{}},
	}

	assert.Error(t, ss.SendPCInitiate(srPolicy, false))

	_, ok := ss.takeSRPolicyIntent(wantSRPID)
	assert.False(t, ok, "intent must be forgotten when message construction fails")
}

func TestSendPCUpdate_InvalidSegmentTypeIsRejected(t *testing.T) {
	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	wantSRPID := ss.srpIDHead
	srPolicy := table.SRPolicy{
		Name:        "bad-segment",
		SegmentList: []table.Segment{unknownSegment{}},
	}

	assert.Error(t, ss.SendPCUpdate(srPolicy))

	_, ok := ss.takeSRPolicyIntent(wantSRPID)
	assert.False(t, ok, "intent must be forgotten when message construction fails")
}

func TestRequestAllSRPolicyDeleted(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(1, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	require.NoError(t, ss.RequestAllSRPolicyDeleted())
	require.NoError(t, readPCEPMessage(client))
}

func TestSelectMetricType_AlwaysUsableForCSPF(t *testing.T) {
	for _, metricType := range []uint8{0, 1, 2, 3, 255} {
		ss := &Session{logger: zap.NewNop()}
		sr := pcep.StateReport{MetricObjects: []*pcep.MetricObject{{MetricType: metricType}}}
		got := ss.selectMetricType(sr)
		assert.Truef(t, got.IsValid() && got != table.UnspecifiedMetric,
			"PCEP metric type %d mapped to a metric CSPF rejects: %v", metricType, got)
	}
	for _, pccType := range []pcep.PccType{pcep.CiscoLegacy, pcep.JuniperLegacy, pcep.RFCCompliant} {
		ss := &Session{logger: zap.NewNop(), pccType: pccType}
		got := ss.selectMetricType(pcep.StateReport{})
		assert.Truef(t, got.IsValid() && got != table.UnspecifiedMetric,
			"pccType %v with no METRIC object mapped to a metric CSPF rejects: %v", pccType, got)
	}
}
