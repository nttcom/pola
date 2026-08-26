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
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

// testLocalOpen returns the default local Open parameters for tests.
func testLocalOpen(sessionID uint8) OpenParams {
	return OpenParams{
		SessionID: sessionID,
		Keepalive: defaultLocalKeepalive,
		DeadTimer: pcep.DeadTimerFor(defaultLocalKeepalive),
	}
}

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
	written            [][]byte // raw bytes passed to each Write call, in order
	failAfter          int      // number of successful writes before writeErr; ignored if writeErr is nil
	writeErr           error
	setReadDeadlineErr error
	closeErr           error
}

func (c *fakeConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCount++
	c.written = append(c.written, append([]byte{}, p...))
	if c.writeErr != nil && c.writeCount > c.failAfter {
		return 0, c.writeErr
	}
	return len(p), nil
}

// writes returns a snapshot of the bytes passed to each Write call, in order.
func (c *fakeConn) writes() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte{}, c.written...)
}

func (c *fakeConn) Close() error                       { return c.closeErr }
func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *fakeConn) SetReadDeadline(_ time.Time) error  { return c.setReadDeadlineErr }

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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, sr.LSPObject.Name, policy.Name)
	assert.Len(t, policy.SegmentList, 2)
}

func TestSRPolicies_SnapshotSegmentListIsIndependent(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 7)

	ss.rememberSRPolicyIntent(7, table.PolicyTypeDynamic, table.TEMetric)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, table.PolicyTypeDynamic, policy.Type)
	assert.Equal(t, table.TEMetric, policy.Metric)
}

func TestSRPolicyIntent_AttachedOnUpdateBySRPID(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	require.True(t, found, "SR Policy reported by the PCC was not registered")
	assert.Equal(t, table.PolicyType(""), policy.Type, "policy type should be unset")
	assert.Equal(t, table.UnspecifiedMetric, policy.Metric)
}

func TestSRPolicyIntent_IndependentPerSRPID(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.syncState = lspDBSyncFinished
	wantSRPID := ss.srpIDHead

	// Close the PCEP-side connection so the send inside sendSRPolicyRequest fails.
	require.NoError(t, server.Close(), "failed to close server connection")

	pce := &Server{sessionList: []*Session{ss}}
	apiServer := &APIServer{pce: pce, logger: zap.NewNop()}

	dstAddr := netip.MustParseAddr("10.255.0.2")
	req := &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			PeerAddr:   ss.peerAddr.AsSlice(),
			DstAddr:    dstAddr.AsSlice(),
			Color:      100,
			PolicyName: "test-policy",
			Type:       pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
		},
		DisablePathCompute: true,
	}

	err := sendSRPolicyRequest(apiServer, req, resolvedPath{SrcAddr: netip.MustParseAddr("10.255.0.1"), DstAddr: dstAddr, Metric: table.UnspecifiedMetric}, true)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	const goroutines = 20
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for i := range goroutines {
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
		require.NoError(t, err)
	}

	ss.srPolicyIntentsMu.Lock()
	gotIntents := len(ss.srPolicyIntents)
	ss.srPolicyIntentsMu.Unlock()
	assert.Equal(t, goroutines, gotIntents, "SRP-IDs must not collide")
	assert.Equal(t, uint32(1+goroutines), ss.srpIDHead)
}

func TestAllocateSRPID_SkipsReservedValues(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	sr.LSPObject.RFlag = true
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	_, found := ss.SearchSRPolicy(sr.LSPObject.PlspID)
	assert.False(t, found, "SR Policy is still registered after being reported as removed")
}

func TestReceiveOpenDoesNotOverwriteAdvertisedCapabilities(t *testing.T) {
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
	openMessage := pcep.NewOpenMessage(1, 30, pcep.DeadTimerFor(30), pccCaps)
	byteOpenMessage, err := openMessage.Serialize()
	require.NoError(t, err, "failed to serialize open message")
	_, err = client.Write(byteOpenMessage)
	require.NoError(t, err, "failed to write open message")

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	require.NoError(t, ss.ReceiveOpen())

	assert.Equal(t, pccCaps, ss.receivedPccCapabilities)
	assert.Equal(t, pccCaps, ss.ReceivedCapabilities())
	assert.Equal(t, pcep.RFCCompliant, ss.PccType())
	assert.Equal(t, pcep.DefaultCapabilities(), ss.advertisedCapabilities)
	assert.Equal(t, pcep.DefaultCapabilities(), ss.AdvertisedCapabilities())

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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeExplicit, table.UnspecifiedMetric)

	_, ok := ss.takeSRPolicyIntent(1)
	require.True(t, ok, "expected intent 1 to be present before consuming it")

	ss.sweepExpiredSRPolicyIntents()

	_, ok = ss.takeSRPolicyIntent(2)
	assert.True(t, ok, "sweep must not remove an unrelated intent still within its TTL")
}

func TestIntentSweep_RunsInBackgroundAndStopsCleanly(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.rememberSRPolicyIntent(0, table.PolicyTypeDynamic, table.TEMetric)
	assert.False(t, ss.srPolicyIntentExists(0))
}

func TestStartIntentSweep_Idempotent(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.startIntentSweep()
	firstStop := ss.sweepStop
	ss.startIntentSweep()
	defer ss.stopIntentSweep()

	assert.Equal(t, firstStop, ss.sweepStop, "startIntentSweep must not replace an already-running sweeper's stop channel")
}

func TestStopIntentSweep_NoopWhenNeverStarted(_ *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.stopIntentSweep()
}

func TestIntentSweep_StopsCleanly(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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

func TestIntentSweep_ConcurrentWithIntentConsumption(_ *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.srpIDMax = 3 // valid range is [1, 2]; 0 and 3 are reserved.
	ss.rememberSRPolicyIntent(1, table.PolicyTypeDynamic, table.TEMetric)
	ss.rememberSRPolicyIntent(2, table.PolicyTypeDynamic, table.TEMetric)

	_, err := ss.allocateSRPID(table.PolicyTypeDynamic, table.TEMetric)
	assert.Error(t, err, "expected an error when every non-reserved SRP-ID is in use")
}

func TestSendPCInitiate_ErrorsWhenSRPIDExhausted(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
		send: func(ss *Session, _ int) error { return ss.SendKeepalive() },
	},
	{
		name: "SendOpen",
		send: func(ss *Session, _ int) error { return ss.SendOpen() },
	},
	{
		name: "SendClose",
		send: func(ss *Session, _ int) error {
			return ss.SendClose(pcep.CloseReasonNoExplanationProvided)
		},
	},
	{
		name: "SendPCUpdate",
		send: func(ss *Session, _ int) error {
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

	for i := range goroutines {
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
		for range wantCount {
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	addrIndex := ted.AddressRouterIDIndex()

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	srcRouterID, dstRouterID, err := ss.extractSrcDstRouterIDs(*sr)
	require.NoError(t, err, "extractSrcDstRouterIDs failed")
	assert.Equal(t, "src-router", srcRouterID)
	assert.Equal(t, "10.255.0.2", dstRouterID)
}

func TestExtractSrcDstRouterIDs_AddressNotFound(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	_, _, err := ss.extractSrcDstRouterIDs(*sr)
	assert.Error(t, err, "expected an error when neither address is present in the TED")
}

func TestExtractSrcDstRouterIDs_InvalidAddresses(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)
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

func readOpenMessage(t *testing.T, r io.Reader) *pcep.OpenMessage {
	t.Helper()

	headerBytes := make([]byte, pcep.CommonHeaderLength)
	_, err := io.ReadFull(r, headerBytes)
	require.NoError(t, err, "failed to read common header")

	var header pcep.CommonHeader
	require.NoError(t, header.DecodeFromBytes(headerBytes))
	require.Equal(t, pcep.MessageTypeOpen, header.MessageType)

	body := make([]byte, int(header.MessageLength)-int(pcep.CommonHeaderLength))
	_, err = io.ReadFull(r, body)
	require.NoError(t, err, "failed to read message body")

	openMessage := &pcep.OpenMessage{}
	require.NoError(t, openMessage.DecodeFromBytes(body))
	return openMessage
}

func TestSendOpen_StoresWireValuesAsLocalOpen(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})

	ss := NewSession(testLocalOpen(7), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	_, ok := ss.LocalOpen()
	require.False(t, ok, "nothing is advertised before the Open message is sent")

	require.NoError(t, ss.SendOpen())

	sent := readOpenMessage(t, client)
	localOpen, ok := ss.LocalOpen()
	require.True(t, ok)
	assert.Equal(t, sent.OpenObject.Sid, localOpen.SessionID, "local SID must match the value actually sent")
	assert.Equal(t, sent.OpenObject.Keepalive, localOpen.Keepalive, "local Keepalive must match the value actually sent")
	assert.Equal(t, sent.OpenObject.Deadtime, localOpen.DeadTimer, "local DeadTimer must match the value actually sent")
	assert.Equal(t, uint8(7), localOpen.SessionID)
	assert.Equal(t, defaultLocalKeepalive, localOpen.Keepalive)
	assert.Equal(t, pcep.DeadTimerFor(defaultLocalKeepalive), localOpen.DeadTimer)
}

func TestSendOpen_AdvertisesConfiguredTimers(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	t.Cleanup(func() { assert.NoError(t, server.Close()) })

	// RFC 5440 §8.1: the local Keepalive and DeadTimer are configurable.
	local := OpenParams{SessionID: 1, Keepalive: 5, DeadTimer: 60}
	ss := NewSession(local, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	require.NoError(t, ss.SendOpen())

	sent := readOpenMessage(t, client)
	assert.Equal(t, uint8(5), sent.OpenObject.Keepalive)
	assert.Equal(t, uint8(60), sent.OpenObject.Deadtime)
}

func TestSendOpen_AdvertisesFullCapabilitySetOnTheWire(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	t.Cleanup(func() { assert.NoError(t, server.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	require.NoError(t, ss.SendOpen())

	sent := readOpenMessage(t, client)
	assert.Equal(t, pcep.DefaultCapabilities(), sent.OpenObject.Caps,
		"the wire-level Open must carry Pola's complete capability set, not a partial default")
	assert.Equal(t, pcep.DefaultCapabilities(), ss.AdvertisedCapabilities(),
		"AdvertisedCapabilities must match what was actually sent on the wire")
}

func TestSendOpen_ErrorPropagatesFromSendFailure(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	require.Error(t, ss.SendOpen())
}

func TestReceiveOpen_StoresPccOpenParams(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})

	writeMessage(t, client, pcep.NewOpenMessage(42, 10, 40, nil))

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	_, ok := ss.PccOpen()
	require.False(t, ok, "nothing is known before the PCC's Open message arrives")

	require.NoError(t, ss.ReceiveOpen())

	pccOpen, ok := ss.PccOpen()
	require.True(t, ok)
	assert.Equal(t, OpenParams{SessionID: 42, Keepalive: 10, DeadTimer: 40}, pccOpen)
}

func TestReceiveOpen_StoresSessionIDZeroAsAdvertised(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	t.Cleanup(func() { assert.NoError(t, server.Close()) })

	writeMessage(t, client, pcep.NewOpenMessage(0, 30, 120, nil))

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	require.NoError(t, ss.ReceiveOpen())

	pccOpen, ok := ss.PccOpen()
	require.True(t, ok, "a SID of 0 must be recorded, not treated as absent")
	assert.Zero(t, pccOpen.SessionID)
}

func TestAcceptableOpen(t *testing.T) {
	tests := []struct {
		name    string
		session *Session
		pccOpen OpenParams
		want    bool
	}{
		{
			name:    "range disabled accepts any nonconflicting keepalive",
			session: &Session{},
			pccOpen: OpenParams{Keepalive: 250, DeadTimer: 255},
			want:    true,
		},
		{
			name:    "deadtimer shorter than keepalive is never acceptable",
			session: &Session{},
			pccOpen: OpenParams{Keepalive: 30, DeadTimer: 10},
			want:    false,
		},
		{
			name:    "zero keepalive requires zero deadtimer per RFC",
			session: &Session{},
			pccOpen: OpenParams{Keepalive: 0, DeadTimer: 1},
			want:    false,
		},
		{
			name:    "zero keepalive with zero deadtimer is acceptable",
			session: &Session{},
			pccOpen: OpenParams{Keepalive: 0, DeadTimer: 0},
			want:    true,
		},
		{
			name:    "zero deadtimer is exempt from the ratio check",
			session: &Session{},
			pccOpen: OpenParams{Keepalive: 30, DeadTimer: 0},
			want:    true,
		},
		{
			name:    "below the configured minimum is rejected",
			session: &Session{keepaliveRangeEnabled: true, minKeepalive: 10, maxKeepalive: 60},
			pccOpen: OpenParams{Keepalive: 5, DeadTimer: 20},
			want:    false,
		},
		{
			name:    "at the configured minimum is accepted",
			session: &Session{keepaliveRangeEnabled: true, minKeepalive: 10, maxKeepalive: 60},
			pccOpen: OpenParams{Keepalive: 10, DeadTimer: 40},
			want:    true,
		},
		{
			name:    "at the configured maximum is accepted",
			session: &Session{keepaliveRangeEnabled: true, minKeepalive: 10, maxKeepalive: 60},
			pccOpen: OpenParams{Keepalive: 60, DeadTimer: 240},
			want:    true,
		},
		{
			name:    "above the configured maximum is rejected",
			session: &Session{keepaliveRangeEnabled: true, minKeepalive: 10, maxKeepalive: 60},
			pccOpen: OpenParams{Keepalive: 61, DeadTimer: 244},
			want:    false,
		},
		{
			name:    "zero keepalive outside a strictly positive range is rejected",
			session: &Session{keepaliveRangeEnabled: true, minKeepalive: 10, maxKeepalive: 60},
			pccOpen: OpenParams{Keepalive: 0, DeadTimer: 0},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.session.acceptableOpen(tt.pccOpen))
		})
	}
}

func TestProposedTimers(t *testing.T) {
	tests := []struct {
		name          string
		session       *Session
		pccOpen       OpenParams
		wantKeepalive uint8
		wantDeadTimer uint8
	}{
		{
			name:          "range disabled keeps the peer's keepalive and fixes only the ratio",
			session:       &Session{},
			pccOpen:       OpenParams{Keepalive: 30, DeadTimer: 10},
			wantKeepalive: 30,
			wantDeadTimer: 120,
		},
		{
			name:          "below range clamps up to the minimum",
			session:       &Session{keepaliveRangeEnabled: true, minKeepalive: 10, maxKeepalive: 60},
			pccOpen:       OpenParams{Keepalive: 5, DeadTimer: 20},
			wantKeepalive: 10,
			wantDeadTimer: 40,
		},
		{
			name:          "above range clamps down to the maximum",
			session:       &Session{keepaliveRangeEnabled: true, minKeepalive: 10, maxKeepalive: 60},
			pccOpen:       OpenParams{Keepalive: 200, DeadTimer: 255},
			wantKeepalive: 60,
			wantDeadTimer: 240,
		},
		{
			name:          "high keepalive has deadtimer disabled when capped at 255",
			session:       &Session{},
			pccOpen:       OpenParams{Keepalive: 255, DeadTimer: 255},
			wantKeepalive: 255,
			wantDeadTimer: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keepalive, deadTimer := tt.session.proposedTimers(tt.pccOpen)
			assert.Equal(t, tt.wantKeepalive, keepalive)
			assert.Equal(t, tt.wantDeadTimer, deadTimer)
		})
	}
}

func TestEffectiveKeepalive(t *testing.T) {
	tests := []struct {
		name           string
		localKeepalive uint8
		localDeadTimer uint8
		want           uint8
	}{
		{"own dead timer disabled keeps the advertised keepalive", 30, 0, 30},
		{"keepalive of zero stays zero", 0, 0, 0},
		{"keepalive of zero is never overridden by a dead timer", 0, 40, 0},
		{"a short own dead timer shortens the interval", 30, 8, 2},
		{"a very short own dead timer floors at one second", 30, 2, 1},
		{"a generous own dead timer keeps the advertised keepalive", 30, 200, 30},
		{"the RFC default ratio needs no shortening", 30, 120, 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, effectiveKeepalive(tt.localKeepalive, tt.localDeadTimer))
		})
	}
}

func TestKeepaliveInterval_IgnoresPccAdvertisedValues(t *testing.T) {
	// RFC 5440 §7.3: advertising 0 disables Keepalive transmissions.
	ss := &Session{localOpen: &OpenParams{Keepalive: 30, DeadTimer: 120}}
	assert.Equal(t, uint8(30), ss.keepaliveInterval())

	ss.pccOpen = &OpenParams{Keepalive: 5, DeadTimer: 8}
	assert.Equal(t, uint8(30), ss.keepaliveInterval())
}

func TestKeepaliveInterval_ConstrainedByOwnDeadTimer(t *testing.T) {
	ss := &Session{localOpen: &OpenParams{Keepalive: 30, DeadTimer: 20}}
	assert.Equal(t, uint8(5), ss.keepaliveInterval())
}

func TestKeepaliveInterval_ZeroBeforeOpenIsSent(t *testing.T) {
	ss := &Session{}
	assert.Zero(t, ss.keepaliveInterval())
}

func TestKeepaliveInterval_ZeroWhenPolaAdvertisedKeepaliveZero(t *testing.T) {
	ss := &Session{localOpen: &OpenParams{Keepalive: 0, DeadTimer: 0}}
	assert.Zero(t, ss.keepaliveInterval())
}

// handshakeBytes returns an Open message followed by its Keepalive acknowledgment.
func handshakeBytes(t *testing.T, openMessage *pcep.OpenMessage) ([]byte, error) {
	t.Helper()

	openBytes, err := openMessage.Serialize()
	if err != nil {
		return nil, err
	}
	keepaliveBytes, err := pcep.NewKeepaliveMessage().Serialize()
	if err != nil {
		return nil, err
	}
	return append(openBytes, keepaliveBytes...), nil
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

	require.NoError(t, client.Close(), "failed to close client connection")

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after Open failed")
	}

	assert.False(t, ss.Up())
}

func TestEstablished_StateMachineFollowsRFC5440(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	assert.Equal(t, sessionStateTCPPending, ss.State(), "a freshly accepted session is TCP pending")
	assert.Equal(t, pb.SessionState_SESSION_STATE_TCP_PENDING, toPBSessionState(ss.State()))
	assert.False(t, ss.Up())

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read the Keepalive acknowledging the peer's Open")

	// RFC 5440 §6.2: the session is established only once both peers have received
	// a Keepalive, so Pola stays in KeepWait until the PCC acknowledges its Open.
	require.Eventually(t, func() bool { return ss.State() == sessionStateKeepWait }, 2*time.Second, 10*time.Millisecond,
		"Pola must wait in KeepWait for the peer's Keepalive")
	assert.Equal(t, pb.SessionState_SESSION_STATE_KEEP_WAIT, toPBSessionState(ss.State()))
	assert.False(t, ss.Up(), "the session must not be up before the peer acknowledges Pola's Open")

	writeMessage(t, client, pcep.NewKeepaliveMessage())

	require.Eventually(t, ss.Up, 2*time.Second, 10*time.Millisecond,
		"the session must come up once the peer's Keepalive arrives")
	assert.Equal(t, pb.SessionState_SESSION_STATE_UP, toPBSessionState(ss.State()))

	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the peer sent a Close message")
	}
}

func TestEstablished_KeepWaitExpiryReportsErrorValue7(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.keepWait = 50 * time.Millisecond

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read the Keepalive acknowledging the peer's Open")

	// RFC 5440 §6.2 and Appendix A: KeepWait expiry sends PCErr Error-value=7.
	pcerrMessage := readPCErrMessage(t, client)
	require.Len(t, pcerrMessage.Errors, 1)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorType)
	assert.Equal(t, uint8(7), pcerrMessage.Errors[0].ErrorValue)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after KeepWait expired")
	}
	assert.False(t, ss.Up())
}

func TestEstablished_OpenWaitExpiryReportsErrorValue2(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.openWait = 50 * time.Millisecond

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Pola's initial Open")

	// RFC 5440 §6.2 and Appendix A: OpenWait expiry sends PCErr Error-value=2.
	pcerrMessage := readPCErrMessage(t, client)
	require.Len(t, pcerrMessage.Errors, 1)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorType)
	assert.Equal(t, uint8(2), pcerrMessage.Errors[0].ErrorValue)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after OpenWait expired")
	}
}

func TestEstablished_NonOpenFirstMessageReportsErrorValue1(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	// RFC 5440 §6.2: any message received before an Open message is an error.
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Pola's initial Open")

	pcerrMessage := readPCErrMessage(t, client)
	require.Len(t, pcerrMessage.Errors, 1)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorType)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorValue)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after a non-Open first message")
	}
}

func TestEstablished_InvalidZeroMSDIsToleratedWithWarning(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	core, logs := observer.New(zap.WarnLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.New(core), nil, 0)

	// RFC 8664 §5.1 forbids X=0 with a zero MSD, but Cisco XRd, Juniper
	// vJunos, and FRRouting all advertise it in practice; the session must
	// still come up.
	pccCaps := []pcep.CapabilityInterface{&pcep.SRPCECapability{}}
	openMessage := pcep.NewOpenMessage(1, 30, pcep.DeadTimerFor(30), pccCaps)
	writeMessage(t, client, openMessage)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read the Keepalive acknowledging the peer's Open")

	writeMessage(t, client, pcep.NewKeepaliveMessage())

	require.Eventually(t, ss.Up, 2*time.Second, 10*time.Millisecond,
		"the session must come up despite the peer's invalid SR-PCE-CAPABILITY")

	assert.Len(t, logs.FilterMessage(
		"peer advertised SR-PCE-CAPABILITY with X=0 and MSD=0 (RFC 8664 §5.1); tolerating as a known deployed-peer deviation").All(), 1)

	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the peer sent a Close message")
	}
}

func TestValidateCapabilities_ChecksSRPCECapabilityNestedInPathSetupType(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.New(core), nil, 0)

	caps := []pcep.CapabilityInterface{
		&pcep.PathSetupTypeCapability{
			PathSetupTypes: pcep.Psts{pcep.PathSetupTypeSRTE},
			SubTLVs: []pcep.TLVInterface{
				&pcep.SRPCECapability{},
			},
		},
	}

	ss.validateCapabilities(caps)

	assert.Len(t, logs.FilterMessage(
		"peer advertised SR-PCE-CAPABILITY with X=0 and MSD=0 (RFC 8664 §5.1); tolerating as a known deployed-peer deviation").All(), 1)
}

func TestValidateCapabilities_WarnsWhenSRTEAdvertisedWithoutSRCapability(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.New(core), nil, 0)

	caps := []pcep.CapabilityInterface{
		&pcep.PathSetupTypeCapability{PathSetupTypes: pcep.Psts{pcep.PathSetupTypeSRTE}},
	}

	ss.validateCapabilities(caps)

	assert.Len(t, logs.FilterMessage(
		"peer advertised PST=1 (SR-TE) without an SR-PCE-CAPABILITY sub-TLV (RFC 8664 §4.1.2)").All(), 1)
}

func TestValidateCapabilities_WarnsWhenSRv6TEAdvertisedWithoutSRv6Capability(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.New(core), nil, 0)

	caps := []pcep.CapabilityInterface{
		&pcep.PathSetupTypeCapability{PathSetupTypes: pcep.Psts{pcep.PathSetupTypeSRv6TE}},
	}

	ss.validateCapabilities(caps)

	assert.Len(t, logs.FilterMessage(
		"peer advertised PST=3 (SRv6-TE) without an SRv6-PCE-CAPABILITY sub-TLV (RFC 9603 §4.1.1)").All(), 1)
}

func TestValidateCapabilities_NoWarningWhenSRCapabilityAdvertisedAtTopLevel(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.New(core), nil, 0)

	caps := []pcep.CapabilityInterface{
		&pcep.PathSetupTypeCapability{PathSetupTypes: pcep.Psts{pcep.PathSetupTypeSRTE}},
		&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true},
	}

	ss.validateCapabilities(caps)

	assert.Zero(t, logs.Len())
}

func TestValidateCapabilities_NoWarningWhenSRv6CapabilityAdvertisedAtTopLevel(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.New(core), nil, 0)

	caps := []pcep.CapabilityInterface{
		&pcep.PathSetupTypeCapability{PathSetupTypes: pcep.Psts{pcep.PathSetupTypeSRv6TE}},
		&pcep.SRv6PCECapability{},
	}

	ss.validateCapabilities(caps)

	assert.Zero(t, logs.Len())
}

func TestEstablished_PCErrDuringKeepWaitReportsErrorValue6(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))
	// Pola does not negotiate, so a proposal in KeepWait is unacceptable.
	writeMessage(t, client, pcep.NewPCErrMessage(1, 4, nil))

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read the Keepalive acknowledging the peer's Open")

	pcerrMessage := readPCErrMessage(t, client)
	require.Len(t, pcerrMessage.Errors, 1)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorType)
	assert.Equal(t, uint8(6), pcerrMessage.Errors[0].ErrorValue)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after receiving a PCErr in KeepWait")
	}
	assert.False(t, ss.Up())
}

func TestEstablished_UnacceptableKeepaliveNonNegotiableReportsErrorValue3(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.keepaliveRangeEnabled = true
	ss.minKeepalive, ss.maxKeepalive = 10, 60
	ss.allowNegotiation = false

	// RFC 7420 pcePcepEntityMin/MaxKeepAliveTimer: outside [10,60] is unacceptable.
	writeMessage(t, client, pcep.NewOpenMessage(1, 5, 20, nil))

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Pola's initial Open")

	// RFC 5440 §6.2: negotiation disabled sends Error-Value=3 (non-negotiable).
	pcerrMessage := readPCErrMessage(t, client)
	require.Len(t, pcerrMessage.Errors, 1)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorType)
	assert.Equal(t, uint8(3), pcerrMessage.Errors[0].ErrorValue)
	assert.Nil(t, pcerrMessage.Open, "a non-negotiable rejection carries no proposed OPEN object")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after an unacceptable, non-negotiable Open")
	}
	assert.False(t, ss.Up())
}

func TestEstablished_NegotiatesAcceptableKeepaliveThenEstablishes(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.keepaliveRangeEnabled = true
	ss.minKeepalive, ss.maxKeepalive = 10, 60
	ss.allowNegotiation = true

	writeMessage(t, client, pcep.NewOpenMessage(1, 5, 20, nil))

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Pola's initial Open")

	// RFC 5440 §7.15: propose acceptable session characteristics with Error-Value=4.
	pcerrMessage := readPCErrMessage(t, client)
	require.Len(t, pcerrMessage.Errors, 1)
	assert.Equal(t, uint8(1), pcerrMessage.Errors[0].ErrorType)
	assert.Equal(t, uint8(4), pcerrMessage.Errors[0].ErrorValue)
	require.NotNil(t, pcerrMessage.Open, "a negotiable rejection proposes an OPEN object")
	assert.Equal(t, uint8(10), pcerrMessage.Open.Keepalive, "the proposal clamps up to the configured minimum")
	assert.Equal(t, uint8(40), pcerrMessage.Open.Deadtime)

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))

	require.NoError(t, readPCEPMessage(client), "failed to read the Keepalive acknowledging the peer's Open")

	writeMessage(t, client, pcep.NewKeepaliveMessage())

	require.Eventually(t, ss.Up, 2*time.Second, 10*time.Millisecond,
		"the session must come up once the peer proposes acceptable session characteristics")

	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the peer sent a Close message")
	}
}

func TestEstablished_SecondOpenStillUnacceptableReportsErrorValue5(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	ss.keepaliveRangeEnabled = true
	ss.minKeepalive, ss.maxKeepalive = 10, 60
	ss.allowNegotiation = true

	writeMessage(t, client, pcep.NewOpenMessage(1, 5, 20, nil))

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Pola's initial Open")

	firstErr := readPCErrMessage(t, client)
	require.Equal(t, uint8(4), firstErr.Errors[0].ErrorValue)

	writeMessage(t, client, pcep.NewOpenMessage(1, 200, 255, nil))

	// RFC 5440 §6.2: a second unacceptable Open sends Error-Value=5 and gives up.
	secondErr := readPCErrMessage(t, client)
	require.Len(t, secondErr.Errors, 1)
	assert.Equal(t, uint8(1), secondErr.Errors[0].ErrorType)
	assert.Equal(t, uint8(5), secondErr.Errors[0].ErrorValue)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after a second unacceptable Open")
	}
	assert.False(t, ss.Up())
}

func TestEstablished_ReturnsOnCloseMessage(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
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

	writeMessage(t, client, pcep.NewOpenMessage(1, 0, 0, nil))
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
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

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
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
	// Use a 1-second Keepalive so the periodic send fails quickly.
	openBytes, err := handshakeBytes(t, pcep.NewOpenMessage(1, 30, 120, nil))
	require.NoError(t, err)

	// Block the receive loop so the test observes the periodic send failure.
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, pw.Close(), "failed to close pipe writer")
	})

	conn := &fakeConn{
		r:         io.MultiReader(bytes.NewReader(openBytes), pr),
		failAfter: 2,
		writeErr:  errors.New("write: broken pipe"),
	}

	ss := NewSession(OpenParams{SessionID: 1, Keepalive: 1, DeadTimer: 4}, netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		require.Fail(t, "Established did not return after the periodic keepalive send failed")
	}
}

func TestEstablished_ReturnsWhenInitialKeepaliveSendFails(t *testing.T) {
	openBytes, err := handshakeBytes(t, pcep.NewOpenMessage(1, 30, 120, nil))
	require.NoError(t, err)

	pr, pw := io.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, pw.Close(), "failed to close pipe writer")
	})

	conn := &fakeConn{
		r:         io.MultiReader(bytes.NewReader(openBytes), pr),
		failAfter: 1,
		writeErr:  errors.New("write: broken pipe"),
	}

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
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

			ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
			assert.Error(t, ss.ReceiveOpen())
		})
	}
}

// errAfterReader returns prefix once, then always returns err. It allows
// deadline-exceeded handling to be tested without waiting for a real timer.
type errAfterReader struct {
	prefix []byte
	err    error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return 0, r.err
}

func TestOpen_SendOpenFailureAfterSuccessfulNegotiation(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 30, 120, nil).Serialize()
	require.NoError(t, err)

	conn := &fakeConn{r: bytes.NewReader(openBytes), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	require.Error(t, ss.Open(), "expected Open to fail once negotiation succeeds but SendOpen cannot write")
}

func TestAwaitKeepalive_ReadCommonHeaderErrorIsPropagated(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 30, 120, nil).Serialize()
	require.NoError(t, err)

	// The peer disconnects during KeepWait without sending a Keepalive.
	conn := &fakeConn{r: bytes.NewReader(openBytes)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	err = ss.Open()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "KeepWait timer expired", "an abrupt disconnect is not a timer expiry")
}

func TestAwaitKeepalive_TruncatedMessageBodyReturnsError(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 30, 120, nil).Serialize()
	require.NoError(t, err)

	truncated := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeReport, MessageLength: pcep.CommonHeaderLength + 4}
	stream := append([]byte{}, openBytes...)
	stream = append(stream, truncated.Serialize()...)
	stream = append(stream, 0x00, 0x00)

	conn := &fakeConn{r: bytes.NewReader(stream)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	require.Error(t, ss.Open(), "expected a truncated KeepWait message body to be reported as an error")
}

func TestAwaitKeepalive_UnexpectedMessageTypeIsRejected(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 30, 120, nil).Serialize()
	require.NoError(t, err)
	closeBytes, err := pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided).Serialize()
	require.NoError(t, err)

	conn := &fakeConn{r: bytes.NewReader(append(openBytes, closeBytes...))}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	err = ss.Open()
	assert.ErrorContains(t, err, "expected a Keepalive or PCErr message in KeepWait")
}

func TestAwaitKeepalive_SendPCErrFailureIsLoggedNotFatal(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 30, 120, nil).Serialize()
	require.NoError(t, err)

	// Allow the Open and Keepalive writes to succeed; fail the KeepWait-expiry PCErr.
	conn := &fakeConn{
		r:         &errAfterReader{prefix: openBytes, err: os.ErrDeadlineExceeded},
		failAfter: 2,
		writeErr:  errors.New("write: broken pipe"),
	}
	core, logs := observer.New(zap.DebugLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.New(core), nil, 0)

	err = ss.Open()
	require.ErrorContains(t, err, "KeepWait timer expired",
		"the session must still report timer expiry even though the best-effort PCErr send failed")
	assert.NotEmpty(t, logs.FilterMessage("ERROR! Send PCErr Message").All())
}

func TestAwaitKeepalive_KeepWaitExpiresWhileReadingBody(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 30, 120, nil).Serialize()
	require.NoError(t, err)

	// Simulate a body read timeout after receiving the header.
	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeReport, MessageLength: pcep.CommonHeaderLength + 4}
	conn := &fakeConn{r: &errAfterReader{prefix: append(openBytes, header.Serialize()...), err: os.ErrDeadlineExceeded}}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	err = ss.Open()
	require.ErrorContains(t, err, "KeepWait timer expired while reading the message body")
}

func TestHandleKeepWaitPCErr_MalformedPCErrReturnsError(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	_, err := ss.handleKeepWaitPCErr([]byte{}, true)
	require.ErrorContains(t, err, "malformed PCErr in KeepWait")
}

func TestHandleKeepWaitPCErr_OtherErrorIsReportedAsIs(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	pcerrMessage := pcep.NewPCErrMessage(pcepErrorTypeSessionEstablishmentFailure, pcepErrorValueSecondOpenStillUnacceptable, nil)
	full, err := pcerrMessage.Serialize()
	require.NoError(t, err)

	_, err = ss.handleKeepWaitPCErr(full[pcep.CommonHeaderLength:], true)
	require.ErrorContains(t, err, "peer rejected session establishment")
}

func TestHandleKeepWaitPCErr_NegotiableProposalIsFoundBehindOtherErrors(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	ss.allowNegotiation = true

	pcerrMessage := &pcep.PCErrMessage{
		Errors: []*pcep.ErrorObject{
			pcep.NewErrorObject(pcepErrorTypeCapabilityNotSupported, pcepErrorValueUnassigned, nil),
			pcep.NewErrorObject(pcepErrorTypeSessionEstablishmentFailure, pcepErrorValueUnacceptableNegotiable, nil),
		},
		Open: pcep.NewOpenObject(1, 20, 80, nil),
	}
	full, err := pcerrMessage.Serialize()
	require.NoError(t, err)

	retry, err := ss.handleKeepWaitPCErr(full[pcep.CommonHeaderLength:], true)
	require.NoError(t, err)
	assert.True(t, retry, "an Error 1/4 must drive renegotiation even when it is not the first PCEP-ERROR object")
	assert.Equal(t, uint8(20), ss.localKeepalive)
}

func TestHandleKeepWaitPCErr_AllErrorsAreReported(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	pcerrMessage := &pcep.PCErrMessage{
		Errors: []*pcep.ErrorObject{
			pcep.NewErrorObject(pcepErrorTypeCapabilityNotSupported, pcepErrorValueUnassigned, nil),
			pcep.NewErrorObject(pcepErrorTypeSessionEstablishmentFailure, pcepErrorValueUnacceptableNonNegotiable, nil),
		},
	}
	full, err := pcerrMessage.Serialize()
	require.NoError(t, err)

	_, err = ss.handleKeepWaitPCErr(full[pcep.CommonHeaderLength:], true)
	require.ErrorContains(t, err, "error-type=2, error-value=0")
	require.ErrorContains(t, err, "error-type=1, error-value=3")
	assert.Zero(t, conn.writeCount, "a non-negotiable rejection must not be answered with PCErr 1/6")
}

func TestOpen_RetriesAfterAcceptablePCErrProposal(t *testing.T) {
	peerOpenBytes, err := pcep.NewOpenMessage(1, 30, 120, nil).Serialize()
	require.NoError(t, err)

	proposedOpen := pcep.NewOpenObject(1, 20, 80, nil)
	pcerrMessage := pcep.NewPCErrMessageWithOpen(pcepErrorTypeSessionEstablishmentFailure, pcepErrorValueUnacceptableNegotiable, proposedOpen)
	pcerrBytes, err := pcerrMessage.Serialize()
	require.NoError(t, err)

	keepaliveBytes, err := pcep.NewKeepaliveMessage().Serialize()
	require.NoError(t, err)

	stream := append(append(peerOpenBytes, pcerrBytes...), keepaliveBytes...)
	conn := &fakeConn{r: bytes.NewReader(stream)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	require.NoError(t, ss.Open(), "Open must retry with the peer's acceptable proposal instead of failing")
	assert.Equal(t, uint8(20), ss.localKeepalive)
	assert.Equal(t, uint8(80), ss.localDeadTimer)
}

func TestOpen_SendOpenFailsAfterRetryingWithProposal(t *testing.T) {
	// Use distinct SIDs to verify that retrying keeps Pola's own SID.
	peerOpenBytes, err := pcep.NewOpenMessage(2, 30, 120, nil).Serialize()
	require.NoError(t, err)

	proposedOpen := pcep.NewOpenObject(2, 20, 80, nil)
	pcerrMessage := pcep.NewPCErrMessageWithOpen(pcepErrorTypeSessionEstablishmentFailure, pcepErrorValueUnacceptableNegotiable, proposedOpen)
	pcerrBytes, err := pcerrMessage.Serialize()
	require.NoError(t, err)

	stream := append(append([]byte(nil), peerOpenBytes...), pcerrBytes...)
	conn := &fakeConn{
		r:         bytes.NewReader(stream),
		failAfter: 2,
		writeErr:  errors.New("write: broken pipe"),
	}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	err = ss.Open()
	require.Error(t, err)
	require.ErrorContains(t, err, "write: broken pipe")

	writes := conn.writes()
	require.Len(t, writes, 3, "expected initial Open, Keepalive, and retry Open")

	initialOpen := readOpenMessage(t, bytes.NewReader(writes[0]))
	assert.Equal(t, uint8(1), initialOpen.OpenObject.Sid, "initial SendOpen must use Pola's own SID")

	var keepaliveHeader pcep.CommonHeader
	require.NoError(t, keepaliveHeader.DecodeFromBytes(writes[1]))
	assert.Equal(t, pcep.MessageTypeKeepalive, keepaliveHeader.MessageType, "second write must be the Keepalive")

	retryOpen := readOpenMessage(t, bytes.NewReader(writes[2]))
	assert.Equal(t, uint8(1), retryOpen.OpenObject.Sid, "retry SendOpen must still use Pola's own SID, not the peer's proposed one")
}

func TestHandleProposedOpen_UnacceptableProposalIsRejected(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	proposedOpen := pcep.NewOpenObject(1, 50, 10, nil)
	retry, err := ss.handleProposedOpen(proposedOpen, true)
	assert.False(t, retry)
	require.ErrorContains(t, err, "peer proposed unacceptable session characteristics")
}

func TestHandleProposedOpen_IgnoresPCCKeepaliveRange(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	ss.keepaliveRangeEnabled = true
	ss.minKeepalive, ss.maxKeepalive = 10, 60

	proposedOpen := pcep.NewOpenObject(1, 5, 20, nil)
	retry, err := ss.handleProposedOpen(proposedOpen, true)
	require.NoError(t, err)
	assert.True(t, retry)
	assert.Equal(t, uint8(5), ss.localKeepalive)
	assert.Equal(t, uint8(20), ss.localDeadTimer)
}

func TestHandleProposedOpen_MissingOpenObjectIsRejected(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	retry, err := ss.handleProposedOpen(nil, true)
	assert.False(t, retry)
	require.ErrorContains(t, err, "without proposing acceptable ones")
}

func TestHandleProposedOpen_FurtherProposalAfterRetryIsRejected(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	retry, err := ss.handleProposedOpen(pcep.NewOpenObject(1, 20, 80, nil), false)
	assert.False(t, retry)
	require.ErrorContains(t, err, "further proposal")
	assert.Equal(t, 1, conn.writeCount, "an exhausted negotiation must be answered with PCErr 1/6")
}

func TestOpen_RejectsSecondProposalWithErrorValue6(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	proposedOpen := pcep.NewOpenObject(1, 20, 80, nil)
	pcerrMessage := pcep.NewPCErrMessageWithOpen(pcepErrorTypeSessionEstablishmentFailure, pcepErrorValueUnacceptableNegotiable, proposedOpen)

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))
	writeMessage(t, client, pcerrMessage)
	writeMessage(t, client, pcerrMessage)

	errCh := make(chan error, 1)
	go func() { errCh <- ss.Open() }()

	for range 4 {
		require.NoError(t, readPCEPMessage(client))
	}

	rejection := readPCErrMessage(t, client)
	require.Len(t, rejection.Errors, 1)
	assert.Equal(t, pcepErrorTypeSessionEstablishmentFailure, rejection.Errors[0].ErrorType)
	assert.Equal(t, pcepErrorValueUnacceptableProposal, rejection.Errors[0].ErrorValue)

	select {
	case err := <-errCh:
		require.ErrorContains(t, err, "further proposal")
	case <-time.After(2 * time.Second):
		require.Fail(t, "Open did not return after rejecting the second proposal")
	}
	assert.False(t, ss.Up())
}

func TestReceiveOpen_OpenWaitExpiresWhileReadingBody(t *testing.T) {
	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeOpen, MessageLength: pcep.CommonHeaderLength + 10}
	conn := &fakeConn{r: &errAfterReader{prefix: header.Serialize(), err: os.ErrDeadlineExceeded}}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	err := ss.ReceiveOpen()
	assert.ErrorContains(t, err, "OpenWait timer expired before the Open message was complete")
}

func TestNegotiateOpen_ProposeAcceptableOpenSendFailure(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 5, 20, nil).Serialize()
	require.NoError(t, err)

	conn := &fakeConn{r: bytes.NewReader(openBytes), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	ss.keepaliveRangeEnabled = true
	ss.minKeepalive, ss.maxKeepalive = 10, 60
	ss.allowNegotiation = true

	require.Error(t, ss.negotiateOpen(), "expected negotiateOpen to fail once proposeAcceptableOpen cannot send")
}

func TestNegotiateOpen_SecondReceiveOpenFailure(t *testing.T) {
	openBytes, err := pcep.NewOpenMessage(1, 5, 20, nil).Serialize()
	require.NoError(t, err)

	conn := &fakeConn{r: bytes.NewReader(openBytes)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
	ss.keepaliveRangeEnabled = true
	ss.minKeepalive, ss.maxKeepalive = 10, 60
	ss.allowNegotiation = true

	require.Error(t, ss.negotiateOpen(), "expected negotiateOpen to fail once the peer's second Open never arrives")
}

func TestReceivePCEPMessage_SendCloseFailureIsLoggedNotFatal(t *testing.T) {
	conn := &fakeConn{r: &errAfterReader{err: os.ErrDeadlineExceeded}, writeErr: errors.New("write: broken pipe")}
	core, logs := observer.New(zap.DebugLevel)
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.New(core), nil, 0)
	ss.pccOpen = &OpenParams{Keepalive: 1, DeadTimer: 1}

	err := ss.ReceivePCEPMessage()
	require.Error(t, err, "the DeadTimer expiry error must still be returned even if the Close send fails")
	assert.NotEmpty(t, logs.FilterMessage("ERROR! Send Close Message").All())
}

func TestReceivePCEPMessage_ProcessesMessagesThenReturnsOnClose(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	// The DeadTimer the PCC advertised bounds the read (RFC 5440 §7.3).
	ss.pccOpen = &OpenParams{Keepalive: 1, DeadTimer: 1}

	_, err := client.Write([]byte{0x20, 0x01}) // half of a 4-byte common header
	require.NoError(t, err)

	start := time.Now()
	_, err = ss.readCommonHeader(ss.messageDeadline())
	elapsed := time.Since(start)

	require.Error(t, err, "a stalled peer must not block the read indefinitely")
	assert.Less(t, elapsed, 10*time.Second, "read should time out near the PCC's dead timer, not hang")
}

func TestReadDeadline_UsesPccAdvertisedDeadTimer(t *testing.T) {
	tests := []struct {
		name    string
		pccOpen *OpenParams
		want    time.Duration
	}{
		{"no Open received yet", nil, 0},
		{"PCC dead timer is used verbatim", &OpenParams{Keepalive: 30, DeadTimer: 120}, 120 * time.Second},
		{"maximum PCC dead timer", &OpenParams{Keepalive: 60, DeadTimer: math.MaxUint8}, time.Duration(math.MaxUint8) * time.Second},
		// RFC 5440 §7.3: the DeadTimer MUST be ignored when the Keepalive is 0, and
		// RFC 5440 §6.3 forbids declaring such a session inactive.
		{"PCC keepalive of zero disables the deadline", &OpenParams{Keepalive: 0, DeadTimer: 120}, 0},
		{"PCC dead timer of zero disables the deadline", &OpenParams{Keepalive: 30, DeadTimer: 0}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := &Session{pccOpen: tt.pccOpen}
			assert.Equal(t, tt.want, ss.readDeadline())
		})
	}
}

func TestReadDeadline_IgnoresLocalDeadTimer(t *testing.T) {
	// Pola's own DeadTimer tells the PCC when to declare Pola down; it must never
	// bound Pola's own reads (RFC 5440 §7.3).
	ss := &Session{
		localOpen: &OpenParams{Keepalive: 30, DeadTimer: 120},
		pccOpen:   &OpenParams{Keepalive: 0, DeadTimer: 0},
	}
	assert.Zero(t, ss.readDeadline())

	ss.pccOpen = &OpenParams{Keepalive: 10, DeadTimer: 40}
	assert.Equal(t, 40*time.Second, ss.readDeadline())
}

func TestEstablished_DoesNotTimeOutAPccThatSendsNoKeepalives(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	// RFC 5440 §6.3: a peer that advertises Keepalive=0 sends none, and the
	// receiver MUST NOT declare the session inactive.
	writeMessage(t, client, pcep.NewOpenMessage(1, 0, 0, nil))
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read initial Keepalive")
	require.Eventually(t, ss.Up, 2*time.Second, 10*time.Millisecond)

	assert.Zero(t, ss.readDeadline(), "a PCC advertising Keepalive=0 must never be timed out")

	select {
	case <-done:
		require.Fail(t, "Established must not return while the silent peer is still connected")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestEstablished_SendsCloseWhenTheDeadTimerExpires(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	// A 2-second DeadTimer from the PCC keeps the test fast.
	writeMessage(t, client, pcep.NewOpenMessage(1, 1, 2, nil))
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	ss := NewSession(OpenParams{SessionID: 1, Keepalive: 0, DeadTimer: 0}, netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read initial Keepalive")

	// RFC 5440 §6.8 and Appendix A: DeadTimer expiry terminates the session.
	closeMessage := readCloseMessage(t, client)
	assert.Equal(t, pcep.CloseReasonDeadTimerExpired, closeMessage.CloseObject.Reason)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the DeadTimer expired")
	}
}

func TestReadFullWithDeadline_SetReadDeadlineErrorIsPropagated(t *testing.T) {
	wantErr := errors.New("use of closed network connection")
	conn := &fakeConn{r: bytes.NewReader(nil), setReadDeadlineErr: wantErr}

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	sr := newTestStateReport(t, 7, 0)
	byteSrp, err := sr.SrpObject.Serialize()
	require.NoError(t, err, "failed to serialize SrpObject")
	byteLsp, err := sr.LSPObject.Serialize()
	require.NoError(t, err, "failed to serialize LSPObject")
	body := slices.Concat(byteSrp, byteLsp) // no ERO object
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

			ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
			assert.Error(t, ss.ReceivePCEPMessage())
		})
	}
}

func TestReceivePCEPMessage_ShortMessageLengthIsRejected(t *testing.T) {
	for length := range pcep.CommonHeaderLength {
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

			ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

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

func TestReceivePCEPMessage_NotificationBodyIsConsumed(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	trap, err := pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided).Serialize()
	require.NoError(t, err, "failed to serialize the message body")
	writeRawPCEPMessage(t, client, pcep.MessageTypeNotification, trap)

	writeStateReportMessage(t, client, newTestStateReport(t, 5, 0))
	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))

	require.NoError(t, ss.ReceivePCEPMessage())

	_, found := ss.SearchSRPolicy(5)
	assert.True(t, found, "the PCRpt following a Notification was not processed")
	assert.Equal(t, uint64(1), ss.Stats().PCNtfRcvd)
}

func TestReceivePCEPMessage_NotificationTruncatedBodyReturnsError(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})

	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageTypeNotification, MessageLength: pcep.CommonHeaderLength + 4}
	_, err := client.Write(header.Serialize())
	require.NoError(t, err, "failed to write header")
	require.NoError(t, client.Close(), "failed to close client connection")

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	assert.Error(t, ss.ReceivePCEPMessage(), "a truncated Notification body must be reported")
}

func TestHandleUnsupportedMessage_ReadBodyErrorIsReturned(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil)}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageType(0x63), MessageLength: pcep.CommonHeaderLength + 4}
	assert.Error(t, ss.handleUnsupportedMessage(header, ss.messageDeadline()), "a truncated unsupported message body must be reported")
}

func TestHandleUnsupportedMessage_SendPCErrFailureIsLoggedNotFatal(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)

	header := &pcep.CommonHeader{Version: 1, MessageType: pcep.MessageType(0x63), MessageLength: pcep.CommonHeaderLength}
	err := ss.handleUnsupportedMessage(header, ss.messageDeadline())
	assert.NoError(t, err, "a single unsupported message must not close the session even if the PCErr reply fails to send")
}

func TestHandleUnsupportedMessage_SendCloseFailureStillReturnsError(t *testing.T) {
	conn := &fakeConn{r: bytes.NewReader(nil), writeErr: errors.New("write: broken pipe")}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), conn, zap.NewNop(), nil, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	for range ss.maxUnknownMsgs {
		writeRawPCEPMessage(t, client, pcep.MessageType(0x63), nil)
	}
	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))

	require.NoError(t, ss.ReceivePCEPMessage(), "unrecognized messages within the threshold must not close the session")

	for range ss.maxUnknownMsgs {
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

func TestIsSynced_ConcurrentAccess(_ *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			ss.setSynced()
		}
	}()

	for range 100 {
		ss.IsSynced()
	}
	<-done
}

// RFC 8231 §5.6: an LSP report with the S-Flag is part of state synchronization
// and is registered regardless of PLSP-ID or SRP-ID..
func TestHandleStateReport_Synchronization(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SFlag = true

	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	policy, found := ss.SearchSRPolicy(1)
	require.True(t, found, "SR Policy reported during synchronization was not registered")
	assert.Equal(t, sr.LSPObject.Name, policy.Name)
}

func TestHandleStateReport_SynchronizationRegistrationFailure(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SFlag = true
	sr.EroObject = nil

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
}

// RFC 8231 §5.6: PLSP-ID 0 marks the end of state synchronization.
func TestHandleStateReport_FinishSynchronization(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	require.False(t, ss.IsSynced())

	sr := newTestStateReport(t, 0, 0)
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	assert.True(t, ss.IsSynced())
}

func TestHandleStateReport_StatefulPCERequestRegistrationFailure(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 3) // non-zero SRP-ID uses handleStatefulPCERequest
	sr.EroObject = nil

	require.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	_, found := ss.SearchSRPolicy(1)
	assert.False(t, found)
}

func TestHandleStateReport_ReportedSRPolicyRegistrationFailure(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)
	sr.EroObject = nil // no TED available and no explicit path reported

	assert.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
}

func TestComputePathFromTED_NoTED(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := newTestStateReport(t, 1, 0)

	_, err := ss.computePathFromTED(*sr)
	assert.Error(t, err)
}

func TestHandleSRPolicyWithPLSPID_ExtractRouterIDsFails(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)
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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = srcAddr
	sr.LSPObject.DstAddr = dstAddr

	require.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), ted, 0)

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = selfAddr
	sr.LSPObject.DstAddr = selfAddr

	require.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), ted, 0)

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = srcAddr
	sr.LSPObject.DstAddr = dstAddr

	require.Error(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

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
			ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = netip.Addr{}
	sr.AssociationObject.AssocSrc = netip.MustParseAddr("192.0.2.9")

	require.NoError(t, ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 0, 0, table.PolicyUp))

	policy, found := ss.SearchSRPolicy(1)
	require.True(t, found)
	assert.Equal(t, netip.MustParseAddr("192.0.2.9"), policy.SrcAddr)
}

func TestUpdateOrCreatePolicy_InvalidSrcAddr(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.SrcAddr = netip.Addr{}

	err := ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 0, 0, table.PolicyUp)
	assert.Error(t, err)
}

func TestUpdateOrCreatePolicy_DstAddrFallsBackToAssociationEndpoint(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	sr := *newTestStateReport(t, 1, 0)
	sr.LSPObject.DstAddr = netip.Addr{}

	err := ss.updateOrCreatePolicy(sr, sr.EroObject.ToSegmentList(), 0, 0, table.PolicyUp)
	assert.Error(t, err)
}

// RFC 8231 §7.3: a stale LSP-ID must not overwrite newer state.
func TestUpdateOrCreatePolicy_StaleLSPIDIsIgnored(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
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
	return nil, errors.New("serialize failed")
}

func TestSendPCEPMessage_SerializeErrorIsPropagated(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	assert.Error(t, ss.sendPCEPMessage(failingMessage{}))
}

type unknownSegment struct{}

func (unknownSegment) SidString() string { return "unknown" }

func TestSendPCInitiate_InvalidSegmentTypeIsRejected(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	wantSRPID := ss.srpIDHead
	srPolicy := table.SRPolicy{
		Name:        "bad-segment",
		SrcAddr:     netip.MustParseAddr("10.255.0.1"),
		DstAddr:     netip.MustParseAddr("10.255.0.2"),
		SegmentList: []table.Segment{unknownSegment{}},
	}

	require.Error(t, ss.SendPCInitiate(srPolicy, false))

	_, ok := ss.takeSRPolicyIntent(wantSRPID)
	assert.False(t, ok, "intent must be forgotten when message construction fails")
}

func TestSendPCUpdate_InvalidSegmentTypeIsRejected(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	wantSRPID := ss.srpIDHead
	srPolicy := table.SRPolicy{
		Name:        "bad-segment",
		SegmentList: []table.Segment{unknownSegment{}},
	}

	require.Error(t, ss.SendPCUpdate(srPolicy))

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

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

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

func TestSession_CreatedAtSetOnConstruction(t *testing.T) {
	before := time.Now()
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	after := time.Now()

	assert.False(t, ss.CreatedAt().Before(before))
	assert.False(t, ss.CreatedAt().After(after))
	assert.True(t, ss.EstablishedAt().IsZero(), "EstablishedAt must be zero before the session comes up")
}

func TestSession_InitiatorDefaultsToRemote(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	assert.Equal(t, sessionInitiatorRemote, ss.Initiator(), "Pola only accepts connections, so the initiator is always remote today")
}

func TestEstablished_SetsEstablishedAtOnceUp(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, client.Close(), "failed to close client connection") })

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	require.True(t, ss.EstablishedAt().IsZero())

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))

	done := make(chan struct{})
	go func() {
		_ = ss.Established()
		close(done)
	}()

	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read the Keepalive acknowledging the peer's Open")
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	require.Eventually(t, ss.Up, 2*time.Second, 10*time.Millisecond, "the session must come up")
	assert.False(t, ss.EstablishedAt().IsZero(), "EstablishedAt must be set once the session is up")

	writeMessage(t, client, pcep.NewCloseMessage(pcep.CloseReasonNoExplanationProvided))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "Established did not return after the peer sent a Close message")
	}
}

func TestEstablished_ReturnsErrorOnlyWhenEstablishmentFails(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() { assert.NoError(t, server.Close(), "failed to close server connection") })
	require.NoError(t, client.Close(), "failed to close client connection")

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	assert.Error(t, ss.Established(), "Established must report an error when Open fails")
}

func TestSyncState_TransitionsPendingOngoingFinished(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	assert.Equal(t, lspDBSyncPending, ss.SyncState())

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SFlag = true
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
	assert.Equal(t, lspDBSyncOngoing, ss.SyncState())

	finish := newTestStateReport(t, 0, 0)
	require.NoError(t, ss.handleStateReport(finish, pcep.NewPCRptMessage()))
	assert.Equal(t, lspDBSyncFinished, ss.SyncState())
}

func TestSyncState_DoesNotRegressAfterFinished(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.setSynced()
	require.Equal(t, lspDBSyncFinished, ss.SyncState())

	sr := newTestStateReport(t, 1, 0)
	sr.LSPObject.SFlag = true
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))

	assert.Equal(t, lspDBSyncFinished, ss.SyncState(), "sync state must not regress once finished")
}

func TestSessionStats_SendCountersIncrementOnSuccess(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	require.NoError(t, ss.SendOpen())
	require.NoError(t, readPCEPMessage(client))
	assert.Equal(t, uint64(1), ss.Stats().OpenSent)

	require.NoError(t, ss.SendKeepalive())
	require.NoError(t, readPCEPMessage(client))
	assert.Equal(t, uint64(1), ss.Stats().KeepaliveSent)

	require.NoError(t, ss.SendClose(pcep.CloseReasonNoExplanationProvided))
	require.NoError(t, readPCEPMessage(client))
	assert.Equal(t, uint64(1), ss.Stats().CloseSent)

	require.NoError(t, ss.SendPCErr(pcepErrorTypeCapabilityNotSupported, pcepErrorValueUnassigned))
	require.NoError(t, readPCEPMessage(client))
	assert.Equal(t, uint64(1), ss.Stats().PCErrSent)

	require.NoError(t, ss.SendPCUpdate(table.SRPolicy{
		Name:    "stats-test",
		SrcAddr: netip.MustParseAddr("10.255.0.1"),
		DstAddr: netip.MustParseAddr("10.255.0.2"),
		Type:    table.PolicyTypeDynamic,
		Metric:  table.TEMetric,
	}))
	require.NoError(t, readPCEPMessage(client))
	assert.Equal(t, uint64(1), ss.Stats().UpdSent)

	require.NoError(t, ss.SendPCInitiate(table.SRPolicy{
		Name:    "stats-test",
		SrcAddr: netip.MustParseAddr("10.255.0.1"),
		DstAddr: netip.MustParseAddr("10.255.0.2"),
		Type:    table.PolicyTypeDynamic,
		Metric:  table.TEMetric,
	}, false))
	require.NoError(t, readPCEPMessage(client))
	assert.Equal(t, uint64(1), ss.Stats().PCInitiateSent)
}

func TestSessionStats_OpenRcvdIncrementsOnSuccess(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	openMessage := pcep.NewOpenMessage(1, 30, pcep.DeadTimerFor(30), nil)
	byteOpenMessage, err := openMessage.Serialize()
	require.NoError(t, err, "failed to serialize open message")
	_, err = client.Write(byteOpenMessage)
	require.NoError(t, err, "failed to write open message")

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)
	require.NoError(t, ss.ReceiveOpen())
	assert.Equal(t, uint64(1), ss.Stats().OpenRcvd)
}

func TestCountReceived_IncrementsExpectedCounter(t *testing.T) {
	cases := map[string]struct {
		messageType pcep.MessageType
		get         func(sessionStatsSnapshot) uint64
	}{
		"Keepalive":    {pcep.MessageTypeKeepalive, func(s sessionStatsSnapshot) uint64 { return s.KeepaliveRcvd }},
		"Report":       {pcep.MessageTypeReport, func(s sessionStatsSnapshot) uint64 { return s.RptRcvd }},
		"Error":        {pcep.MessageTypeError, func(s sessionStatsSnapshot) uint64 { return s.PCErrRcvd }},
		"Notification": {pcep.MessageTypeNotification, func(s sessionStatsSnapshot) uint64 { return s.PCNtfRcvd }},
		"Close":        {pcep.MessageTypeClose, func(s sessionStatsSnapshot) uint64 { return s.CloseRcvd }},
		"Pcreq":        {pcep.MessageTypePcreq, func(s sessionStatsSnapshot) uint64 { return s.PCReqRcvd }},
		"Pcrep":        {pcep.MessageTypePcrep, func(s sessionStatsSnapshot) uint64 { return s.PCRepRcvd }},
		"Unknown":      {pcep.MessageTypeStartTLS, func(s sessionStatsSnapshot) uint64 { return s.UnknownRcvd }},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
			ss.countReceived(tt.messageType)
			assert.Equal(t, uint64(1), tt.get(ss.Stats()), "unexpected counter value for message type %s", name)
		})
	}
}

func TestCountReceived_CloseHasDedicatedCounter(t *testing.T) {
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, zap.NewNop(), nil, 0)
	ss.countReceived(pcep.MessageTypeClose)
	snap := ss.Stats()
	assert.Equal(t, uint64(1), snap.CloseRcvd)
	assert.Zero(t, snap.UnknownRcvd, "Close must not be counted as an unrecognized message")
	assert.Zero(t, snap.KeepaliveRcvd)
	assert.Zero(t, snap.RptRcvd)
	assert.Zero(t, snap.PCErrRcvd)
	assert.Zero(t, snap.PCNtfRcvd)
}

func TestSessionStats_CorruptRcvdOnMalformedPCErr(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	// A truncated object header cannot form a valid PCEP-ERROR object.
	malformedBody := []byte{0x00, 0x00}
	_, err := client.Write(malformedBody)
	require.NoError(t, err)

	err = ss.receivePCErr(pcep.CommonHeaderLength+uint16(len(malformedBody)), time.Time{})
	require.Error(t, err)
	assert.Equal(t, uint64(1), ss.Stats().CorruptRcvd)
}

func TestSessionStats_CorruptRcvdOnMalformedPCRpt(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	// A truncated object header cannot form a valid state report.
	malformedBody := []byte{0x00, 0x00}
	_, err := client.Write(malformedBody)
	require.NoError(t, err)

	err = ss.handlePCRpt(pcep.CommonHeaderLength+uint16(len(malformedBody)), time.Time{})
	require.Error(t, err)
	assert.Equal(t, uint64(1), ss.Stats().CorruptRcvd)
}

func TestSessionStats_CorruptRcvdOnMalformedCommonHeader(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, zap.NewNop(), nil, 0)

	// Version 0 is not a supported PCEP version.
	_, err := client.Write([]byte{0x00, 0x00, 0x00, 0x04})
	require.NoError(t, err)

	_, err = ss.readCommonHeader(time.Time{})
	require.Error(t, err)
	assert.Equal(t, uint64(1), ss.Stats().CorruptRcvd)
}

func TestServer_PeerSetupStats_RecordsOkAndFail(t *testing.T) {
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

	clientAddr, err := netip.ParseAddrPort(client.LocalAddr().String())
	require.NoError(t, err)
	peerAddr := clientAddr.Addr()

	// Establishment fails: the client disconnects before completing the Open handshake.
	require.NoError(t, client.Close())

	require.Eventually(t, func() bool {
		_, fail := s.PeerSetupStats(peerAddr)
		return fail == 1
	}, 2*time.Second, 10*time.Millisecond, "expected a failed establishment to be recorded")

	ok, fail := s.PeerSetupStats(peerAddr)
	assert.Equal(t, uint64(0), ok)
	assert.Equal(t, uint64(1), fail)
}

func TestServer_PeerSetupStats_RecordsOkOnSuccessfulEstablishment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close(), "failed to release the reserved port")

	s := &Server{logger: zap.NewNop(), localKeepalive: defaultLocalKeepalive, localDeadTimer: pcep.DeadTimerFor(defaultLocalKeepalive)}
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
	t.Cleanup(func() { _ = client.Close() })

	clientAddr, err := netip.ParseAddrPort(client.LocalAddr().String())
	require.NoError(t, err)
	peerAddr := clientAddr.Addr()

	writeMessage(t, client, pcep.NewOpenMessage(1, 30, 120, nil))
	require.NoError(t, readPCEPMessage(client), "failed to read Open reply")
	require.NoError(t, readPCEPMessage(client), "failed to read the Keepalive acknowledging the peer's Open")
	writeMessage(t, client, pcep.NewKeepaliveMessage())

	require.Eventually(t, func() bool {
		ok, _ := s.PeerSetupStats(peerAddr)
		return ok == 1
	}, 2*time.Second, 10*time.Millisecond, "expected a successful establishment to be recorded")

	ok, fail := s.PeerSetupStats(peerAddr)
	assert.Equal(t, uint64(1), ok)
	assert.Equal(t, uint64(0), fail)
}
