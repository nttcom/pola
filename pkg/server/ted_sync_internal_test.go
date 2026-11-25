// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	syncTestSrc = netip.MustParseAddr("10.0.0.1")
	syncTestDst = netip.MustParseAddr("10.0.0.2")

	// Keep reported and computed segments distinct.
	reportedSegments = []table.Segment{table.NewSegmentSRMPLS(16002), table.NewSegmentSRMPLS(16003)}
	computedSegments = []table.Segment{table.NewSegmentSRMPLS(16002)}
)

func newSyncTestElems() []table.TEDElem {
	src, dst := newLinkedSRMPLSNodes(syncTestSrc, syncTestDst, 20)

	return []table.TEDElem{src, dst}
}

func newSyncTestReport(t *testing.T, plspID uint32) *pcep.StateReport {
	t.Helper()

	sr := newTestStateReport(t, plspID, 0)
	sr.LSPObject.SrcAddr = syncTestSrc
	sr.LSPObject.DstAddr = syncTestDst

	return sr
}

func newSyncTestServer() *Server {
	s := &Server{logger: logger.NewNop()}
	s.setTED(&table.LsTED{Nodes: map[string]*table.LsNode{}})

	return s
}

func newSyncTestSession(t *testing.T, s *Server) (*Session, net.Conn) {
	t.Helper()

	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, server.Close(), "failed to close server connection")
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), server, logger.NewNop(), s.TED(), 0)
	ss.tedSource = s.tedState
	ss.commitPeerOpen(OpenParams{SessionID: 1, Keepalive: 30, DeadTimer: 120}, pcep.RFCCompliant,
		[]pcep.CapabilityInterface{pcep.NewSRPCECapability(true, false, 0)})

	s.sessionMu.Lock()
	s.sessionList = append(s.sessionList, ss)
	s.sessionMu.Unlock()

	return ss, client
}

func startSyncLoop(t *testing.T, s *Server) chan []table.TEDElem {
	t.Helper()

	ch := make(chan []table.TEDElem)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		s.syncTEDLoop(ctx, ch, 65000)
		close(done)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	return ch
}

func requireSegments(t *testing.T, ss *Session, plspID uint32, want []table.Segment) {
	t.Helper()

	policy, found := ss.SearchSRPolicy(plspID)
	require.True(t, found, "SR Policy %d is not registered", plspID)
	assert.Equal(t, want, policy.SegmentList)
}

func requireNoPCEPMessage(t *testing.T, c net.Conn) {
	t.Helper()

	require.NoError(t, c.SetReadDeadline(time.Now().Add(50*time.Millisecond)))

	buf := make([]byte, 1)
	_, err := c.Read(buf)

	var ne net.Error

	require.ErrorAs(t, err, &ne)
	assert.True(t, ne.Timeout(), "expected no PCEP message, got %v", err)
	require.NoError(t, c.SetReadDeadline(time.Time{}))
}

// readPCEPWithTimeout prevents tests from hanging when no message arrives.
func readPCEPWithTimeout(t *testing.T, c net.Conn) error {
	t.Helper()

	require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))

	err := readPCEPMessage(c)

	require.NoError(t, c.SetReadDeadline(time.Time{}))

	return err
}

func pendingCount(ss *Session) int {
	ss.pendingMu.Lock()
	defer ss.pendingMu.Unlock()

	return len(ss.pendingRecompute)
}

// Defer reports received before the initial TED synchronization.
func TestTEDInitialSync_SessionBeforeSync(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)
	ch := startSyncLoop(t, s)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()),
		"a report received before TED sync must not fail")
	requireSegments(t, ss, 1, reportedSegments)
	assert.Equal(t, 1, pendingCount(ss))
	requireNoPCEPMessage(t, client)

	ch <- newSyncTestElems()

	require.NoError(t, readPCEPWithTimeout(t, client), "expected a PCUpd once the TED is synchronized")
	requireSegments(t, ss, 1, computedSegments)
	assert.Zero(t, pendingCount(ss))
}

func TestTEDInitialSync_SyncBeforeSession(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ch := startSyncLoop(t, s)

	ch <- newSyncTestElems()

	require.Eventually(t, func() bool { _, ready := s.tedState(); return ready }, 2*time.Second, time.Millisecond)

	ss, client := newSyncTestSession(t, s)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))
	require.NoError(t, readPCEPWithTimeout(t, client))
	requireSegments(t, ss, 1, computedSegments)
	assert.Zero(t, pendingCount(ss))
}

// A session must use the current TED rather than its initial snapshot.
func TestTEDInitialSync_SessionSeesLiveTED(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)
	ch := startSyncLoop(t, s)

	ch <- newSyncTestElems()

	require.Eventually(t, func() bool { _, ready := s.tedState(); return ready }, 2*time.Second, time.Millisecond)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))
	require.NoError(t, readPCEPWithTimeout(t, client))
	requireSegments(t, ss, 1, computedSegments)
}

func TestTEDInitialSync_TEDDisabled(t *testing.T) {
	t.Parallel()

	s := &Server{logger: logger.NewNop()}
	ss, client := newSyncTestSession(t, s)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))
	requireSegments(t, ss, 1, reportedSegments)
	assert.Zero(t, pendingCount(ss))
	requireNoPCEPMessage(t, client)

	ss.recomputePending()
	requireNoPCEPMessage(t, client)
}

// Only the latest report per PLSP-ID is recomputed.
func TestTEDInitialSync_RecomputesLatestReportPerLSP(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)
	ch := startSyncLoop(t, s)

	first := newSyncTestReport(t, 1)
	second := newSyncTestReport(t, 1)
	second.LSPObject.LSPID = 2

	for _, sr := range []*pcep.StateReport{first, second, newSyncTestReport(t, 2)} {
		require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
	}

	assert.Equal(t, 2, pendingCount(ss))

	ch <- newSyncTestElems()

	require.NoError(t, readPCEPWithTimeout(t, client))
	require.NoError(t, readPCEPWithTimeout(t, client))
	requireNoPCEPMessage(t, client)
	requireSegments(t, ss, 1, computedSegments)
	requireSegments(t, ss, 2, computedSegments)
}

// A removed LSP must not be recomputed after TED synchronization.
func TestTEDInitialSync_RemovedLSPIsNotRecomputed(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)
	ch := startSyncLoop(t, s)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))

	removal := newSyncTestReport(t, 1)
	removal.LSPObject.RFlag = true
	require.NoError(t, ss.handleStateReport(removal, pcep.NewPCRptMessage()))
	assert.Zero(t, pendingCount(ss))

	ch <- newSyncTestElems()

	require.Eventually(t, func() bool { _, ready := s.tedState(); return ready }, 2*time.Second, time.Millisecond)
	requireNoPCEPMessage(t, client)

	_, found := ss.SearchSRPolicy(1)
	assert.False(t, found)
}

// An explicit path must be preserved during TED synchronization.
func TestTEDInitialSync_ExplicitPathIsNotRecomputed(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))

	ss.srPoliciesMu.Lock()
	ss.srPolicies[0].CandidatePath = table.CandidatePath{Explicit: &table.ExplicitPath{}}
	ss.srPoliciesMu.Unlock()

	s.applyTEDSnapshot(syncedTED(t))
	ss.recomputePending()

	requireNoPCEPMessage(t, client)
	requireSegments(t, ss, 1, reportedSegments)
}

// Only the first snapshot is the initial synchronization.
func TestServer_ApplyTEDSnapshot_InitialOnce(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	_, ready := s.tedState()
	require.False(t, ready, "NewPCE starts with a TED that is not synchronized")

	assert.True(t, s.applyTEDSnapshot(syncedTED(t)))
	assert.False(t, s.applyTEDSnapshot(syncedTED(t)))

	_, ready = s.tedState()
	assert.True(t, ready)
}

// Deferred reports are retained until the TED is ready.
func TestSession_RecomputePending_WaitsForReadyTED(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))

	ss.recomputePending()

	assert.Equal(t, 1, pendingCount(ss))
	requireNoPCEPMessage(t, client)
}

// Concurrent TED synchronization and PCRpt handling must not lose reports.
func TestTEDInitialSync_ConcurrentReportAndSync(t *testing.T) {
	t.Parallel()

	for range 50 {
		s := newSyncTestServer()
		ss, client := newSyncTestSession(t, s)
		ch := startSyncLoop(t, s)

		var wg sync.WaitGroup

		wg.Go(func() {
			assert.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))
		})

		wg.Go(func() {
			ch <- newSyncTestElems()
		})

		wg.Wait()

		require.NoError(t, readPCEPWithTimeout(t, client), "the report must be computed whichever side won the race")
		require.Eventually(t, func() bool {
			p, ok := ss.SearchSRPolicy(1)
			return ok && len(p.SegmentList) == len(computedSegments)
		}, 2*time.Second, time.Millisecond)
	}
}

func syncedTED(t *testing.T) *table.LsTED {
	t.Helper()

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	ted.Update(newSyncTestElems(), 65000)

	return ted
}

// A failed recomputation must not prevent processing subsequent reports.
func TestSession_RecomputePending_FailureDoesNotStopOthers(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)

	unroutable := newSyncTestReport(t, 1)
	unroutable.LSPObject.DstAddr = netip.MustParseAddr("192.0.2.99")

	require.NoError(t, ss.handleStateReport(unroutable, pcep.NewPCRptMessage()))
	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 2), pcep.NewPCRptMessage()))

	s.applyTEDSnapshot(syncedTED(t))
	ss.recomputePending()

	require.NoError(t, readPCEPWithTimeout(t, client))
	requireNoPCEPMessage(t, client)
	requireSegments(t, ss, 1, reportedSegments)
	requireSegments(t, ss, 2, computedSegments)
	assert.Zero(t, pendingCount(ss))
}

func TestSession_DropPendingRecompute_KeepsNewerPending(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, _ := newSyncTestSession(t, s)

	newer := newSyncTestReport(t, 1)
	newer.LSPObject.LSPID = 5
	require.NoError(t, ss.handleStateReport(newer, pcep.NewPCRptMessage()))
	require.Equal(t, 1, pendingCount(ss))

	stale := newSyncTestReport(t, 1)
	stale.LSPObject.LSPID = 3
	ss.dropPendingRecompute(stale)

	assert.Equal(t, 1, pendingCount(ss), "a stale report must not remove the newer pending report")

	ss.pendingMu.Lock()
	kept := ss.pendingRecompute[1]
	ss.pendingMu.Unlock()
	require.NotNil(t, kept)
	assert.Equal(t, uint16(5), kept.LSPObject.LSPID)
}

func TestSession_StatefulAck_ClearsPendingRecompute(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, _ := newSyncTestSession(t, s)

	require.NoError(t, ss.handleStateReport(newSyncTestReport(t, 1), pcep.NewPCRptMessage()))
	require.Equal(t, 1, pendingCount(ss))

	ack := newSyncTestReport(t, 1)
	ack.SrpObject.SrpID = 7
	require.NoError(t, ss.handleStateReport(ack, pcep.NewPCRptMessage()))

	assert.Zero(t, pendingCount(ss))
}

func TestDelegatedSRPolicyWithEmptyEROAwaitsBothSynchronizations(t *testing.T) {
	t.Parallel()

	for _, tedFirst := range []bool{true, false} {
		name := "LSP database first"
		if tedFirst {
			name = "TED first"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newSyncTestServer()
			ss, client := newSyncTestSession(t, s)
			ch := startSyncLoop(t, s)
			sr := newSyncTestReport(t, 1)
			sr.LSPObject.DFlag = true
			sr.LSPObject.SFlag = true
			sr.LSPObject.OFlag = 0
			sr.EroObject.EroSubobjects = nil

			require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
			requireSegments(t, ss, 1, []table.Segment{})
			assert.Equal(t, 1, pendingCount(ss))

			syncTED := func() {

				ch <- newSyncTestElems()

				require.Eventually(t, func() bool { _, ready := s.tedState(); return ready }, time.Second, time.Millisecond)
			}
			finishReports := func() {
				marker := pcep.NewStateReport()
				require.NoError(t, ss.handleStateReport(marker, pcep.NewPCRptMessage()))
			}

			if tedFirst {
				syncTED()
				requireNoPCEPMessage(t, client)
				finishReports()
			} else {
				finishReports()
				requireNoPCEPMessage(t, client)
				syncTED()
			}

			require.NoError(t, readPCEPWithTimeout(t, client))
			assert.Equal(t, uint64(1), ss.Stats().UpdSent)
			requireSegments(t, ss, 1, computedSegments)
			assert.Zero(t, pendingCount(ss))
		})
	}
}

func TestSyncReportCanRevokePendingDelegation(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)
	ch := startSyncLoop(t, s)

	ch <- newSyncTestElems()

	require.Eventually(t, func() bool { _, ready := s.tedState(); return ready }, time.Second, time.Millisecond)

	sr := newSyncTestReport(t, 1)
	sr.LSPObject.DFlag = true
	sr.LSPObject.SFlag = true
	sr.LSPObject.OFlag = 0
	sr.EroObject.EroSubobjects = nil
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
	assert.Equal(t, 1, pendingCount(ss))

	revocation := newSyncTestReport(t, 1)
	revocation.LSPObject.SFlag = true
	require.NoError(t, ss.handleStateReport(revocation, pcep.NewPCRptMessage()))
	assert.Zero(t, pendingCount(ss))

	require.NoError(t, ss.handleStateReport(pcep.NewStateReport(), pcep.NewPCRptMessage()))
	requireNoPCEPMessage(t, client)
}

func TestDelegationRevokedAfterLSPSyncWhileTEDIsPending(t *testing.T) {
	t.Parallel()

	s := newSyncTestServer()
	ss, client := newSyncTestSession(t, s)
	ch := startSyncLoop(t, s)
	sr := newSyncTestReport(t, 1)
	sr.LSPObject.DFlag = true
	sr.LSPObject.SFlag = true
	sr.LSPObject.OFlag = 0
	sr.EroObject.EroSubobjects = nil
	require.NoError(t, ss.handleStateReport(sr, pcep.NewPCRptMessage()))
	require.NoError(t, ss.handleStateReport(pcep.NewStateReport(), pcep.NewPCRptMessage()))
	assert.Equal(t, 1, pendingCount(ss))

	revocation := newSyncTestReport(t, 1)
	require.NoError(t, ss.handleStateReport(revocation, pcep.NewPCRptMessage()))
	assert.Zero(t, pendingCount(ss))

	ch <- newSyncTestElems()

	require.Eventually(t, func() bool { _, ready := s.tedState(); return ready }, time.Second, time.Millisecond)
	requireNoPCEPMessage(t, client)
}
