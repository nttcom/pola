// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"net/netip"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToPBSessionState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   SessionState
		want pb.SessionState
	}{
		{"TCPPending", SessionStateTCPPending, pb.SessionState_SESSION_STATE_TCP_PENDING},
		{"OpenWait", SessionStateOpenWait, pb.SessionState_SESSION_STATE_OPEN_WAIT},
		{"KeepWait", SessionStateKeepWait, pb.SessionState_SESSION_STATE_KEEP_WAIT},
		{"Up", SessionStateUp, pb.SessionState_SESSION_STATE_UP},
		{"unrecognized value maps to unspecified", SessionState(99), pb.SessionState_SESSION_STATE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, toPBSessionState(tt.in))
		})
	}
}

func TestToPBPccType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   pcep.PccType
		want pb.PccType
	}{
		{"CiscoLegacy", pcep.CiscoLegacy, pb.PccType_PCC_TYPE_CISCO_LEGACY},
		{"JuniperLegacy", pcep.JuniperLegacy, pb.PccType_PCC_TYPE_JUNIPER_LEGACY},
		{"RFCCompliant", pcep.RFCCompliant, pb.PccType_PCC_TYPE_RFC_COMPLIANT},
		{"unrecognized value maps to unspecified", pcep.PccType(99), pb.PccType_PCC_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, toPBPccType(tt.in))
		})
	}
}

func TestToPBInitiator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   SessionInitiator
		want pb.SessionInitiator
	}{
		{"Remote", SessionInitiatorRemote, pb.SessionInitiator_SESSION_INITIATOR_REMOTE},
		{"Local", SessionInitiatorLocal, pb.SessionInitiator_SESSION_INITIATOR_LOCAL},
		{"unrecognized value maps to unspecified", SessionInitiator(99), pb.SessionInitiator_SESSION_INITIATOR_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, toPBInitiator(tt.in))
		})
	}
}

func TestToPBSyncState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   SyncState
		want pb.LspDbSyncState
	}{
		{"Pending", SyncStatePending, pb.LspDbSyncState_LSP_DB_SYNC_STATE_PENDING},
		{"Ongoing", SyncStateOngoing, pb.LspDbSyncState_LSP_DB_SYNC_STATE_ONGOING},
		{"Finished", SyncStateFinished, pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED},
		{"unrecognized value maps to unspecified", SyncState(99), pb.LspDbSyncState_LSP_DB_SYNC_STATE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, toPBSyncState(tt.in))
		})
	}
}

func TestToPBSessionStats_AlwaysZeroCountersForRolesPolaNeverPlays(t *testing.T) {
	t.Parallel()

	stats := SessionStats{
		OpenSent: 20, OpenRcvd: 21,
		KeepaliveSent: 1, KeepaliveRcvd: 2,
		CloseSent: 22, CloseRcvd: 23,
		PCErrSent: 3, PCErrRcvd: 4,
		PCNtfRcvd: 5,
		PCReqRcvd: 24, PCRepRcvd: 25,
		RptRcvd: 6, UpdSent: 7, PCInitiateSent: 8,
		UnknownRcvd: 9, CorruptRcvd: 10,
	}

	got := toPBSessionStats(stats, 11, 12)

	assert.Equal(t, uint64(20), got.GetOpen().GetSent())
	assert.Equal(t, uint64(21), got.GetOpen().GetRcvd())
	assert.Equal(t, uint64(1), got.GetKeepalive().GetSent())
	assert.Equal(t, uint64(2), got.GetKeepalive().GetRcvd())
	assert.Equal(t, uint64(22), got.GetClose().GetSent())
	assert.Equal(t, uint64(23), got.GetClose().GetRcvd())
	assert.Equal(t, uint64(3), got.GetPcerr().GetSent())
	assert.Equal(t, uint64(4), got.GetPcerr().GetRcvd())
	assert.Equal(t, uint64(0), got.GetPcntf().GetSent(), "Pola never sends PCNtf")
	assert.Equal(t, uint64(5), got.GetPcntf().GetRcvd())
	assert.Equal(t, uint64(0), got.GetPcreq().GetSent(), "Pola never sends PCReq")
	assert.Equal(t, uint64(24), got.GetPcreq().GetRcvd())
	assert.Equal(t, uint64(0), got.GetPcrep().GetSent(), "Pola never sends PCRep")
	assert.Equal(t, uint64(25), got.GetPcrep().GetRcvd())
	assert.Equal(t, uint64(0), got.GetReport().GetSent(), "Pola never sends PCRpt")
	assert.Equal(t, uint64(6), got.GetReport().GetRcvd())
	assert.Equal(t, uint64(7), got.GetUpdate().GetSent())
	assert.Equal(t, uint64(0), got.GetUpdate().GetRcvd(), "Pola never receives PCUpd")
	assert.Equal(t, uint64(8), got.GetInitiate().GetSent())
	assert.Equal(t, uint64(0), got.GetInitiate().GetRcvd(), "Pola never receives PCInitiate")
	assert.Equal(t, uint64(9), got.GetUnrecognizedRcvd())
	assert.Equal(t, uint64(10), got.GetCorruptRcvd())
	assert.Equal(t, uint64(11), got.GetSessSetupOk())
	assert.Equal(t, uint64(12), got.GetSessSetupFail())
}

func TestBuildPBSession_StatsOmittedUnlessRequested(t *testing.T) {
	t.Parallel()

	server := &Server{logger: logger.NewNop()}
	apiServer := &APIServer{pce: server, logger: logger.NewNop()}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, logger.NewNop(), nil, 0)

	without := apiServer.buildPBSession(ss, false)
	assert.Nil(t, without.GetStats(), "Stats must be nil unless includeStats is set")

	with := apiServer.buildPBSession(ss, true)
	require.NotNil(t, with.GetStats(), "Stats must be populated when includeStats is set")
}

func TestBuildPBSession_TimestampsAndInitiatorAndSyncState(t *testing.T) {
	t.Parallel()

	apiServer := &APIServer{pce: &Server{logger: logger.NewNop()}, logger: logger.NewNop()}
	ss := NewSession(testLocalOpen(1), netip.MustParseAddr("10.0.255.1"), nil, logger.NewNop(), nil, 0)

	pbSession := apiServer.buildPBSession(ss, false)
	assert.NotZero(t, pbSession.GetCreatedAtUnixNano())
	assert.Zero(t, pbSession.GetEstablishedAtUnixNano(), "session has not reached Up yet")
	assert.Equal(t, pb.SessionInitiator_SESSION_INITIATOR_REMOTE, pbSession.GetInitiator())
	assert.Equal(t, pb.LspDbSyncState_LSP_DB_SYNC_STATE_PENDING, pbSession.GetSyncState())

	ss.setState(SessionStateUp)
	pbSession = apiServer.buildPBSession(ss, false)
	assert.NotZero(t, pbSession.GetEstablishedAtUnixNano())
}

func TestSessionListFilter(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("10.0.255.1")

	got, err := sessionListFilter(&pb.GetSessionListRequest{})
	require.NoError(t, err)
	assert.False(t, got.IsValid(), "no filter address means no filter")

	got, err = sessionListFilter(&pb.GetSessionListRequest{PeerAddr: addr.AsSlice()})
	require.NoError(t, err)
	assert.Equal(t, addr, got)

	_, err = sessionListFilter(&pb.GetSessionListRequest{PeerAddr: []byte{0x01, 0x02, 0x03}})
	assert.Error(t, err, "an address that is neither 4 nor 16 bytes must be rejected")
}
