// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package grpc

import (
	"context"
	"encoding/json"
	"math"
	"net/netip"
	"testing"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	testIPv4Addr1  = "192.0.2.1"
	testIPv4Addr2  = "192.0.2.2"
	testPrefix     = "10.0.0.1/32"
	testRouterID1  = "0000.0aff.0001"
	testRouterID2  = "0000.0aff.0002"
	testPolicyName = "pol1"
)

type fakeClient struct {
	pb.PCEServiceClient

	sessionListResp *pb.GetSessionListResponse
	sessionListErr  error
	sessionListReq  *pb.GetSessionListRequest

	deleteSessionErr error

	srPolicyListResp *pb.GetSRPolicyListResponse
	srPolicyListErr  error

	createSRPolicyErr error
	deleteSRPolicyErr error

	tedResp *pb.GetTEDResponse
	tedErr  error
}

func (f *fakeClient) GetSessionList(_ context.Context, req *pb.GetSessionListRequest, _ ...grpc.CallOption) (*pb.GetSessionListResponse, error) {
	f.sessionListReq = req
	return f.sessionListResp, f.sessionListErr
}

func (f *fakeClient) DeleteSession(_ context.Context, _ *pb.DeleteSessionRequest, _ ...grpc.CallOption) (*pb.DeleteSessionResponse, error) {
	if f.deleteSessionErr != nil {
		return nil, f.deleteSessionErr
	}
	return &pb.DeleteSessionResponse{}, nil
}

func (f *fakeClient) GetSRPolicyList(_ context.Context, _ *pb.GetSRPolicyListRequest, _ ...grpc.CallOption) (*pb.GetSRPolicyListResponse, error) {
	return f.srPolicyListResp, f.srPolicyListErr
}

func (f *fakeClient) CreateSRPolicy(_ context.Context, _ *pb.CreateSRPolicyRequest, _ ...grpc.CallOption) (*pb.CreateSRPolicyResponse, error) {
	if f.createSRPolicyErr != nil {
		return nil, f.createSRPolicyErr
	}
	return &pb.CreateSRPolicyResponse{}, nil
}

func (f *fakeClient) DeleteSRPolicy(_ context.Context, _ *pb.DeleteSRPolicyRequest, _ ...grpc.CallOption) (*pb.DeleteSRPolicyResponse, error) {
	if f.deleteSRPolicyErr != nil {
		return nil, f.deleteSRPolicyErr
	}
	return &pb.DeleteSRPolicyResponse{}, nil
}

func (f *fakeClient) GetTED(_ context.Context, _ *pb.GetTEDRequest, _ ...grpc.CallOption) (*pb.GetTEDResponse, error) {
	return f.tedResp, f.tedErr
}

// sid_index presence must distinguish index 0 from an absent Prefix-SID.
func TestCreateLsPrefix_SidIndexPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		prefix          *pb.LsPrefix
		wantSidIndex    uint32
		wantHasSidIndex bool
	}{
		{
			name:            "no Prefix-SID",
			prefix:          &pb.LsPrefix{Prefix: testPrefix},
			wantSidIndex:    0,
			wantHasSidIndex: false,
		},
		{
			name:            "Prefix-SID index 0",
			prefix:          &pb.LsPrefix{Prefix: testPrefix, SidIndex: proto.Uint32(0)},
			wantSidIndex:    0,
			wantHasSidIndex: true,
		},
		{
			name:            "Prefix-SID index 16000",
			prefix:          &pb.LsPrefix{Prefix: testPrefix, SidIndex: proto.Uint32(16000)},
			wantSidIndex:    16000,
			wantHasSidIndex: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lsPrefix, err := createLsPrefix(table.NewLsNode(65000, "0000.0000.0001"), tt.prefix)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSidIndex, lsPrefix.SidIndex)
			assert.Equal(t, tt.wantHasSidIndex, lsPrefix.HasSidIndex)
			assert.Equal(t, tt.wantHasSidIndex, lsPrefix.HasPrefixSID())
		})
	}
}

func TestCreateLsPrefix_InvalidPrefix(t *testing.T) {
	t.Parallel()

	_, err := createLsPrefix(table.NewLsNode(65000, "0000.0000.0001"), &pb.LsPrefix{Prefix: "not-a-prefix"})
	require.Error(t, err)
}

func TestSegmentFromPB_SRMPLS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		localAddr  string
		remoteAddr string
	}{
		{name: "localAddr only", localAddr: testIPv4Addr1},
		{name: "remoteAddr only", remoteAddr: testIPv4Addr2},
		{name: "localAddr and remoteAddr", localAddr: testIPv4Addr1, remoteAddr: testIPv4Addr2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			seg, err := segmentFromPB(&pb.Segment{
				Sid:        "16003",
				LocalAddr:  tt.localAddr,
				RemoteAddr: tt.remoteAddr,
			})
			require.NoError(t, err)

			mplsSeg, ok := seg.(table.SegmentSRMPLS)
			require.Truef(t, ok, "segment type: got %T, want table.SegmentSRMPLS", seg)
			assert.Equal(t, "16003", mplsSeg.SidString())
			if tt.localAddr == "" {
				assert.False(t, mplsSeg.LocalAddr.IsValid())
			} else {
				assert.Equal(t, tt.localAddr, mplsSeg.LocalAddr.String())
			}
			if tt.remoteAddr == "" {
				assert.False(t, mplsSeg.RemoteAddr.IsValid())
			} else {
				assert.Equal(t, tt.remoteAddr, mplsSeg.RemoteAddr.String())
			}
		})
	}
}

func TestSegmentFromPB_SRMPLS_SidAbsent(t *testing.T) {
	t.Parallel()

	seg, err := segmentFromPB(&pb.Segment{
		Sid:       "0",
		LocalAddr: testIPv4Addr1,
		SidAbsent: true,
	})
	require.NoError(t, err)

	mplsSeg, ok := seg.(table.SegmentSRMPLS)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRMPLS", seg)
	assert.True(t, mplsSeg.SidAbsent)
	assert.Equal(t, testIPv4Addr1, mplsSeg.LocalAddr.String())
}

func TestSegmentFromPB_SRv6(t *testing.T) {
	t.Parallel()

	seg, err := segmentFromPB(&pb.Segment{
		Sid:          "2001:db8:1005::",
		LocalAddr:    "2001:db8::5",
		RemoteAddr:   "2001:db8::6",
		SidStructure: "32,16,0,80",
	})
	require.NoError(t, err)

	srv6Seg, ok := seg.(table.SegmentSRv6)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRv6", seg)
	assert.Equal(t, "2001:db8:1005::", srv6Seg.SidString())
	assert.Equal(t, "2001:db8::5", srv6Seg.LocalAddr.String())
	assert.Equal(t, "2001:db8::6", srv6Seg.RemoteAddr.String())
	assert.Equal(t, table.SIDStructureBytes{32, 16, 0, 80}, srv6Seg.Structure)
}

func TestSegmentFromPB_InvalidSID(t *testing.T) {
	t.Parallel()

	_, err := segmentFromPB(&pb.Segment{Sid: "not-a-sid"})
	require.Error(t, err)
}

func TestSegmentFromPB_InvalidAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		segment *pb.Segment
	}{
		{
			name:    "SRv6 invalid local address",
			segment: &pb.Segment{Sid: "2001:db8:1005::", LocalAddr: "not-an-addr", RemoteAddr: "2001:db8::6"},
		},
		{
			name:    "SRv6 invalid remote address",
			segment: &pb.Segment{Sid: "2001:db8:1005::", LocalAddr: "2001:db8::5", RemoteAddr: "not-an-addr"},
		},
		{
			name:    "SR-MPLS invalid local address",
			segment: &pb.Segment{Sid: "16003", LocalAddr: "not-an-addr", RemoteAddr: testIPv4Addr2},
		},
		{
			name:    "SR-MPLS invalid remote address",
			segment: &pb.Segment{Sid: "16003", LocalAddr: testIPv4Addr1, RemoteAddr: "not-an-addr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := segmentFromPB(tt.segment)
			require.Error(t, err)
		})
	}
}

func TestParseSidStructure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    []uint8
		wantErr bool
	}{
		{name: "empty returns nil", in: "", want: nil},
		{name: "valid", in: "32,16,0,80", want: []uint8{32, 16, 0, 80}},
		{name: "wrong part count", in: "32,16,0", wantErr: true},
		{name: "non-numeric part", in: "32,16,0,xx", wantErr: true},
		{name: "value out of uint8 range", in: "32,16,0,256", wantErr: true},
		{name: "sum exceeds 128 bits", in: "128,128,0,0", wantErr: true},
		{name: "whitespace around parts is trimmed", in: " 32 , 16 , 0 , 80 ", want: []uint8{32, 16, 0, 80}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSidStructure(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSegmentFromPB_InvalidSidStructure(t *testing.T) {
	t.Parallel()

	_, err := segmentFromPB(&pb.Segment{
		Sid:          "2001:db8:1005::",
		SidStructure: "32,16,0",
	})
	require.Error(t, err)
}

func TestGetSessions_NoCapabilitiesIsEmptySlice(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				PeerAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:    pb.SessionState_SESSION_STATE_UP,
			},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	assert.Equal(t, "up", sessions[0].State)

	require.NotNil(t, sessions[0].LocalCapabilities)
	assert.Empty(t, sessions[0].LocalCapabilities)

	marshaled, err := json.Marshal(sessions[0])
	require.NoError(t, err)
	assert.Contains(t, string(marshaled), `"LocalCapabilities":[]`)
}

func TestGetSessions_WithCapabilities(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				PeerAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:    pb.SessionState_SESSION_STATE_UP,
				LocalCapabilities: []*pb.Capability{
					{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: proto.Uint32(10)}}},
				},
			},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, []Capability{{Type: "SR", Detail: SRCapability{MSD: proto.Uint32(10)}}}, sessions[0].LocalCapabilities)
}

func TestGetSessions_WithPccCapabilities(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				PeerAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:    pb.SessionState_SESSION_STATE_UP,
				PeerCapabilities: []*pb.Capability{
					{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: proto.Uint32(10)}}},
				},
			},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, []Capability{{Type: "SR", Detail: SRCapability{MSD: proto.Uint32(10)}}}, sessions[0].PeerCapabilities)
}

func TestGetSessions_WithSessionIDsAndTimers(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				PeerAddr:       netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:          pb.SessionState_SESSION_STATE_UP,
				LocalSessionId: proto.Uint32(1),
				PeerSessionId:  proto.Uint32(2),
				LocalTimers:    &pb.SessionTimers{Keepalive: 30, DeadTimer: 120},
				PeerTimers:     &pb.SessionTimers{Keepalive: 10, DeadTimer: 40},
			},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	require.NotNil(t, sessions[0].LocalSessionID)
	assert.Equal(t, uint32(1), *sessions[0].LocalSessionID)
	require.NotNil(t, sessions[0].PeerSessionID)
	assert.Equal(t, uint32(2), *sessions[0].PeerSessionID)
	require.NotNil(t, sessions[0].LocalTimers)
	assert.Equal(t, SessionTimers{Keepalive: 30, DeadTimer: 120}, *sessions[0].LocalTimers)
	require.NotNil(t, sessions[0].PeerTimers)
	assert.Equal(t, SessionTimers{Keepalive: 10, DeadTimer: 40}, *sessions[0].PeerTimers)
}

func TestGetSessions_EffectiveTimersIgnoredBeforeUp(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				PeerAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:    pb.SessionState_SESSION_STATE_KEEP_WAIT,
				// A well-behaved server leaves EffectiveTimers nil before Up,
				// but the client must not trust that convention blindly.
				EffectiveTimers: &pb.EffectiveTimers{Keepalive: 30, DeadTimer: 120},
			},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, EffectiveTimers{}, sessions[0].EffectiveTimers)
}

func TestGetSessions_EffectiveTimersPopulatedWhenUp(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				PeerAddr:        netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:           pb.SessionState_SESSION_STATE_UP,
				EffectiveTimers: &pb.EffectiveTimers{Keepalive: 30, DeadTimer: 120},
			},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	assert.NotNil(t, sessions[0].EffectiveTimers.Keepalive)
	assert.Equal(t, uint32(30), *sessions[0].EffectiveTimers.Keepalive)
	assert.NotNil(t, sessions[0].EffectiveTimers.DeadTimer)
	assert.Equal(t, uint32(120), *sessions[0].EffectiveTimers.DeadTimer)
}

func TestGetSessions_TimestampsInitiatorSyncStateAndStats(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				PeerAddr:              netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:                 pb.SessionState_SESSION_STATE_UP,
				Initiator:             pb.SessionInitiator_SESSION_INITIATOR_REMOTE,
				SyncState:             pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED,
				CreatedAtUnixNano:     1000,
				EstablishedAtUnixNano: 2000,
				Stats: &pb.SessionStats{
					Keepalive:        &pb.MessageCounter{Sent: 1, Rcvd: 2},
					Pcerr:            &pb.MessageCounter{Sent: 3, Rcvd: 4},
					Pcntf:            &pb.MessageCounter{Rcvd: 5},
					Report:           &pb.MessageCounter{Rcvd: 6},
					Update:           &pb.MessageCounter{Sent: 7},
					Initiate:         &pb.MessageCounter{Sent: 8},
					UnrecognizedRcvd: 9,
					CorruptRcvd:      10,
					SessSetupOk:      11,
					SessSetupFail:    12,
				},
			},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, true)
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	ss := sessions[0]
	assert.Equal(t, "remote", ss.Initiator)
	assert.Equal(t, "finished", ss.SyncState)
	assert.Equal(t, time.Unix(0, 1000), ss.CreatedAt)
	assert.Equal(t, time.Unix(0, 2000), ss.EstablishedAt)

	require.NotNil(t, ss.Stats)
	assert.Equal(t, MessageCounter{Sent: 1, Rcvd: 2}, ss.Stats.Keepalive)
	assert.Equal(t, MessageCounter{Sent: 3, Rcvd: 4}, ss.Stats.PCErr)
	assert.Equal(t, MessageCounter{Sent: 0, Rcvd: 5}, ss.Stats.PCNtf)
	assert.Equal(t, MessageCounter{Sent: 0, Rcvd: 6}, ss.Stats.Report)
	assert.Equal(t, MessageCounter{Sent: 7, Rcvd: 0}, ss.Stats.Update)
	assert.Equal(t, MessageCounter{Sent: 8, Rcvd: 0}, ss.Stats.Initiate)
	assert.Equal(t, uint64(9), ss.Stats.UnrecognizedRcvd)
	assert.Equal(t, uint64(10), ss.Stats.CorruptRcvd)
	assert.Equal(t, uint64(11), ss.Stats.SessSetupOK)
	assert.Equal(t, uint64(12), ss.Stats.SessSetupFail)
}

func TestInitiatorFromPB(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   pb.SessionInitiator
		want string
	}{
		"local":       {pb.SessionInitiator_SESSION_INITIATOR_LOCAL, "local"},
		"remote":      {pb.SessionInitiator_SESSION_INITIATOR_REMOTE, "remote"},
		"unspecified": {pb.SessionInitiator_SESSION_INITIATOR_UNSPECIFIED, unknownDisplayValue},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, initiatorFromPB(tt.in))
		})
	}
}

func TestSyncStateFromPB(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   pb.LspDbSyncState
		want string
	}{
		"pending":     {pb.LspDbSyncState_LSP_DB_SYNC_STATE_PENDING, "pending"},
		"ongoing":     {pb.LspDbSyncState_LSP_DB_SYNC_STATE_ONGOING, "ongoing"},
		"finished":    {pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED, "finished"},
		"unspecified": {pb.LspDbSyncState_LSP_DB_SYNC_STATE_UNSPECIFIED, unknownDisplayValue},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, syncStateFromPB(tt.in))
		})
	}
}

func TestSessionStateFromPB(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   pb.SessionState
		want string
	}{
		"up":          {pb.SessionState_SESSION_STATE_UP, "up"},
		"tcp-pending": {pb.SessionState_SESSION_STATE_TCP_PENDING, "tcp-pending"},
		"open-wait":   {pb.SessionState_SESSION_STATE_OPEN_WAIT, "open-wait"},
		"keep-wait":   {pb.SessionState_SESSION_STATE_KEEP_WAIT, "keep-wait"},
		"unspecified": {pb.SessionState_SESSION_STATE_UNSPECIFIED, unknownDisplayValue},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, sessionStateFromPB(tt.in))
		})
	}
}

func TestGetSessions_ZeroTimestampsAndUnsetEnumsStayZero(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{PeerAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(), State: pb.SessionState_SESSION_STATE_OPEN_WAIT},
		},
	}}

	sessions, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	ss := sessions[0]
	assert.Equal(t, unknownDisplayValue, ss.Initiator)
	assert.Equal(t, unknownDisplayValue, ss.SyncState)
	assert.True(t, ss.CreatedAt.IsZero())
	assert.True(t, ss.EstablishedAt.IsZero())
	assert.Nil(t, ss.Stats)
}

func TestGetSessions_PassesFilterAddrAndIncludeStats(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{}}
	addr := netip.MustParseAddr(testIPv4Addr1)

	_, err := GetSessions(client, addr, true)
	require.NoError(t, err)

	require.NotNil(t, client.sessionListReq)
	assert.Equal(t, addr.AsSlice(), client.sessionListReq.GetPeerAddr())
	assert.True(t, client.sessionListReq.GetIncludeStats())
}

func TestGetSessions_NoFilterAddrLeavesSessionAddrEmpty(t *testing.T) {
	t.Parallel()

	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{}}

	_, err := GetSessions(client, netip.Addr{}, false)
	require.NoError(t, err)

	require.NotNil(t, client.sessionListReq)
	assert.Empty(t, client.sessionListReq.GetPeerAddr())
	assert.False(t, client.sessionListReq.GetIncludeStats())
}

func TestGetSessions_Errors(t *testing.T) {
	t.Parallel()

	t.Run("client error propagates", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{sessionListErr: assert.AnError}
		_, err := GetSessions(client, netip.Addr{}, false)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("malformed session address", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
			Sessions: []*pb.Session{{PeerAddr: []byte{1, 2, 3}}},
		}}
		_, err := GetSessions(client, netip.Addr{}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session address")
	})
}

func TestDeleteSession(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{}
		err := DeleteSession(client, &pb.DeleteSessionRequest{PeerAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice()})
		require.NoError(t, err)
	})

	t.Run("error propagates", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{deleteSessionErr: assert.AnError}
		err := DeleteSession(client, &pb.DeleteSessionRequest{})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestCapabilityDetail_Strings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		detail capabilityDetail
		want   []string
	}{
		{
			name: "Stateful with every RFC 8231/8232 flag set",
			detail: StatefulCapability{
				LSPUpdate: true, IncludeDBVersion: true, LSPInstantiation: true,
				TriggeredResync: true, DeltaLSPSync: true, TriggeredInitialSync: true, Color: true,
			},
			want: []string{"Stateful", "Update", "Include-DB-Ver", "Instantiation", "Triggered-Resync", "Delta-LSP-Sync", "Triggered-Initial-Sync", "Color"},
		},
		{name: "Stateful with no flags", detail: StatefulCapability{}, want: []string{"Stateful"}},
		{name: "SR unlimited MSD with NAI support", detail: SRCapability{UnlimitedMSD: true, NAISupported: true}, want: []string{"SR", "Unlimited-SID-Depth", "SR-NAI-Supported"}},
		{name: "SR bounded MSD without NAI support", detail: SRCapability{MSD: proto.Uint32(10)}, want: []string{"SR", "MSD=10"}},
		{name: "SR MSD advertised as zero", detail: SRCapability{MSD: proto.Uint32(0)}, want: []string{"SR", "MSD=0"}},
		{name: "SR MSD not advertised", detail: SRCapability{}, want: []string{"SR"}},
		{name: "SRv6 with NAI support", detail: SRv6Capability{NAISupported: true}, want: []string{"SRv6", "SRv6-NAI-Supported"}},
		{name: "SRv6 without NAI support", detail: SRv6Capability{}, want: []string{"SRv6"}},
		{name: "PathSetupType SR-TE (1) and SRv6-TE (3)", detail: PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}, want: []string{"SR-TE", "SRv6-TE"}},
		{name: "PathSetupType unrecognized value is omitted", detail: PathSetupTypeCapability{PathSetupTypes: []uint32{99}}, want: nil},
		{name: "AssocTypeList", detail: AssocTypeListCapability{AssocTypes: []uint32{6, 7}}, want: []string{"AssocType:6", "AssocType:7"}},
		{name: "LSPDBVersion", detail: LSPDBVersionCapability{VersionNumber: 5}, want: []string{"LSP-DB-VERSION"}},
		{
			name:   "Multipath with every RFC 8751 flag set",
			detail: MultipathCapability{MaxMultipaths: 4, Weighted: true, OppositeDir: true, ForwardClass: true, CompositePath: true},
			want:   []string{"Multipath", "MaxMultipaths=4", "Weighted", "OppositeDir", "ForwardClass", "CompositePath"},
		},
		{name: "Multipath with no flags", detail: MultipathCapability{MaxMultipaths: 2}, want: []string{"Multipath", "MaxMultipaths=2"}},
		{name: "VendorInformation known PEN", detail: VendorInformationCapability{EnterpriseNumber: 9}, want: []string{"9 (Cisco Systems, Inc.)"}},
		{name: "VendorInformation unknown PEN", detail: VendorInformationCapability{EnterpriseNumber: 99999}, want: []string{"99999 (Unknown)"}},
		{name: "Unknown TLV", detail: UnknownCapability{TLVType: 42}, want: []string{"unknown_type_42"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.detail.Strings())
		})
	}
}

func TestCapability_Strings(t *testing.T) {
	t.Parallel()

	t.Run("nil Detail falls back to type token", func(t *testing.T) {
		t.Parallel()
		capability := Capability{Type: "VENDOR_INFORMATION"}
		assert.Equal(t, []string{"VENDOR_INFORMATION"}, capability.Strings())
	})

	t.Run("typed Detail is unaffected", func(t *testing.T) {
		t.Parallel()
		capability := Capability{Type: "SR", Detail: SRCapability{MSD: proto.Uint32(10)}}
		assert.Equal(t, []string{"SR", "MSD=10"}, capability.Strings())
	})
}

func TestCapabilityFromPB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		pbCap *pb.Capability
		want  Capability
	}{
		{
			name:  "Stateful",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_STATEFUL, Detail: &pb.Capability_Stateful{Stateful: &pb.StatefulCapability{LspUpdate: true, Color: true}}},
			want:  Capability{Type: "STATEFUL", Detail: StatefulCapability{LSPUpdate: true, Color: true}},
		},
		{
			name:  "SR",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{UnlimitedMsd: true, NaiSupported: true, Msd: proto.Uint32(5)}}},
			want:  Capability{Type: "SR", Detail: SRCapability{UnlimitedMSD: true, NAISupported: true, MSD: proto.Uint32(5)}},
		},
		{
			name:  "SRv6",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_SRV6, Detail: &pb.Capability_Srv6{Srv6: &pb.Srv6Capability{NaiSupported: true}}},
			want:  Capability{Type: "SRV6", Detail: SRv6Capability{NAISupported: true}},
		},
		{
			name:  "PathSetupType",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_PATH_SETUP_TYPE, Detail: &pb.Capability_PathSetupType{PathSetupType: &pb.PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}}},
			want:  Capability{Type: "PATH_SETUP_TYPE", Detail: PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}},
		},
		{
			name: "PathSetupType with SR/SRv6 sub-capabilities",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_PATH_SETUP_TYPE, Detail: &pb.Capability_PathSetupType{PathSetupType: &pb.PathSetupTypeCapability{
				PathSetupTypes: []uint32{1, 3},
				SubCapabilities: []*pb.Capability{
					{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{UnlimitedMsd: true}}},
					{Type: pb.CapabilityType_CAPABILITY_TYPE_SRV6, Detail: &pb.Capability_Srv6{Srv6: &pb.Srv6Capability{}}},
				},
			}}},
			want: Capability{Type: "PATH_SETUP_TYPE", Detail: PathSetupTypeCapability{
				PathSetupTypes: []uint32{1, 3},
				SubCapabilities: []Capability{
					{Type: "SR", Detail: SRCapability{UnlimitedMSD: true}},
					{Type: "SRV6", Detail: SRv6Capability{}},
				},
			}},
		},
		{
			name:  "AssocTypeList",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_ASSOC_TYPE_LIST, Detail: &pb.Capability_AssocTypeList{AssocTypeList: &pb.AssocTypeListCapability{AssocTypes: []uint32{6}}}},
			want:  Capability{Type: "ASSOC_TYPE_LIST", Detail: AssocTypeListCapability{AssocTypes: []uint32{6}}},
		},
		{
			name:  "LspDbVersion",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_LSP_DB_VERSION, Detail: &pb.Capability_LspDbVersion{LspDbVersion: &pb.LspDbVersionCapability{VersionNumber: 9}}},
			want:  Capability{Type: "LSP_DB_VERSION", Detail: LSPDBVersionCapability{VersionNumber: 9}},
		},
		{
			name:  "Multipath",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_MULTIPATH, Detail: &pb.Capability_Multipath{Multipath: &pb.MultipathCapability{MaxMultipaths: 3, Weighted: true}}},
			want:  Capability{Type: "MULTIPATH", Detail: MultipathCapability{MaxMultipaths: 3, Weighted: true}},
		},
		{
			name:  "VendorInformation",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_VENDOR_INFORMATION, Detail: &pb.Capability_VendorInformation{VendorInformation: &pb.VendorInformationCapability{EnterpriseNumber: 12}}},
			want:  Capability{Type: "VENDOR_INFORMATION", Detail: VendorInformationCapability{EnterpriseNumber: 12}},
		},
		{
			name:  "Unknown",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_UNKNOWN, Detail: &pb.Capability_Unknown{Unknown: &pb.UnknownCapability{TlvType: 77}}},
			want:  Capability{Type: "UNKNOWN", Detail: UnknownCapability{TLVType: 77}},
		},
		{
			name:  "no detail set falls back to nil Detail",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_UNSPECIFIED},
			want:  Capability{Type: "UNSPECIFIED", Detail: nil},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, capabilityFromPB(tt.pbCap))
		})
	}
}

func TestPolicyStateFromPB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   pb.SRPolicyState
		want table.PolicyState
	}{
		{"down", pb.SRPolicyState_SR_POLICY_STATE_DOWN, table.PolicyDown},
		{"up", pb.SRPolicyState_SR_POLICY_STATE_UP, table.PolicyUp},
		{"active", pb.SRPolicyState_SR_POLICY_STATE_ACTIVE, table.PolicyActive},
		{"unknown", pb.SRPolicyState_SR_POLICY_STATE_UNKNOWN, table.PolicyUnknown},
		{"unspecified maps to the empty state", pb.SRPolicyState_SR_POLICY_STATE_UNSPECIFIED, table.PolicyState("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, policyStateFromPB(tt.in))
		})
	}
}

func TestPolicyTypeFromPB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   pb.SRPolicyType
		want table.PolicyType
	}{
		{"explicit", pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, table.PolicyTypeExplicit},
		{"dynamic", pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, table.PolicyTypeDynamic},
		{"unspecified maps to the unknown type", pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED, table.PolicyType("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, policyTypeFromPB(tt.in))
		})
	}
}

func TestMetricTypeFromPB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   pb.MetricType
		want table.MetricType
	}{
		{"igp", pb.MetricType_METRIC_TYPE_IGP, table.IGPMetric},
		{"te", pb.MetricType_METRIC_TYPE_TE, table.TEMetric},
		{"delay", pb.MetricType_METRIC_TYPE_DELAY, table.DelayMetric},
		{"hopcount", pb.MetricType_METRIC_TYPE_HOPCOUNT, table.HopcountMetric},
		{"unspecified maps to no optimization objective (explicit path)", pb.MetricType_METRIC_TYPE_UNSPECIFIED, table.UnspecifiedMetric},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, metricTypeFromPB(tt.in))
		})
	}
}

func TestConvertSRPolicy(t *testing.T) {
	t.Parallel()

	t.Run("full mapping", func(t *testing.T) {
		t.Parallel()
		p := &pb.SRPolicy{
			PlspId:      7,
			PolicyName:  testPolicyName,
			SrcAddr:     netip.MustParseAddr(testIPv4Addr1).AsSlice(),
			DstAddr:     netip.MustParseAddr(testIPv4Addr2).AsSlice(),
			SrcRouterId: testRouterID1,
			DstRouterId: testRouterID2,
			Color:       100,
			Preference:  200,
			LspId:       3,
			State:       pb.SRPolicyState_SR_POLICY_STATE_UP,
			Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
			Metric:      pb.MetricType_METRIC_TYPE_UNSPECIFIED,
			SegmentList: []*pb.Segment{{Sid: "16003"}},
		}
		got, err := convertSRPolicy(p)
		require.NoError(t, err)
		want := table.SRPolicy{
			PlspID:      7,
			Name:        testPolicyName,
			SegmentList: []table.Segment{table.SegmentSRMPLS{Sid: 16003}},
			SrcAddr:     netip.MustParseAddr(testIPv4Addr1),
			DstAddr:     netip.MustParseAddr(testIPv4Addr2),
			SrcRouterID: testRouterID1,
			DstRouterID: testRouterID2,
			Color:       100,
			Preference:  200,
			LSPID:       3,
			State:       table.PolicyUp,
			Type:        table.PolicyTypeExplicit,
			Metric:      table.UnspecifiedMetric,
		}
		assert.Equal(t, want, got)
	})

	t.Run("invalid source address", func(t *testing.T) {
		t.Parallel()
		_, err := convertSRPolicy(&pb.SRPolicy{SrcAddr: []byte{1, 2, 3}, DstAddr: netip.MustParseAddr(testIPv4Addr2).AsSlice()})
		require.Error(t, err)
	})

	t.Run("invalid destination address", func(t *testing.T) {
		t.Parallel()
		_, err := convertSRPolicy(&pb.SRPolicy{SrcAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(), DstAddr: []byte{1, 2, 3}})
		require.Error(t, err)
	})

	t.Run("invalid segment propagates the error", func(t *testing.T) {
		t.Parallel()
		_, err := convertSRPolicy(&pb.SRPolicy{
			SrcAddr:     netip.MustParseAddr(testIPv4Addr1).AsSlice(),
			DstAddr:     netip.MustParseAddr(testIPv4Addr2).AsSlice(),
			SegmentList: []*pb.Segment{{Sid: "not-a-sid"}},
		})
		require.Error(t, err)
	})

	t.Run("LSP-ID overflow", func(t *testing.T) {
		t.Parallel()
		_, err := convertSRPolicy(&pb.SRPolicy{
			SrcAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(),
			DstAddr: netip.MustParseAddr(testIPv4Addr2).AsSlice(),
			LspId:   math.MaxUint16 + 1,
		})
		require.Error(t, err)
	})
}

func TestSidStructureFromPB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    *pb.SidStructure
	}{
		{"LocalBlock overflow", &pb.SidStructure{LocalBlock: math.MaxUint8 + 1}},
		{"LocalNode overflow", &pb.SidStructure{LocalNode: math.MaxUint8 + 1}},
		{"LocalFunc overflow", &pb.SidStructure{LocalFunc: math.MaxUint8 + 1}},
		{"LocalArg overflow", &pb.SidStructure{LocalArg: math.MaxUint8 + 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := sidStructureFromPB(tt.s)
			require.Error(t, err)
		})
	}
}

func TestGetSRPolicyList(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.SRPolicySession{{
				PeerAddr: netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				State:    pb.SessionState_SESSION_STATE_UP,
				SrPolicies: []*pb.SRPolicy{{
					PolicyName: testPolicyName,
					SrcAddr:    netip.MustParseAddr(testIPv4Addr1).AsSlice(),
					DstAddr:    netip.MustParseAddr(testIPv4Addr2).AsSlice(),
				}},
			}},
		}}
		got, err := GetSRPolicyList(client, netip.MustParseAddr(testIPv4Addr1))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, testIPv4Addr1, got[0].PeerAddr.String())
		assert.Equal(t, "up", got[0].State)
		require.Len(t, got[0].SRPolicies, 1)
		assert.Equal(t, testPolicyName, got[0].SRPolicies[0].Name)
	})

	t.Run("client error propagates", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{srPolicyListErr: assert.AnError}
		_, err := GetSRPolicyList(client, netip.Addr{})
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("invalid session address", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.SRPolicySession{{PeerAddr: []byte{1, 2, 3}}},
		}}
		_, err := GetSRPolicyList(client, netip.Addr{})
		require.Error(t, err)
	})

	t.Run("policy conversion error propagates", func(t *testing.T) {
		t.Parallel()
		client := &fakeClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.SRPolicySession{{
				PeerAddr:   netip.MustParseAddr(testIPv4Addr1).AsSlice(),
				SrPolicies: []*pb.SRPolicy{{SrcAddr: []byte{1, 2, 3}}},
			}},
		}}
		_, err := GetSRPolicyList(client, netip.Addr{})
		require.Error(t, err)
	})
}

func TestCreateSRPolicy(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, CreateSRPolicy(&fakeClient{}, &pb.CreateSRPolicyRequest{}))
	})

	t.Run("error propagates", func(t *testing.T) {
		t.Parallel()
		err := CreateSRPolicy(&fakeClient{createSRPolicyErr: assert.AnError}, &pb.CreateSRPolicyRequest{})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestDeleteSRPolicy(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DeleteSRPolicy(&fakeClient{}, &pb.DeleteSRPolicyRequest{}))
	})

	t.Run("error propagates", func(t *testing.T) {
		t.Parallel()
		err := DeleteSRPolicy(&fakeClient{deleteSRPolicyErr: assert.AnError}, &pb.DeleteSRPolicyRequest{})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestGetTED_Disabled(t *testing.T) {
	t.Parallel()

	ted, err := GetTED(&fakeClient{tedResp: &pb.GetTEDResponse{Enabled: false}})
	require.NoError(t, err)
	assert.Nil(t, ted)
}

func TestGetTED_ClientError(t *testing.T) {
	t.Parallel()

	_, err := GetTED(&fakeClient{tedErr: assert.AnError})
	require.ErrorIs(t, err, assert.AnError)
}

func TestGetTED_Success(t *testing.T) {
	t.Parallel()

	nodeA := &pb.LsNode{
		Asn:        65000,
		RouterId:   testRouterID1,
		Hostname:   "routerA",
		IsisAreaId: "49.0001",
		SrgbBegin:  16000,
		SrgbEnd:    23999,
		Links: []*pb.LsLink{
			{
				LocalRouterId:  testRouterID1,
				RemoteRouterId: testRouterID2,
				LocalIp:        testIPv4Addr1,
				RemoteIp:       testIPv4Addr2,
				AdjSid:         24001,
				Metrics: []*pb.Metric{
					{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10},
					{Type: pb.MetricType_METRIC_TYPE_TE, Value: 20},
					{Type: pb.MetricType_METRIC_TYPE_DELAY, Value: 30},
					{Type: pb.MetricType_METRIC_TYPE_HOPCOUNT, Value: 1},
				},
				Srv6EndXSid: &pb.Srv6EndXSID{
					EndpointBehavior: uint32(table.BehaviorENDX),
					Sids:             []*pb.SID{{Sid: "2001:db8:1::"}},
					SidStructure:     &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80},
				},
			},
			{
				LocalRouterId:  testRouterID1,
				RemoteRouterId: testRouterID2,
			},
		},
		Prefixes: []*pb.LsPrefix{
			{Prefix: testPrefix, SidIndex: proto.Uint32(1)},
			{Prefix: "10.0.0.2/32"},
		},
		Srv6Sids: []*pb.LsSrv6SID{
			{
				Sids:             []*pb.SID{{Sid: "2001:db8:1::"}},
				EndpointBehavior: &pb.EndpointBehavior{Behavior: uint32(table.BehaviorEND), Flags: 1, Algorithm: 0},
				SidStructure:     &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80},
				MultiTopoIds:     []*pb.MultiTopoID{{MultiTopoId: 1}},
			},
		},
	}
	nodeB := &pb.LsNode{Asn: 65000, RouterId: testRouterID2}

	client := &fakeClient{tedResp: &pb.GetTEDResponse{Enabled: true, Nodes: []*pb.LsNode{nodeA, nodeB}}}
	ted, err := GetTED(client)
	require.NoError(t, err)
	require.NotNil(t, ted)

	a := ted.Nodes[testRouterID1]
	require.NotNil(t, a)
	assert.Equal(t, "routerA", a.Hostname)
	assert.Equal(t, "49.0001", a.IsisAreaID)
	assert.Equal(t, uint32(16000), a.SrgbBegin)
	assert.Equal(t, uint32(23999), a.SrgbEnd)
	require.Len(t, a.Links, 2)

	link0 := a.Links[0]
	assert.Equal(t, testIPv4Addr1, link0.LocalIP.String())
	assert.Equal(t, testIPv4Addr2, link0.RemoteIP.String())
	assert.Same(t, ted.Nodes[testRouterID2], link0.RemoteNode)
	assert.Equal(t, uint32(24001), link0.AdjSid)
	assert.Equal(t, []*table.Metric{
		table.NewMetric(table.IGPMetric, 10),
		table.NewMetric(table.TEMetric, 20),
		table.NewMetric(table.DelayMetric, 30),
		table.NewMetric(table.HopcountMetric, 1),
	}, link0.Metrics)
	require.NotNil(t, link0.Srv6EndXSID)
	assert.Equal(t, table.BehaviorENDX, link0.Srv6EndXSID.EndpointBehavior)
	assert.Equal(t, []string{"2001:db8:1::"}, link0.Srv6EndXSID.Sids)
	assert.Equal(t, table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80}, link0.Srv6EndXSID.Srv6SIDStructure)

	link1 := a.Links[1]
	assert.False(t, link1.LocalIP.IsValid())
	assert.False(t, link1.RemoteIP.IsValid())

	require.Len(t, a.Prefixes, 2)
	assert.True(t, a.Prefixes[0].HasPrefixSID())
	assert.Equal(t, uint32(1), a.Prefixes[0].SidIndex)
	assert.False(t, a.Prefixes[1].HasPrefixSID())

	require.Len(t, a.SRv6SIDs, 1)
	sid := a.SRv6SIDs[0]
	assert.Equal(t, []string{"2001:db8:1::"}, sid.Sids)
	assert.Equal(t, []uint32{1}, sid.MultiTopoIDs)
	assert.Equal(t, table.EndpointBehavior{Behavior: table.BehaviorEND, Flags: 1, Algorithm: 0}, sid.EndpointBehavior)
	assert.Equal(t, table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80}, sid.SIDStructure)
}

func TestGetTED_PropagatesConversionErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid link IP", func(t *testing.T) {
		t.Parallel()
		node := &pb.LsNode{RouterId: testRouterID1, Links: []*pb.LsLink{
			{LocalRouterId: testRouterID1, RemoteRouterId: testRouterID1, LocalIp: "not-an-ip"},
		}}
		_, err := GetTED(&fakeClient{tedResp: &pb.GetTEDResponse{Enabled: true, Nodes: []*pb.LsNode{node}}})
		require.Error(t, err)
	})

	t.Run("invalid prefix", func(t *testing.T) {
		t.Parallel()
		node := &pb.LsNode{RouterId: testRouterID1, Prefixes: []*pb.LsPrefix{{Prefix: "not-a-prefix"}}}
		_, err := GetTED(&fakeClient{tedResp: &pb.GetTEDResponse{Enabled: true, Nodes: []*pb.LsNode{node}}})
		require.Error(t, err)
	})
}

func TestCreateLsLink(t *testing.T) {
	t.Parallel()

	localNode := table.NewLsNode(65000, "0000.0000.0001")
	remoteNode := table.NewLsNode(65000, "0000.0000.0002")

	t.Run("invalid localIp", func(t *testing.T) {
		t.Parallel()
		_, err := createLsLink(localNode, remoteNode, &pb.LsLink{LocalIp: "not-an-ip"})
		require.Error(t, err)
	})

	t.Run("invalid remoteIp", func(t *testing.T) {
		t.Parallel()
		_, err := createLsLink(localNode, remoteNode, &pb.LsLink{RemoteIp: "not-an-ip"})
		require.Error(t, err)
	})

	t.Run("metric conversion error propagates", func(t *testing.T) {
		t.Parallel()
		_, err := createLsLink(localNode, remoteNode, &pb.LsLink{
			Metrics: []*pb.Metric{{Type: pb.MetricType_METRIC_TYPE_UNSPECIFIED, Value: 1}},
		})
		require.Error(t, err)
	})

	t.Run("SRv6 End.X SID conversion error propagates", func(t *testing.T) {
		t.Parallel()
		_, err := createLsLink(localNode, remoteNode, &pb.LsLink{
			Srv6EndXSid: &pb.Srv6EndXSID{EndpointBehavior: math.MaxUint16 + 1},
		})
		require.Error(t, err)
	})
}

func TestCreateLsLink_InvalidMetric(t *testing.T) {
	t.Parallel()

	localNode := table.NewLsNode(65000, "0000.0000.0001")
	remoteNode := table.NewLsNode(65000, "0000.0000.0002")

	_, err := createLsLink(localNode, remoteNode, &pb.LsLink{
		Metrics: []*pb.Metric{
			{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10},
			{Type: pb.MetricType_METRIC_TYPE_UNSPECIFIED, Value: 1},
		},
	})
	assert.EqualError(t, err, "unknown metric type")
}

func TestAddLsNode_InvalidSrv6SID(t *testing.T) {
	t.Parallel()

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{
		testRouterID1: table.NewLsNode(65000, testRouterID1),
	}}
	node := &pb.LsNode{
		RouterId: testRouterID1,
		Prefixes: []*pb.LsPrefix{{Prefix: "not-a-prefix"}},
	}

	err := addLsNode(ted, node)
	require.Error(t, err)
}

func TestAddLsNode_Srv6SIDConversionErrorPropagates(t *testing.T) {
	t.Parallel()

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{
		testRouterID1: table.NewLsNode(65000, testRouterID1),
	}}
	node := &pb.LsNode{
		RouterId: testRouterID1,
		Srv6Sids: []*pb.LsSrv6SID{{
			EndpointBehavior: &pb.EndpointBehavior{Behavior: math.MaxUint16 + 1},
		}},
	}

	err := addLsNode(ted, node)
	require.Error(t, err)
}

func TestCreateSrv6EndXSID(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := createSrv6EndXSID(&pb.Srv6EndXSID{
			EndpointBehavior: uint32(table.BehaviorENDX),
			Sids:             []*pb.SID{{Sid: "2001:db8::1:0"}},
			SidStructure:     &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
		})
		require.NoError(t, err)
		assert.Equal(t, &table.Srv6EndXSID{
			EndpointBehavior: table.BehaviorENDX,
			Sids:             []string{"2001:db8::1:0"},
			Srv6SIDStructure: table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
		}, got)
	})

	t.Run("endpoint behavior overflow", func(t *testing.T) {
		t.Parallel()
		_, err := createSrv6EndXSID(&pb.Srv6EndXSID{EndpointBehavior: math.MaxUint16 + 1})
		require.Error(t, err)
	})

	t.Run("SID structure overflow propagates", func(t *testing.T) {
		t.Parallel()
		_, err := createSrv6EndXSID(&pb.Srv6EndXSID{
			SidStructure: &pb.SidStructure{LocalBlock: math.MaxUint8 + 1},
		})
		require.Error(t, err)
	})
}

func TestCreateSrv6SID(t *testing.T) {
	t.Parallel()

	lsNode := table.NewLsNode(65000, testRouterID1)

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := createSrv6SID(lsNode, &pb.LsSrv6SID{
			Sids:             []*pb.SID{{Sid: "2001:db8:1::"}},
			MultiTopoIds:     []*pb.MultiTopoID{{MultiTopoId: 0}},
			EndpointBehavior: &pb.EndpointBehavior{Behavior: uint32(table.BehaviorEND)},
			SidStructure:     &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
		})
		require.NoError(t, err)

		want := table.NewLsSrv6SID(lsNode)
		want.Sids = []string{"2001:db8:1::"}
		want.MultiTopoIDs = []uint32{0}
		want.EndpointBehavior = table.EndpointBehavior{Behavior: table.BehaviorEND}
		want.SIDStructure = table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0}
		assert.Equal(t, want, got)
	})

	t.Run("behavior overflow", func(t *testing.T) {
		t.Parallel()
		_, err := createSrv6SID(lsNode, &pb.LsSrv6SID{
			EndpointBehavior: &pb.EndpointBehavior{Behavior: math.MaxUint16 + 1},
		})
		require.Error(t, err)
	})

	t.Run("flags overflow", func(t *testing.T) {
		t.Parallel()
		_, err := createSrv6SID(lsNode, &pb.LsSrv6SID{
			EndpointBehavior: &pb.EndpointBehavior{Flags: math.MaxUint8 + 1},
		})
		require.Error(t, err)
	})

	t.Run("algorithm overflow", func(t *testing.T) {
		t.Parallel()
		_, err := createSrv6SID(lsNode, &pb.LsSrv6SID{
			EndpointBehavior: &pb.EndpointBehavior{Algorithm: math.MaxUint8 + 1},
		})
		require.Error(t, err)
	})

	t.Run("SID structure overflow propagates", func(t *testing.T) {
		t.Parallel()
		_, err := createSrv6SID(lsNode, &pb.LsSrv6SID{
			SidStructure: &pb.SidStructure{LocalBlock: math.MaxUint8 + 1},
		})
		require.Error(t, err)
	})
}

func TestCreateMetric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   *pb.Metric
		want *table.Metric
	}{
		{"igp", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10}, table.NewMetric(table.IGPMetric, 10)},
		{"te", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_TE, Value: 20}, table.NewMetric(table.TEMetric, 20)},
		{"delay", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_DELAY, Value: 30}, table.NewMetric(table.DelayMetric, 30)},
		{"hopcount", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_HOPCOUNT, Value: 1}, table.NewMetric(table.HopcountMetric, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := createMetric(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("unspecified metric type is an error", func(t *testing.T) {
		t.Parallel()
		_, err := createMetric(&pb.Metric{Type: pb.MetricType_METRIC_TYPE_UNSPECIFIED})
		require.Error(t, err)
	})
}
