// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewSessionCmd_RunE(t *testing.T) {
	jsonFmt = false
	cmd := newSessionCmd()

	client = &fakePCEServiceClient{}
	captureStdout(t, func() {
		require.NoError(t, cmd.RunE(cmd, []string{}))
	})

	client = &fakePCEServiceClient{sessionListErr: assert.AnError}
	err := cmd.RunE(cmd, []string{})
	require.ErrorIs(t, err, assert.AnError)
}

func TestNewSessionCmd_PassesParsedArgs(t *testing.T) {
	jsonFmt = false
	cmd := newSessionCmd()
	client = &fakePCEServiceClient{}

	captureStdout(t, func() {
		require.NoError(t, cmd.RunE(cmd, []string{"192.0.2.1", "detail"}))
	})

	require.NotNil(t, client.(*fakePCEServiceClient).sessionListReq)
	req := client.(*fakePCEServiceClient).sessionListReq
	assert.Equal(t, netip.MustParseAddr("192.0.2.1").AsSlice(), req.GetPeerAddr())
	assert.True(t, req.GetIncludeStats())
}

func TestParseSessionArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantAddr   string
		wantDetail bool
		wantErr    bool
	}{
		{name: "no args", args: []string{}},
		{name: "addr only", args: []string{"192.0.2.1"}, wantAddr: "192.0.2.1"},
		{name: "detail only", args: []string{"detail"}, wantDetail: true},
		{name: "addr then detail", args: []string{"192.0.2.1", "detail"}, wantAddr: "192.0.2.1", wantDetail: true},
		{name: "detail then addr", args: []string{"detail", "192.0.2.1"}, wantAddr: "192.0.2.1", wantDetail: true},
		{name: "invalid address", args: []string{"not-an-addr"}, wantErr: true},
		{name: "duplicate detail", args: []string{"detail", "detail"}, wantErr: true},
		{name: "two addresses", args: []string{"192.0.2.1", "192.0.2.2"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, detail, err := parseSessionArgs(tt.args)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantAddr == "" {
				assert.False(t, addr.IsValid())
			} else {
				assert.Equal(t, netip.MustParseAddr(tt.wantAddr), addr)
			}
			assert.Equal(t, tt.wantDetail, detail)
		})
	}
}

func sessionFixture() *pb.Session {
	return &pb.Session{
		PeerAddr:       netip.MustParseAddr("192.0.2.1").AsSlice(),
		State:          pb.SessionState_SESSION_STATE_UP,
		LocalSessionId: proto.Uint32(1),
		PeerSessionId:  proto.Uint32(7),
		LocalTimers:    &pb.SessionTimers{Keepalive: 30, DeadTimer: 120},
		PeerTimers:     &pb.SessionTimers{Keepalive: 10, DeadTimer: 40},
		EffectiveTimers: &pb.EffectiveTimers{
			Keepalive: 10, DeadTimer: 40,
		},
		PccType: pb.PccType_PCC_TYPE_RFC_COMPLIANT,
		LocalCapabilities: []*pb.Capability{
			{Type: pb.CapabilityType_CAPABILITY_TYPE_STATEFUL, Detail: &pb.Capability_Stateful{Stateful: &pb.StatefulCapability{LspUpdate: true}}},
			{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: proto.Uint32(10)}}},
		},
		PeerCapabilities: []*pb.Capability{
			{Type: pb.CapabilityType_CAPABILITY_TYPE_STATEFUL, Detail: &pb.Capability_Stateful{Stateful: &pb.StatefulCapability{LspUpdate: true}}},
			{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: proto.Uint32(16)}}},
		},
		Initiator:             pb.SessionInitiator_SESSION_INITIATOR_REMOTE,
		SyncState:             pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED,
		CreatedAtUnixNano:     time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC).UnixNano(),
		EstablishedAtUnixNano: time.Date(2026, 8, 19, 9, 30, 5, 0, time.UTC).UnixNano(),
		Stats: &pb.SessionStats{
			Keepalive:     &pb.MessageCounter{Sent: 3, Rcvd: 3},
			Pcerr:         &pb.MessageCounter{Sent: 0, Rcvd: 0},
			Pcntf:         &pb.MessageCounter{Rcvd: 0},
			Report:        &pb.MessageCounter{Rcvd: 5},
			Update:        &pb.MessageCounter{Sent: 2},
			Initiate:      &pb.MessageCounter{Sent: 1},
			SessSetupOk:   1,
			SessSetupFail: 0,
		},
	}
}

func TestShowSession_Text(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 8, 19, 9, 42, 27, 0, time.UTC) }
	t.Cleanup(func() { nowFunc = time.Now })

	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{Sessions: []*pb.Session{sessionFixture()}}}

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, netip.Addr{}, true, outputText))
	out := buf.String()

	assert.Contains(t, out, "Session #0: 192.0.2.1")
	assert.Contains(t, out, "State:             up")
	assert.Contains(t, out, "LSP-DB Sync:       finished")
	assert.Contains(t, out, "Role:              active-stateful-pce")
	assert.Contains(t, out, "Up Time:           00:12:22")
	assert.Contains(t, out, "Session ID:        Local=1, Peer=7")
	assert.Contains(t, out, "STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful, Update")
	assert.Contains(t, out, "    Local only:\n      msd=10\n")
	assert.Contains(t, out, "    Peer only:\n      msd=16\n")
	assert.Contains(t, out, "Session Creation:  2026-08-19T09:30:00Z")
	assert.Contains(t, out, "Initiator:         remote")
	assert.Contains(t, out, "Session Setup:     ok=1, fail=0")
}

func TestShowSession_Text_CapabilityGrouping(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 8, 19, 9, 42, 27, 0, time.UTC) }
	t.Cleanup(func() { nowFunc = time.Now })

	fixture := sessionFixture()
	assocTypeList := &pb.Capability{
		Type: pb.CapabilityType_CAPABILITY_TYPE_ASSOC_TYPE_LIST,
		Detail: &pb.Capability_AssocTypeList{AssocTypeList: &pb.AssocTypeListCapability{
			AssocTypes: []uint32{2, 3, 5, 6, 9},
		}},
	}
	unknownTLV := &pb.Capability{
		Type:   pb.CapabilityType_CAPABILITY_TYPE_UNKNOWN,
		Detail: &pb.Capability_Unknown{Unknown: &pb.UnknownCapability{TlvType: 73}},
	}
	fixture.LocalCapabilities = []*pb.Capability{
		fixture.LocalCapabilities[0], // STATEFUL
		{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: proto.Uint32(10)}}},
		assocTypeList,
		unknownTLV,
	}
	fixture.PeerCapabilities = []*pb.Capability{
		fixture.PeerCapabilities[0], // STATEFUL
		{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: proto.Uint32(10)}}},
		assocTypeList,
		unknownTLV,
	}

	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{Sessions: []*pb.Session{fixture}}}

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, netip.Addr{}, true, outputText))
	out := buf.String()

	assert.Contains(t, out, "      ASSOC-TYPE-LIST [RFC8697]:\n"+
		"        2 Disjoint Association\n"+
		"        3 Policy Association\n"+
		"        5 Double Sided Bidirectional LSP Association\n"+
		"        6 SR Policy Association\n"+
		"        9 P2MP SR Policy Association (draft)\n")
	assert.Contains(t, out, "      Unrecognized TLVs:\n"+
		"        type=73: SR-P2MP-POLICY-CAPABILITY (draft-ietf-pce-sr-p2mp-policy-11)\n")
	assert.Contains(t, out, "    Local only:\n      -\n")
	assert.Contains(t, out, "    Peer only:\n      -\n")
	assert.NotContains(t, out, "ASSOC-TYPE-LIST [RFC8697]: 2 Disjoint Association")
}

func TestShowSession_JSON(t *testing.T) {
	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{Sessions: []*pb.Session{sessionFixture()}}}

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, netip.Addr{}, false, outputJSON))

	var decoded []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.Len(t, decoded, 1)

	summary := decoded[0]
	assert.Equal(t, "192.0.2.1", summary["peerAddress"])
	assert.Equal(t, "up", summary["state"])
	assert.Equal(t, "finished", summary["lspDbSync"])
	assert.Equal(t, "active-stateful-pce", summary["role"])

	// Summary output must not include detail-only fields.
	assert.NotContains(t, summary, "sessionCreation")
	assert.NotContains(t, summary, "initiator")
	assert.NotContains(t, summary, "stats")
}

func TestShowSession_JSONDetailAddsWithoutChangingSummaryKeys(t *testing.T) {
	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{Sessions: []*pb.Session{sessionFixture()}}}

	var summaryBuf, detailBuf bytes.Buffer
	require.NoError(t, showSession(&summaryBuf, netip.Addr{}, false, outputJSON))
	require.NoError(t, showSession(&detailBuf, netip.Addr{}, true, outputJSON))

	var summary, detail []map[string]any
	require.NoError(t, json.Unmarshal(summaryBuf.Bytes(), &summary))
	require.NoError(t, json.Unmarshal(detailBuf.Bytes(), &detail))
	require.Len(t, summary, 1)
	require.Len(t, detail, 1)

	for k, v := range summary[0] {
		assert.Equal(t, v, detail[0][k], "detail must not change summary key %q", k)
	}
	assert.Contains(t, detail[0], "sessionCreation")
	assert.Contains(t, detail[0], "initiator")
	assert.Contains(t, detail[0], "lspDbSync")
	assert.Contains(t, detail[0], "stats")
}

func TestShowSession_AdvertisedValuesUnsetBeforeOpenExchange(t *testing.T) {
	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{Sessions: []*pb.Session{{
		PeerAddr: netip.MustParseAddr("192.0.2.1").AsSlice(),
		State:    pb.SessionState_SESSION_STATE_OPEN_WAIT,
	}}}}

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, netip.Addr{}, false, outputText))
	out := buf.String()

	assert.Contains(t, out, "State:             open-wait")
	assert.Contains(t, out, "Session ID:        Local=-, Peer=-")
	assert.NotContains(t, out, "Up Time:")
}

func TestShowSession_SessionIDZeroDistinguishedFromUnset(t *testing.T) {
	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{Sessions: []*pb.Session{{
		PeerAddr:       netip.MustParseAddr("192.0.2.1").AsSlice(),
		State:          pb.SessionState_SESSION_STATE_UP,
		LocalSessionId: proto.Uint32(0),
		PeerSessionId:  proto.Uint32(0),
	}}}}

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, netip.Addr{}, false, outputText))
	assert.Contains(t, buf.String(), "Session ID:        Local=0, Peer=0")
}

func TestShowSession_NoSessionsText(t *testing.T) {
	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{}}

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, netip.Addr{}, false, outputText))
	assert.Equal(t, "No PCEP sessions connected.\n", buf.String())
}

func TestShowSession_NoSessionForAddrText(t *testing.T) {
	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{}}
	addr := netip.MustParseAddr("192.0.2.9")

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, addr, false, outputText))
	assert.Equal(t, "No PCEP session for 192.0.2.9.\n", buf.String())
}

func TestShowSession_NoSessionsJSON(t *testing.T) {
	client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{}}

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, netip.Addr{}, false, outputJSON))
	assert.Equal(t, "[]\n", buf.String())
}

func TestShowSession_GRPCErrorPropagates(t *testing.T) {
	client = &fakePCEServiceClient{sessionListErr: assert.AnError}
	var buf bytes.Buffer
	err := showSession(&buf, netip.Addr{}, false, outputText)
	require.ErrorIs(t, err, assert.AnError)
}

func TestShowSession_PassesAddrFilterAndDetailFlag(t *testing.T) {
	fake := &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{}}
	client = fake
	addr := netip.MustParseAddr("192.0.2.1")

	var buf bytes.Buffer
	require.NoError(t, showSession(&buf, addr, true, outputText))

	require.NotNil(t, fake.sessionListReq)
	assert.Equal(t, addr.AsSlice(), fake.sessionListReq.GetPeerAddr())
	assert.True(t, fake.sessionListReq.GetIncludeStats())
}
