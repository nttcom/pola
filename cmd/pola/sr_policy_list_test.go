// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/table"
)

func newTestSRPolicyListCmd(client pb.PCEServiceClient, jsonFmt bool) *cobra.Command {
	return newSRPolicyListCmd(&cli{client: client, jsonFmt: jsonFmt})
}

func TestPeerAddrFlag_Unset(t *testing.T) {
	t.Parallel()

	cmd := newTestSRPolicyListCmd(nil, false)

	addr, err := peerAddrFlag(cmd)
	require.NoError(t, err)
	assert.False(t, addr.IsValid())
}

func TestPeerAddrFlag_Valid(t *testing.T) {
	t.Parallel()

	cmd := newTestSRPolicyListCmd(nil, false)
	require.NoError(t, cmd.Flags().Set("peer", "10.0.0.1"))

	addr, err := peerAddrFlag(cmd)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", addr.String())
}

func TestPeerAddrFlag_Invalid(t *testing.T) {
	t.Parallel()

	cmd := newTestSRPolicyListCmd(nil, false)
	require.NoError(t, cmd.Flags().Set("peer", "not-an-address"))

	_, err := peerAddrFlag(cmd)
	require.Error(t, err)
}

func TestPeerAddrFlag_UnregisteredFlag(t *testing.T) {
	t.Parallel()

	_, err := peerAddrFlag(&cobra.Command{})
	require.Error(t, err)
}

func TestShowSRPolicyList_UnregisteredFlag(t *testing.T) {
	t.Parallel()

	err := showSRPolicyList(&cobra.Command{}, []string{}, nil, false)
	require.Error(t, err)
}

func TestSegmentDisplayString(t *testing.T) {
	t.Parallel()

	local := netip.MustParseAddr(testPeerAddr1)
	remote := netip.MustParseAddr(testPeerAddr2)

	tests := []struct {
		name string
		seg  table.SegmentSRMPLS
		want string
	}{
		{
			name: "no localAddr, no remoteAddr",
			seg:  table.SegmentSRMPLS{Sid: 16003},
			want: "16003",
		},
		{
			name: "localAddr only",
			seg:  table.SegmentSRMPLS{Sid: 16003, LocalAddr: local},
			want: "16003 (local=192.0.2.1)",
		},
		{
			name: "remoteAddr only",
			seg:  table.SegmentSRMPLS{Sid: 16003, RemoteAddr: remote},
			want: "16003 (remote=192.0.2.2)",
		},
		{
			name: "localAddr and remoteAddr",
			seg:  table.SegmentSRMPLS{Sid: 16003, LocalAddr: local, RemoteAddr: remote},
			want: "16003 (local=192.0.2.1, remote=192.0.2.2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, segmentDisplayString(tt.seg))
		})
	}
}

func TestSegmentDisplayString_SRv6(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("2001:db8:1005::")
	local := netip.MustParseAddr("2001:db8::5")
	remote := netip.MustParseAddr("2001:db8::6")

	tests := []struct {
		name string
		seg  table.SegmentSRv6
		want string
	}{
		{
			name: "no localAddr, no remoteAddr",
			seg:  table.SegmentSRv6{Sid: sid},
			want: "2001:db8:1005::",
		},
		{
			name: "localAddr only",
			seg:  table.SegmentSRv6{Sid: sid, LocalAddr: local},
			want: "2001:db8:1005:: (local=2001:db8::5)",
		},
		{
			name: "remoteAddr only",
			seg:  table.SegmentSRv6{Sid: sid, RemoteAddr: remote},
			want: "2001:db8:1005:: (remote=2001:db8::6)",
		},
		{
			name: "localAddr and remoteAddr",
			seg:  table.SegmentSRv6{Sid: sid, LocalAddr: local, RemoteAddr: remote},
			want: "2001:db8:1005:: (local=2001:db8::5, remote=2001:db8::6)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, segmentDisplayString(tt.seg))
		})
	}
}

func TestSrcDstDisplay(t *testing.T) {
	t.Parallel()

	assert.Equal(t, testPeerAddr1, srcDstDisplay(testPeerAddr1, ""))
	assert.Equal(t, "192.0.2.1 (0000.0aff.0001)", srcDstDisplay(testPeerAddr1, testRouterID1))
}

func TestShowSRPolicyList(t *testing.T) {
	t.Parallel()

	t.Run("no policies found", func(t *testing.T) {
		client := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{}}
		cmd := newTestSRPolicyListCmd(client, false)
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showSRPolicyList(cmd, []string{}, client, false))
		assert.Equal(t, "No PCEP sessions connected.\n", out.String())
	})

	t.Run("no policies found, json output", func(t *testing.T) {
		client := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{}}
		cmd := newTestSRPolicyListCmd(client, true)
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showSRPolicyList(cmd, []string{}, client, true))
		assert.Equal(t, "[]\n", out.String())
	})

	t.Run("plain text output", func(t *testing.T) {
		client := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.SRPolicySession{{
				PeerAddr:  netip.MustParseAddr(testPeerAddr1).AsSlice(),
				State:     pb.SessionState_SESSION_STATE_UP,
				SyncState: pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED,
				SrPolicies: []*pb.SRPolicy{
					{
						PolicyName:  testPolicyName,
						PlspId:      1,
						LspId:       2,
						State:       pb.SRPolicyState_SR_POLICY_STATE_UP,
						Type:        pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
						Metric:      pb.MetricType_METRIC_TYPE_TE,
						SrcAddr:     netip.MustParseAddr(testPeerAddr1).AsSlice(),
						SrcRouterId: testRouterID1,
						DstAddr:     netip.MustParseAddr(testPeerAddr2).AsSlice(),
						DstRouterId: testRouterID2,
						Color:       100,
						Preference:  200,
						SegmentList: []*pb.Segment{{Sid: "16003"}, {Sid: "16002"}},
					},
					{
						PolicyName: "pol2",
						SrcAddr:    netip.MustParseAddr("192.0.2.3").AsSlice(),
						DstAddr:    netip.MustParseAddr("192.0.2.4").AsSlice(),
					},
				},
			}},
		}}

		cmd := newTestSRPolicyListCmd(client, false)
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showSRPolicyList(cmd, []string{}, client, false))

		want := "Session: 192.0.2.1 (State: up, LSP-DB Sync: finished)\n" +
			"  PolicyName: pol1\n" +
			"    PlspID: 1\n" +
			"    LSPID: 2\n" +
			"    State: up\n" +
			"    Type: dynamic\n" +
			"    Metric: te\n" +
			"    SrcAddr: 192.0.2.1 (0000.0aff.0001)\n" +
			"    DstAddr: 192.0.2.2 (0000.0aff.0002)\n" +
			"    Color: 100\n" +
			"    Preference: 200\n" +
			"    SegmentList: 16003 -> 16002\n" +
			"  PolicyName: pol2\n" +
			"    PlspID: 0\n" +
			"    LSPID: 0\n" +
			"    State: \n" +
			"    SrcAddr: 192.0.2.3\n" +
			"    DstAddr: 192.0.2.4\n" +
			"    Color: 0\n" +
			"    Preference: 0\n" +
			"    SegmentList: None\n"
		assert.Equal(t, want, out.String())
	})

	t.Run("synced session with no policies", func(t *testing.T) {
		client := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.SRPolicySession{{
				PeerAddr:  netip.MustParseAddr(testPeerAddr1).AsSlice(),
				State:     pb.SessionState_SESSION_STATE_UP,
				SyncState: pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED,
			}},
		}}

		cmd := newTestSRPolicyListCmd(client, false)
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showSRPolicyList(cmd, []string{}, client, false))

		want := "Session: 192.0.2.1 (State: up, LSP-DB Sync: finished)\n" +
			"  No SR Policies.\n"
		assert.Equal(t, want, out.String())
	})

	t.Run("unsynced session is shown with an explanatory note", func(t *testing.T) {
		client := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.SRPolicySession{{
				PeerAddr:  netip.MustParseAddr(testPeerAddr1).AsSlice(),
				State:     pb.SessionState_SESSION_STATE_UP,
				SyncState: pb.LspDbSyncState_LSP_DB_SYNC_STATE_PENDING,
			}},
		}}

		cmd := newTestSRPolicyListCmd(client, false)
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showSRPolicyList(cmd, []string{}, client, false))

		want := "Session: 192.0.2.1 (State: up, LSP-DB Sync: pending)\n" +
			"  No SR Policies: session is still synchronizing.\n"
		assert.Equal(t, want, out.String())
	})

	t.Run("json output", func(t *testing.T) {
		client := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.SRPolicySession{{
				PeerAddr:  netip.MustParseAddr(testPeerAddr1).AsSlice(),
				State:     pb.SessionState_SESSION_STATE_UP,
				SyncState: pb.LspDbSyncState_LSP_DB_SYNC_STATE_FINISHED,
				SrPolicies: []*pb.SRPolicy{{
					PolicyName: testPolicyName,
					SrcAddr:    netip.MustParseAddr(testPeerAddr1).AsSlice(),
					DstAddr:    netip.MustParseAddr(testPeerAddr2).AsSlice(),
				}},
			}},
		}}

		cmd := newTestSRPolicyListCmd(client, true)
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showSRPolicyList(cmd, []string{}, client, true))
		want := `[{
			"peerAddress": "192.0.2.1",
			"state": "up",
			"lspDbSync": "finished",
			"srPolicies": [{
				"policyName": "pol1",
				"segmentList": [],
				"srcAddr": "192.0.2.1",
				"dstAddr": "192.0.2.2",
				"color": 0,
				"preference": 0
			}]
		}]`
		assert.JSONEq(t, want, out.String())
	})

	t.Run("invalid peer filter is rejected", func(t *testing.T) {
		cmd := newTestSRPolicyListCmd(nil, false)
		require.NoError(t, cmd.Flags().Set("peer", "not-an-address"))
		err := showSRPolicyList(cmd, []string{}, nil, false)
		require.Error(t, err)
	})

	t.Run("peer filter propagates to the request", func(t *testing.T) {
		fake := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{}}
		cmd := newTestSRPolicyListCmd(fake, false)
		require.NoError(t, cmd.Flags().Set("peer", testPeerAddr1))

		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showSRPolicyList(cmd, []string{}, fake, false))

		require.NotNil(t, fake.srPolicyListReq)
		assert.Equal(t, netip.MustParseAddr(testPeerAddr1).AsSlice(), fake.srPolicyListReq.GetPeerAddr())
		assert.Equal(t, "No PCEP session for 192.0.2.1.\n", out.String())
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		client := &fakePCEServiceClient{srPolicyListErr: assert.AnError}
		err := showSRPolicyList(newTestSRPolicyListCmd(client, false), []string{}, client, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve SR policy list")
	})
}

func TestNewSRPolicyListCmd_RunE(t *testing.T) {
	t.Parallel()

	cmd := newSRPolicyListCmd(&cli{client: &fakePCEServiceClient{
		srPolicyListResp: &pb.GetSRPolicyListResponse{},
	}})

	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.RunE(cmd, []string{}))
	assert.Equal(t, "No PCEP sessions connected.\n", out.String())
}
