// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"net/netip"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/table"
)

func TestSessionAddrFlag_Unset(t *testing.T) {
	cmd := newSRPolicyListCmd()

	addr, err := sessionAddrFlag(cmd)
	require.NoError(t, err)
	assert.False(t, addr.IsValid())
}

func TestSessionAddrFlag_Valid(t *testing.T) {
	cmd := newSRPolicyListCmd()
	require.NoError(t, cmd.Flags().Set("session", "10.0.0.1"))

	addr, err := sessionAddrFlag(cmd)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", addr.String())
}

func TestSessionAddrFlag_Invalid(t *testing.T) {
	cmd := newSRPolicyListCmd()
	require.NoError(t, cmd.Flags().Set("session", "not-an-address"))

	_, err := sessionAddrFlag(cmd)
	require.Error(t, err)
}

func TestSessionAddrFlag_UnregisteredFlag(t *testing.T) {
	_, err := sessionAddrFlag(&cobra.Command{})
	require.Error(t, err)
}

func TestShowSRPolicyList_UnregisteredJSONFlag(t *testing.T) {
	err := showSRPolicyList(&cobra.Command{}, []string{})
	require.Error(t, err)
}

func TestSegmentDisplayString(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")

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
	assert.Equal(t, "192.0.2.1", srcDstDisplay("192.0.2.1", ""))
	assert.Equal(t, "192.0.2.1 (0000.0aff.0001)", srcDstDisplay("192.0.2.1", "0000.0aff.0001"))
}

// listCmdWithJSONFlag adds the root command's persistent --json flag for tests.
func listCmdWithJSONFlag() *cobra.Command {
	cmd := newSRPolicyListCmd()
	cmd.Flags().Bool("json", false, "")
	return cmd
}

func TestShowSRPolicyList(t *testing.T) {
	t.Run("no policies found", func(t *testing.T) {
		client = &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{}}
		out := captureStdout(t, func() {
			require.NoError(t, showSRPolicyList(listCmdWithJSONFlag(), []string{}))
		})
		assert.Equal(t, "No PCEP sessions connected.\n", out)
	})

	t.Run("plain text output", func(t *testing.T) {
		client = &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.Session{{
				Addr:     netip.MustParseAddr("192.0.2.1").AsSlice(),
				State:    pb.SessionState_SESSION_STATE_UP,
				IsSynced: true,
				SrPolicies: []*pb.SRPolicy{
					{
						PolicyName:  "pol1",
						PlspId:      1,
						LspId:       2,
						State:       pb.SRPolicyState_SR_POLICY_STATE_UP,
						Type:        pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
						Metric:      pb.MetricType_METRIC_TYPE_TE,
						SrcAddr:     netip.MustParseAddr("192.0.2.1").AsSlice(),
						SrcRouterId: "0000.0aff.0001",
						DstAddr:     netip.MustParseAddr("192.0.2.2").AsSlice(),
						DstRouterId: "0000.0aff.0002",
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

		out := captureStdout(t, func() {
			require.NoError(t, showSRPolicyList(listCmdWithJSONFlag(), []string{}))
		})

		want := "Session: 192.0.2.1 (State: UP, IsSynced: true)\n" +
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
			"    SegmentList: None\n" +
			"\n"
		assert.Equal(t, want, out)
	})

	t.Run("synced session with no policies", func(t *testing.T) {
		client = &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.Session{{
				Addr:     netip.MustParseAddr("192.0.2.1").AsSlice(),
				State:    pb.SessionState_SESSION_STATE_UP,
				IsSynced: true,
			}},
		}}

		out := captureStdout(t, func() {
			require.NoError(t, showSRPolicyList(listCmdWithJSONFlag(), []string{}))
		})

		want := "Session: 192.0.2.1 (State: UP, IsSynced: true)\n" +
			"  No SR Policies.\n\n"
		assert.Equal(t, want, out)
	})

	t.Run("unsynced session is shown with an explanatory note", func(t *testing.T) {
		client = &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.Session{{
				Addr:     netip.MustParseAddr("192.0.2.1").AsSlice(),
				State:    pb.SessionState_SESSION_STATE_UP,
				IsSynced: false,
			}},
		}}

		out := captureStdout(t, func() {
			require.NoError(t, showSRPolicyList(listCmdWithJSONFlag(), []string{}))
		})

		want := "Session: 192.0.2.1 (State: UP, IsSynced: false)\n" +
			"  No SR Policies: session is still synchronizing.\n\n"
		assert.Equal(t, want, out)
	})

	t.Run("json output", func(t *testing.T) {
		client = &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.Session{{
				Addr: netip.MustParseAddr("192.0.2.1").AsSlice(),
				SrPolicies: []*pb.SRPolicy{{
					PolicyName: "pol1",
					SrcAddr:    netip.MustParseAddr("192.0.2.1").AsSlice(),
					DstAddr:    netip.MustParseAddr("192.0.2.2").AsSlice(),
				}},
			}},
		}}

		cmd := listCmdWithJSONFlag()
		require.NoError(t, cmd.Flags().Set("json", "true"))
		out := captureStdout(t, func() {
			require.NoError(t, showSRPolicyList(cmd, []string{}))
		})
		assert.Contains(t, out, `"policyName":"pol1"`)
	})

	t.Run("invalid session filter is rejected", func(t *testing.T) {
		cmd := listCmdWithJSONFlag()
		require.NoError(t, cmd.Flags().Set("session", "not-an-address"))
		err := showSRPolicyList(cmd, []string{})
		require.Error(t, err)
	})

	t.Run("session filter propagates to the request", func(t *testing.T) {
		fake := &fakePCEServiceClient{srPolicyListResp: &pb.GetSRPolicyListResponse{}}
		client = fake
		cmd := listCmdWithJSONFlag()
		require.NoError(t, cmd.Flags().Set("session", "192.0.2.1"))

		captureStdout(t, func() {
			require.NoError(t, showSRPolicyList(cmd, []string{}))
		})

		require.NotNil(t, fake.srPolicyListReq)
		assert.Equal(t, netip.MustParseAddr("192.0.2.1").AsSlice(), fake.srPolicyListReq.GetSessionAddr())
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		client = &fakePCEServiceClient{srPolicyListErr: assert.AnError}
		err := showSRPolicyList(listCmdWithJSONFlag(), []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve SR policy list")
	})
}
