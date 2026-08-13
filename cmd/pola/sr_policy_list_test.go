// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
