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

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/pkg/table"
)

func TestNewSRPolicySessionView(t *testing.T) {
	ss := grpc.SRPolicySession{
		PeerAddr:  netip.MustParseAddr("192.0.2.1"),
		State:     "up",
		SyncState: "finished",
		SRPolicies: []table.SRPolicy{
			{Name: "pol1"},
		},
	}

	v := newSRPolicySessionView(ss)
	assert.Equal(t, "192.0.2.1", v.PeerAddress)
	assert.Equal(t, "up", v.State)
	assert.Equal(t, "finished", v.LSPDBSync)
	assert.Equal(t, []table.SRPolicy{{Name: "pol1"}}, v.SRPolicies)
}

func TestNewSRPolicySessionView_NilSRPoliciesBecomesEmptySlice(t *testing.T) {
	ss := grpc.SRPolicySession{PeerAddr: netip.MustParseAddr("192.0.2.1"), State: "up", SyncState: "pending"}

	v := newSRPolicySessionView(ss)
	require.NotNil(t, v.SRPolicies)
	assert.Empty(t, v.SRPolicies)
}
