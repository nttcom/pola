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
	t.Parallel()

	ss := grpc.SRPolicySession{
		PeerAddr:  netip.MustParseAddr(testPeerAddr1),
		State:     "up",
		SyncState: "finished",
		SRPolicies: []table.SRPolicy{
			{Name: testPolicyName},
		},
	}

	v := newSRPolicySessionView(ss)
	assert.Equal(t, testPeerAddr1, v.PeerAddress)
	assert.Equal(t, "up", v.State)
	assert.Equal(t, "finished", v.LSPDBSync)
	assert.Equal(t, []table.SRPolicy{{Name: testPolicyName}}, v.SRPolicies)
}

func TestNewSRPolicySessionView_NilSRPoliciesBecomesEmptySlice(t *testing.T) {
	t.Parallel()

	ss := grpc.SRPolicySession{PeerAddr: netip.MustParseAddr(testPeerAddr1), State: "up", SyncState: "pending"}

	v := newSRPolicySessionView(ss)
	require.NotNil(t, v.SRPolicies)
	assert.Empty(t, v.SRPolicies)
}
