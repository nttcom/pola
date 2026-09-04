// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sidValidateInternalTestRouterID1 = "0000.0000.0001"

func newSIDValidateInternalTestTED(nodes ...*LsNode) *LsTED {
	m := make(map[string]*LsNode, len(nodes))
	for _, n := range nodes {
		m[n.RouterID] = n
	}

	return &LsTED{Nodes: m}
}

func TestSIDIndexNextHop_OwnerUnknownBranches(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID: sidValidateInternalTestRouterID1,
		Links: []*LsLink{
			{AdjSid: 24001, Srv6EndXSID: &Srv6EndXSID{Sids: []string{"2001:db8::a"}}},
		},
		SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"2001:db8::1"}},
		},
	}
	idx := NewSIDIndex(newSIDValidateInternalTestTED(node))

	t.Run("owner unknown with known SR-MPLS SID", func(t *testing.T) {
		t.Parallel()

		next, err := idx.NextHop(ownerUnknown, NewSegmentSRMPLS(24001))
		require.NoError(t, err)
		assert.Equal(t, ownerUnknown, next)
	})

	t.Run("owner unknown with unknown SR-MPLS SID", func(t *testing.T) {
		t.Parallel()

		_, err := idx.NextHop(ownerUnknown, NewSegmentSRMPLS(16099))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in TED")
	})

	t.Run("owner unknown with known SRv6 adjacency SID", func(t *testing.T) {
		t.Parallel()

		next, err := idx.NextHop(ownerUnknown, NewSegmentSRv6(netip.MustParseAddr("2001:db8::a")))
		require.NoError(t, err)
		assert.Equal(t, ownerUnknown, next)
	})

	t.Run("owner unknown with unknown SRv6 SID", func(t *testing.T) {
		t.Parallel()

		_, err := idx.NextHop(ownerUnknown, NewSegmentSRv6(netip.MustParseAddr("2001:db8::99")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in TED")
	})
}
