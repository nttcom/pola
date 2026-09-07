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

func TestUSIDMicroSegmentPrefixes(t *testing.T) {
	t.Parallel()

	t.Run("block 32 node 16, three micro-segments", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100:0200:0300::")
		got := uSIDMicroSegmentPrefixes(sid, 32, 16)
		want := []netip.Prefix{
			netip.MustParsePrefix("fcbb:bb00:0100::/48"),
			netip.MustParsePrefix("fcbb:bb00:0200::/48"),
			netip.MustParsePrefix("fcbb:bb00:0300::/48"),
		}
		assert.Equal(t, want, got)
	})

	t.Run("stops at zero micro-segment", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100:0000:0300::")
		got := uSIDMicroSegmentPrefixes(sid, 32, 16)
		want := []netip.Prefix{
			netip.MustParsePrefix("fcbb:bb00:0100::/48"),
		}
		assert.Equal(t, want, got)
	})

	t.Run("nodeBits zero returns nil", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, 32, 0))
	})

	t.Run("blockBits negative returns nil", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, -1, 16))
	})

	t.Run("blockBits plus nodeBits exceeds 128 returns nil", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, 120, 16))
	})

	t.Run("non-byte-aligned nodeBits extracts bits correctly", func(t *testing.T) {
		t.Parallel()

		// block=0xA, segments=0x123 and 0x456 (12 bits each).
		sid := netip.AddrFrom16([16]byte{0xA1, 0x23, 0x45, 0x60})
		got := uSIDMicroSegmentPrefixes(sid, 4, 12)
		want := []netip.Prefix{
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xA1, 0x23}), 16),
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xA4, 0x56}), 16),
		}
		assert.Equal(t, want, got)
	})

	t.Run("128 bits used exactly with no padding", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("2001:db8:0:0:1:2:3:4")
		got := uSIDMicroSegmentPrefixes(sid, 64, 32)
		want := []netip.Prefix{
			netip.MustParsePrefix("2001:db8:0:0:1:2::/96"),
			netip.MustParsePrefix("2001:db8:0:0:3:4::/96"),
		}
		assert.Equal(t, want, got)
	})
}

func TestUSIDContainerOwner(t *testing.T) {
	t.Parallel()

	t.Run("fully resolved returns last micro-segment owner", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0200::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeZ := &LsNode{RouterID: "Z", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0300::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY, nodeZ))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100:0200:0300::"))
		seg.USid = true
		seg.Structure = SIDStructureBytes{32, 16, 16, 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, "Z", owner)
	})

	t.Run("partially resolved degrades to owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeZ := &LsNode{RouterID: "Z", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0300::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeZ))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100:0200:0300::"))
		seg.USid = true
		seg.Structure = SIDStructureBytes{32, 16, 16, 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner)
	})

	t.Run("not within any known locator", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX))

		seg := NewSegmentSRv6(netip.MustParseAddr("fd00:bb00:0100:0200:0300::"))
		seg.USid = true
		seg.Structure = SIDStructureBytes{32, 16, 16, 0}

		_, matched := idx.usidContainerOwner(seg)
		assert.False(t, matched)
	})

	t.Run("container has no micro-segments beyond the locator returns owner unknown but matched", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0000::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX))

		// The first micro-segment is all zero, marking the container end (RFC 9800 §5).
		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0000::"))
		seg.USid = true
		seg.Structure = SIDStructureBytes{32, 16, 16, 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner)
	})

	t.Run("same locator advertised by two nodes degrades to owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100::"))
		seg.USid = true
		seg.Structure = SIDStructureBytes{32, 16, 16, 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner)
	})
}
