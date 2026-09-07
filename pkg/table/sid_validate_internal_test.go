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

func TestSIDIndexNextHop_ConflictingExactOwnerIsDeterministic(t *testing.T) {
	t.Parallel()

	t.Run("two nodes advertising the same SRv6 node SID resolve to owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{Sids: []string{"2001:db8::1"}}}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{{Sids: []string{"2001:db8::1"}}}}

		for range 20 {
			idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

			next, err := idx.NextHop(ownerUnknown, NewSegmentSRv6(netip.MustParseAddr("2001:db8::1")))
			require.NoError(t, err)
			assert.Equal(t, ownerUnknown, next, "conflicting owners must never resolve to whichever node was visited last")
		}
	})

	t.Run("two nodes advertising the same MPLS prefix SID label resolve to owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{
			RouterID:  "X",
			SrgbBegin: 16000,
			SrgbEnd:   17000,
			Prefixes:  []*LsPrefix{{HasSidIndex: true, SidIndex: 1}},
		}
		nodeY := &LsNode{
			RouterID:  "Y",
			SrgbBegin: 16000,
			SrgbEnd:   17000,
			Prefixes:  []*LsPrefix{{HasSidIndex: true, SidIndex: 1}},
		}

		for range 20 {
			idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

			next, err := idx.NextHop(ownerUnknown, NewSegmentSRMPLS(16001))
			require.NoError(t, err)
			assert.Equal(t, ownerUnknown, next, "conflicting owners must never resolve to whichever node was visited last")
		}
	})
}

func TestUSIDMicroSegmentPrefixes(t *testing.T) {
	t.Parallel()

	t.Run("block 32 node 16, three micro-segments", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100:0200:0300::")
		got := uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 32, nodeBits: 16})
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
		got := uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 32, nodeBits: 16})
		want := []netip.Prefix{
			netip.MustParsePrefix("fcbb:bb00:0100::/48"),
		}
		assert.Equal(t, want, got)
	})

	t.Run("nodeBits zero returns nil", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 32, nodeBits: 0}))
	})

	t.Run("nodeBits zero with function bits set still returns nil (LIB CSID is not decomposed)", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 32, nodeBits: 0, funcBits: 16}))
	})

	t.Run("blockBits negative returns nil", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: -1, nodeBits: 16}))
	})

	t.Run("funcBits negative returns nil", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 32, nodeBits: 16, funcBits: -1}))
	})

	t.Run("blockBits plus nodeBits exceeds 128 returns nil", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fcbb:bb00:0100::")
		assert.Nil(t, uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 120, nodeBits: 16}))
	})

	t.Run("non-byte-aligned nodeBits extracts bits correctly", func(t *testing.T) {
		t.Parallel()

		// block=0xA, segments=0x123 and 0x456 (12 bits each).
		sid := netip.AddrFrom16([16]byte{0xA1, 0x23, 0x45, 0x60})
		got := uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 4, nodeBits: 12})
		want := []netip.Prefix{
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xA1, 0x23}), 16),
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xA4, 0x56}), 16),
		}
		assert.Equal(t, want, got)
	})

	t.Run("128 bits used exactly with no padding", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("2001:db8:0:0:1:2:3:4")
		got := uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 64, nodeBits: 32})
		want := []netip.Prefix{
			netip.MustParsePrefix("2001:db8:0:0:1:2::/96"),
			netip.MustParsePrefix("2001:db8:0:0:3:4::/96"),
		}
		assert.Equal(t, want, got)
	})

	t.Run("FL>0: stride includes function bits, locator prefix excludes them", func(t *testing.T) {
		t.Parallel()

		sid := netip.AddrFrom16([16]byte{0xAA, 0xBB, 0xCC, 0xEE, 0xFF})
		got := uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 8, nodeBits: 8, funcBits: 8})
		want := []netip.Prefix{
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xAA, 0xBB}), 16),
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xAA, 0xEE}), 16),
		}
		assert.Equal(t, want, got)
	})

	t.Run("FL>0 non-byte-aligned: stride and locator width are independent", func(t *testing.T) {
		t.Parallel()

		sid := netip.AddrFrom16([16]byte{0xA1, 0x23, 0xF4, 0x56, 0x00})
		got := uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 4, nodeBits: 12, funcBits: 4})
		want := []netip.Prefix{
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xA1, 0x23}), 16),
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0xA4, 0x56}), 16),
		}
		assert.Equal(t, want, got)
	})

	t.Run("128 bits used exactly with FL padding included in stride", func(t *testing.T) {
		t.Parallel()

		// blockBits=32, nodeBits=16, funcBits=16 -> stride=32; exactly 3 hops fit in 128 bits.
		structure := srv6Structure{blockBits: 32, nodeBits: 16, funcBits: 16}
		raw := [16]byte{0xFC, 0xBB, 0xBB, 0x00, 0x01, 0x00, 0xFF, 0xFF, 0x02, 0x00, 0xAA, 0xAA, 0x03, 0x00, 0xBB, 0xBB}
		got := uSIDMicroSegmentPrefixes(netip.AddrFrom16(raw), structure)
		want := []netip.Prefix{
			netip.MustParsePrefix("fcbb:bb00:0100::/48"),
			netip.MustParsePrefix("fcbb:bb00:0200::/48"),
			netip.MustParsePrefix("fcbb:bb00:0300::/48"),
		}
		assert.Equal(t, want, got)
	})

	t.Run("does not emit a partial slot when function bits exceed the SID", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("2001:db8::1")
		got := uSIDMicroSegmentPrefixes(sid, srv6Structure{blockBits: 32, nodeBits: 16, funcBits: 81})
		assert.Empty(t, got)
	})
}

func TestSRv6LocatorLookup(t *testing.T) {
	t.Parallel()

	t.Run("longest prefix match: nested locators pick the most specific", func(t *testing.T) {
		t.Parallel()

		idx := &SIDIndex{srv6Locators: map[netip.Prefix]srv6LocatorInfo{
			netip.MustParsePrefix("2001:db8::/32"):   {owner: "broad", structure: srv6Structure{blockBits: 16, nodeBits: 16}, structureKnown: true},
			netip.MustParsePrefix("2001:db8:1::/48"): {owner: "specific", structure: srv6Structure{blockBits: 32, nodeBits: 16}, structureKnown: true},
		}}

		addr := netip.MustParseAddr("2001:db8:1::1")

		info, found := idx.lookupSRv6Locator(addr, -1)
		require.True(t, found)
		assert.Equal(t, "specific", info.owner)
	})

	t.Run("maxBits excludes a too-specific locator, falling back to the broader one", func(t *testing.T) {
		t.Parallel()

		idx := &SIDIndex{srv6Locators: map[netip.Prefix]srv6LocatorInfo{
			netip.MustParsePrefix("2001:db8::/32"):   {owner: "broad", structureKnown: true},
			netip.MustParsePrefix("2001:db8:1::/48"): {owner: "specific", structureKnown: true},
		}}

		addr := netip.MustParseAddr("2001:db8:1::1")

		info, found := idx.lookupSRv6Locator(addr, 32)
		require.True(t, found)
		assert.Equal(t, "broad", info.owner)
	})

	t.Run("no containing locator", func(t *testing.T) {
		t.Parallel()

		idx := &SIDIndex{srv6Locators: map[netip.Prefix]srv6LocatorInfo{
			netip.MustParsePrefix("2001:db8::/32"): {owner: "broad", structureKnown: true},
		}}

		_, found := idx.lookupSRv6Locator(netip.MustParseAddr("fd00::1"), -1)
		assert.False(t, found)
	})
}

func TestSRv6LocatorMerge(t *testing.T) {
	t.Parallel()

	t.Run("same owner, conflicting structure: owner known, structure unknown", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16}},
			{Sids: []string{"fcbb:bb00:0100::1"}, SIDStructure: &SIDStructure{LocalBlock: 16, LocalNode: 32}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(node))

		info, found := idx.lookupSRv6Locator(netip.MustParseAddr("fcbb:bb00:0100::"), -1)
		require.True(t, found)
		assert.Equal(t, "X", info.owner)
		assert.False(t, info.structureKnown, "conflicting structures for the same prefix must not be resolved by last-write-wins")
	})

	t.Run("conflicting owners, same structure: structure known, owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16}},
		}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fcbb:bb00:0100::1"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

		info, found := idx.lookupSRv6Locator(netip.MustParseAddr("fcbb:bb00:0100::"), -1)
		require.True(t, found)
		assert.Equal(t, ownerUnknown, info.owner)
		assert.True(t, info.structureKnown, "an owner collision must not also mark the agreed-upon structure as unknown")
	})

	t.Run("conflicting owners and conflicting structure: both unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16}},
		}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fcbb:bb00:0100::1"}, SIDStructure: &SIDStructure{LocalBlock: 16, LocalNode: 32}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

		info, found := idx.lookupSRv6Locator(netip.MustParseAddr("fcbb:bb00:0100::"), -1)
		require.True(t, found)
		assert.Equal(t, ownerUnknown, info.owner)
		assert.False(t, info.structureKnown)
	})
}

func TestAddSRv6_StructurePresence(t *testing.T) {
	t.Parallel()

	t.Run("absent structure registers the exact SID but no locator", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fc00:1::1"}, SIDStructure: nil},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(node))

		assert.Empty(t, idx.srv6Locators, "no structure was advertised, so no locator can be derived")
		assert.True(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr("fc00:1::1"))))
	})

	t.Run("LocalNode zero with LocalBlock set registers a locator, not skipped as if absent", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fc00:1::1"}, SIDStructure: &SIDStructure{LocalBlock: 32}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(node))

		info, found := idx.lookupSRv6Locator(netip.MustParseAddr("fc00:1::1"), -1)
		require.True(t, found, "expected a /32 locator despite LocalNode being 0")
		assert.Equal(t, "X", info.owner)
	})

	t.Run("LIB C-SID shape (LocalBlock=0, LocalNode=0, LocalFunc>0) registers the exact SID but no locator", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fc00::1"}, SIDStructure: &SIDStructure{LocalFunc: 16}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(node))

		assert.True(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr("fc00::1"))), "expected the exact SID to still be registered")
		assert.Empty(t, idx.srv6Locators, "a zero-width locator carries no usable per-node prefix, present or not")
	})

	t.Run("absent and present-but-zero structures both skip the locator, but neither drops the exact SID", func(t *testing.T) {
		t.Parallel()

		nodeAbsent := &LsNode{RouterID: "absent", SRv6SIDs: []*LsSrv6SID{{Sids: []string{"fc00::1"}}}}
		nodePresentZero := &LsNode{RouterID: "zero", SRv6SIDs: []*LsSrv6SID{{Sids: []string{"fc00::2"}, SIDStructure: &SIDStructure{}}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeAbsent, nodePresentZero))

		assert.Empty(t, idx.srv6Locators)
		assert.True(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr("fc00::1"))))
		assert.True(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr("fc00::2"))))
	})
}

func TestUSIDContainerOwner(t *testing.T) {
	t.Parallel()

	t.Run("fully resolved returns last micro-segment owner", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0200::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeZ := &LsNode{RouterID: "Z", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0300::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY, nodeZ))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100:0200:0300::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, "Z", owner)
	})

	t.Run("resolved owner is the last micro-segment's, not the first's", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0200::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100:0200::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, "Y", owner)
		assert.NotEqual(t, "X", owner)
	})

	t.Run("single micro-segment container resolves to its sole owner", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, "X", owner)
	})

	t.Run("partially resolved degrades to owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeZ := &LsNode{RouterID: "Z", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0300::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeZ))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100:0200:0300::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner)
	})

	t.Run("not within any known locator", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX))

		seg := NewSegmentSRv6(netip.MustParseAddr("fd00:bb00:0100:0200:0300::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		_, matched := idx.usidContainerOwner(seg)
		assert.False(t, matched)
	})

	t.Run("container has no micro-segments beyond the locator returns owner unknown but matched", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0000::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX))

		// The first micro-segment is all zero, marking the container end (RFC 9800 §5).
		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0000::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner)
	})

	t.Run("same locator advertised by two nodes degrades to owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner)
	})

	t.Run("locator structure conflict with no declared structure degrades to owner unknown", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16}},
			{Sids: []string{"fcbb:bb00:0100::1"}, SIDStructure: &SIDStructure{LocalBlock: 16, LocalNode: 32}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(node))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100::"))
		seg.USid = true

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched, "the container is still within a known locator")
		assert.Equal(t, ownerUnknown, owner, "ambiguous locator structure must not be guessed")
	})

	t.Run("declared structure overrides an ambiguous locator structure", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16}},
			{Sids: []string{"fcbb:bb00:0100::1"}, SIDStructure: &SIDStructure{LocalBlock: 16, LocalNode: 32}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(node))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100::"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, "X", owner)
	})

	t.Run("no declared structure and a later micro-segment's locator structure disagrees", func(t *testing.T) {
		t.Parallel()

		nodeA := &LsNode{RouterID: "A", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeB := &LsNode{RouterID: "B", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0200::"}, SIDStructure: &SIDStructure{LocalBlock: 16, LocalNode: 32},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeA, nodeB))

		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100:0200::"))
		seg.USid = true

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner, "the second micro-segment's own locator disagrees with the container's structure")
	})

	t.Run("nested locators: no declared structure selects the most specific locator", func(t *testing.T) {
		t.Parallel()

		nodeBroad := &LsNode{RouterID: "broad", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"1234::"}, SIDStructure: &SIDStructure{LocalBlock: 8, LocalNode: 8}},
		}}
		nodeSpecific := &LsNode{RouterID: "specific", SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"1234:5678::"}, SIDStructure: &SIDStructure{LocalBlock: 16, LocalNode: 16}},
		}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeBroad, nodeSpecific))

		seg := NewSegmentSRv6(netip.MustParseAddr("1234:5678::"))
		seg.USid = true

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, "specific", owner)
	})

	t.Run("node-bits=0 locator resolves directly to its sole owner, not decomposed", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fc00:1::1"}, SIDStructure: &SIDStructure{LocalBlock: 32},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX))

		seg := NewSegmentSRv6(netip.MustParseAddr("fc00:1::1"))
		seg.USid = true

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched, "a node-bits=0 locator is a known, if non-decomposable, match")
		assert.Equal(t, "X", owner)
	})

	t.Run("node-bits=0 locator advertised by two nodes degrades to owner unknown", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fc00:1::1"}, SIDStructure: &SIDStructure{LocalBlock: 32},
		}}}
		nodeY := &LsNode{RouterID: "Y", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fc00:1::2"}, SIDStructure: &SIDStructure{LocalBlock: 32},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX, nodeY))

		seg := NewSegmentSRv6(netip.MustParseAddr("fc00:1::1"))
		seg.USid = true

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, ownerUnknown, owner, "conflicting owners for the same node-bits=0 locator must not be guessed")
	})

	t.Run("declared structure with node-bits=0 resolves to the matched locator's owner", func(t *testing.T) {
		t.Parallel()

		nodeX := &LsNode{RouterID: "X", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fc00:1::1"}, SIDStructure: &SIDStructure{LocalBlock: 32},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeX))

		seg := NewSegmentSRv6(netip.MustParseAddr("fc00:1::1"))
		seg.USid = true
		seg.Structure = &SIDStructure{LocalBlock: 32, LocalNode: 0, LocalFunc: 16, LocalArg: 0}

		owner, matched := idx.usidContainerOwner(seg)
		require.True(t, matched)
		assert.Equal(t, "X", owner)
	})

	t.Run("nested locator: a node-bits=0 umbrella and a more specific node-bits>0 locator resolve independently", func(t *testing.T) {
		t.Parallel()

		nodeUmbrella := &LsNode{RouterID: "umbrella", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb::1"}, SIDStructure: &SIDStructure{LocalBlock: 16},
		}}}
		nodeA := &LsNode{RouterID: "A", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0100::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		nodeB := &LsNode{RouterID: "B", SRv6SIDs: []*LsSrv6SID{{
			Sids: []string{"fcbb:bb00:0200::"}, SIDStructure: &SIDStructure{LocalBlock: 32, LocalNode: 16},
		}}}
		idx := NewSIDIndex(newSIDValidateInternalTestTED(nodeUmbrella, nodeA, nodeB))

		t.Run("address outside the nested locator falls back to the flat umbrella owner", func(t *testing.T) {
			t.Parallel()

			seg := NewSegmentSRv6(netip.MustParseAddr("fcbb::1"))
			seg.USid = true

			owner, matched := idx.usidContainerOwner(seg)
			require.True(t, matched)
			assert.Equal(t, "umbrella", owner)
		})

		t.Run("address within the nested locator still decomposes through the uSID chain", func(t *testing.T) {
			t.Parallel()

			seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:0100:0200::"))
			seg.USid = true

			owner, matched := idx.usidContainerOwner(seg)
			require.True(t, matched)
			assert.Equal(t, "B", owner)
		})
	})
}
