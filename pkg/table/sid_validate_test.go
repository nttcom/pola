// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

const (
	testRouterID1    = "0000.0000.0001"
	testRouterIDA    = "0000.0000.000a"
	testRouterIDB    = "0000.0000.000b"
	testRouterIDC    = "0000.0000.000c"
	testInvalidAddr  = "not-an-address"
	testSRv6SID1     = "2001:db8::1"
	testSRv6SID2     = "2001:db8::2"
	testSRv6ExactSID = "2001:db8:1::"
)

func newTestTED(nodes ...*table.LsNode) *table.LsTED {
	m := make(map[string]*table.LsNode, len(nodes))
	for _, n := range nodes {
		m[n.RouterID] = n
	}

	return &table.LsTED{Nodes: m}
}

func TestSIDIndexHas_SRMPLS(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
		Links: []*table.LsLink{
			{AdjSids: []table.AdjSID{{Sid: 24001}}},
		},
	}
	ted := newTestTED(node)

	tests := []struct {
		name string
		seg  table.Segment
		want bool
	}{
		{"prefix SID match", table.NewSegmentSRMPLS(16003), true},
		{"adj SID match", table.NewSegmentSRMPLS(24001), true},
		{"unknown label", table.NewSegmentSRMPLS(16099), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idx := table.NewSIDIndex(ted)
			assert.Equal(t, tt.want, idx.Has(tt.seg))
		})
	}
}

func TestSIDIndexHas_SRMPLS_SrgbBeginZero(t *testing.T) {
	t.Parallel()

	// Without an SRGB, a Prefix-SID index cannot be converted to a label.
	node := &table.LsNode{
		RouterID: testRouterID1,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 16003, HasSidIndex: true},
		},
	}
	idx := table.NewSIDIndex(newTestTED(node))
	assert.False(t, idx.Has(table.NewSegmentSRMPLS(16003)), "expected SidIndex not to be registered when SrgbBegin is unavailable")
}

func TestSIDIndexHas_SRMPLS_PrefixSIDIndexZero(t *testing.T) {
	t.Parallel()

	// Prefix-SID index 0 is a valid index: SRGB begin + 0 must be registered
	// when the Prefix-SID TLV was actually advertised.
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
		},
	}
	idx := table.NewSIDIndex(newTestTED(node))
	assert.True(t, idx.Has(table.NewSegmentSRMPLS(16000)), "expected Prefix-SID index 0 to be registered as label 16000")
}

func TestSIDIndexHas_SRMPLS_NoPrefixSID(t *testing.T) {
	t.Parallel()

	// A prefix without a Prefix-SID TLV must not register the SRGB begin label.
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
		},
	}
	idx := table.NewSIDIndex(newTestTED(node))
	assert.False(t, idx.Has(table.NewSegmentSRMPLS(16000)), "expected no MPLS SID for a prefix without a Prefix-SID")
}

func TestSIDIndexHas_SRMPLS_PrefixSIDRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		node  *table.LsNode
		label uint32
		want  bool
	}{
		{
			name: "index inside the SRGB",
			node: &table.LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*table.LsPrefix{{SidIndex: 3, HasSidIndex: true}},
			},
			label: 16003,
			want:  true,
		},
		{
			name: "last index of the SRGB (SrgbEnd is exclusive)",
			node: &table.LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*table.LsPrefix{{SidIndex: 7999, HasSidIndex: true}},
			},
			label: 23999,
			want:  true,
		},
		{
			name: "index at SrgbEnd is outside the SRGB",
			node: &table.LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*table.LsPrefix{{SidIndex: 8000, HasSidIndex: true}},
			},
			label: 24000,
			want:  false,
		},
		{
			name: "index beyond the SRGB",
			node: &table.LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*table.LsPrefix{{SidIndex: 100000, HasSidIndex: true}},
			},
			label: 116000,
			want:  false,
		},
		{
			name: "label beyond the 20-bit MPLS range without an SRGB end",
			node: &table.LsNode{
				RouterID: testRouterID1, SrgbBegin: 1000000,
				Prefixes: []*table.LsPrefix{{SidIndex: 100000, HasSidIndex: true}},
			},
			label: 1100000,
			want:  false,
		},
		{
			name: "index that would overflow uint32",
			node: &table.LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000,
				Prefixes: []*table.LsPrefix{{SidIndex: 0xFFFFFFFF, HasSidIndex: true}},
			},
			label: 15999, // 16000 + 0xFFFFFFFF wrapped around
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idx := table.NewSIDIndex(newTestTED(tt.node))
			assert.Equal(t, tt.want, idx.Has(table.NewSegmentSRMPLS(tt.label)))
		})
	}
}

func TestLsPrefixHasPrefixSID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix *table.LsPrefix
		want   bool
	}{
		{"nil prefix", nil, false},
		{"no Prefix-SID", &table.LsPrefix{}, false},
		{"advertised index 0", &table.LsPrefix{HasSidIndex: true}, true},
		{"advertised non-zero index", &table.LsPrefix{SidIndex: 3, HasSidIndex: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.prefix.HasPrefixSID())
		})
	}
}

func TestSIDIndexHas_SRv6Exact(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{
		RouterID: testRouterID1,
		SRv6SIDs: []*table.LsSrv6SID{
			{Sids: []string{testSRv6ExactSID}, SIDStructure: &table.SIDStructure{}},
		},
		Links: []*table.LsLink{
			{
				Srv6EndXSIDs: []*table.Srv6EndXSID{{
					Sids:             []string{"2001:db8:1::1"},
					Srv6SIDStructure: &table.SIDStructure{},
				}},
			},
		},
	}
	ted := newTestTED(node)

	tests := []struct {
		name string
		seg  table.Segment
		want bool
	}{
		{"End SID exact match", table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6ExactSID))), true},
		{"End.X SID exact match", table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("2001:db8:1::1"))), true},
		{"unknown SID", table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("2001:db8:1::99"))), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idx := table.NewSIDIndex(ted)
			assert.Equal(t, tt.want, idx.Has(tt.seg))
		})
	}
}

func TestSIDIndexHas_USID(t *testing.T) {
	t.Parallel()

	// TED advertises a locator of block=32, node=16 bits -> fcbb:bb00:0100::/48.
	node := &table.LsNode{
		RouterID: testRouterID1,
		SRv6SIDs: []*table.LsSrv6SID{
			{
				Sids:         []string{"fcbb:bb00:0100::"},
				SIDStructure: &table.SIDStructure{LocalBlock: 32, LocalNode: 16},
			},
		},
	}
	ted := newTestTED(node)

	container := netip.MustParseAddr("fcbb:bb00:0100:0200:0300::")

	t.Run("structure present, container within locator", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(table.SRv6SID(container))
		seg.USid = true
		seg.Structure = &table.SIDStructure{LocalBlock: 32, LocalNode: 16}
		assert.True(t, table.NewSIDIndex(ted).Has(seg), "expected uSID container to be accepted via locator containment")
	})

	t.Run("no structure, falls back to containment", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(table.SRv6SID(container))
		seg.USid = true
		assert.True(t, table.NewSIDIndex(ted).Has(seg), "expected uSID container without structure to be accepted via containment fallback")
	})

	t.Run("declared locator shorter than TED advertised", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(table.SRv6SID(container))
		seg.USid = true
		// Declares a /32 locator (block=24,node=8), which contradicts the /48
		// the TED actually advertises.
		seg.Structure = &table.SIDStructure{LocalBlock: 24, LocalNode: 8, LocalFunc: 16}
		assert.False(t, table.NewSIDIndex(ted).Has(seg), "expected mismatch when declared locator is shorter than TED advertised")
	})

	t.Run("declared zero-width locator does not match an unrelated enclosing TED locator", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(table.SRv6SID(container))
		seg.USid = true
		seg.Structure = &table.SIDStructure{LocalFunc: 48}
		assert.False(t, table.NewSIDIndex(ted).Has(seg), "expected declared zero-width locator not to match an unrelated enclosing TED locator")
	})

	t.Run("outside any known locator", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fcbb:bb00:ffff::")))
		seg.USid = true
		assert.False(t, table.NewSIDIndex(ted).Has(seg), "expected mismatch for a SID outside any known locator")
	})

	t.Run("non-uSID segment does not fall back to locator containment", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(table.SRv6SID(container))
		assert.False(t, table.NewSIDIndex(ted).Has(seg), "expected non-uSID segment to require an exact SID match")
	})
}

func TestMissingSegmentString(t *testing.T) {
	t.Parallel()

	m := table.MissingSegment{Hop: 2, SID: "16099"}
	assert.Equal(t, "hop 2 (16099)", m.String())
}

func TestNewSIDIndex_SkipsNilNode(t *testing.T) {
	t.Parallel()

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{testRouterID1: nil}}
	idx := table.NewSIDIndex(ted)
	assert.False(t, idx.Has(table.NewSegmentSRMPLS(16003)), "expected no panic and no match when a map entry is nil")
}

func TestSIDIndexAddLinkSIDs_SkipsNilLink(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{
		RouterID: testRouterID1,
		Links:    []*table.LsLink{nil, {AdjSids: []table.AdjSID{{Sid: 24001}}}},
	}
	idx := table.NewSIDIndex(newTestTED(node))
	assert.True(t, idx.Has(table.NewSegmentSRMPLS(24001)), "expected the adj SID after the nil link to still be registered")
}

func TestSIDIndexHas_UnknownSegmentType(t *testing.T) {
	t.Parallel()

	idx := table.NewSIDIndex(newTestTED())
	assert.False(t, idx.Has(fakeUnknownSegment{}))
}

func TestSIDIndexAddSRv6_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("non-IPv6 SID is not registered", func(t *testing.T) {
		t.Parallel()

		node := &table.LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"10.0.0.1"}}},
		}
		idx := table.NewSIDIndex(newTestTED(node))
		assert.False(t, idx.Has(table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("10.0.0.1")))), "expected an IPv4 address advertised as an SRv6 SID to be ignored")
	})

	t.Run("unparsable SID is not registered", func(t *testing.T) {
		t.Parallel()

		node := &table.LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{testInvalidAddr}}},
		}
		idx := table.NewSIDIndex(newTestTED(node))
		assert.False(t, idx.Has(table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID1)))))
	})

	t.Run("zero locator length still registers the exact SID but skips the locator", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fc00:0:1::")
		node := &table.LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{sid.String()}, SIDStructure: &table.SIDStructure{}}},
		}
		idx := table.NewSIDIndex(newTestTED(node))
		assert.True(t, idx.Has(table.NewSegmentSRv6(table.SRv6SID(sid))), "expected exact match regardless of locator length")

		other := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fc00:0:1::1234")))
		other.USid = true
		assert.False(t, idx.Has(other), "expected no locator fallback registered when LocalBlock+LocalNode is 0")
	})

	t.Run("locator length beyond 128 bits is not registered", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fc00:0:1::")
		node := &table.LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{sid.String()}, SIDStructure: &table.SIDStructure{LocalBlock: 200, LocalNode: 200}}},
		}
		idx := table.NewSIDIndex(newTestTED(node))
		assert.True(t, idx.Has(table.NewSegmentSRv6(table.SRv6SID(sid))), "expected exact match regardless of locator length")

		other := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fc00:0:1::1234")))
		other.USid = true
		assert.False(t, idx.Has(other), "expected no locator fallback registered when LocalBlock+LocalNode exceeds 128 bits")
	})

	t.Run("total structure width exceeds 128 bits is not registered", func(t *testing.T) {
		t.Parallel()

		sid := netip.MustParseAddr("fc00:0:1::")
		node := &table.LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*table.LsSrv6SID{{
				Sids: []string{sid.String()},
				SIDStructure: &table.SIDStructure{
					LocalBlock: 32,
					LocalNode:  16,
					LocalFunc:  50,
					LocalArg:   31,
				},
			}},
		}
		idx := table.NewSIDIndex(newTestTED(node))
		assert.True(t, idx.Has(table.NewSegmentSRv6(table.SRv6SID(sid))), "expected exact match regardless of total width")

		other := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fc00:0:1::1234")))
		other.USid = true
		assert.False(t, idx.Has(other), "expected no locator fallback registered when LocalBlock+LocalNode+LocalFunc+LocalArg exceeds 128 bits")
	})

	t.Run("non-IPv6 node SID is not reachable via NextHop either", func(t *testing.T) {
		t.Parallel()

		node := &table.LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"10.0.0.1"}}},
		}
		idx := table.NewSIDIndex(newTestTED(node))

		seg := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("10.0.0.1")))
		assert.False(t, idx.Has(seg))
		_, err := idx.NextHop(testRouterID1, seg)
		assert.Error(t, err, "expected NextHop to agree with Has() for a non-IPv6 advertised SID")
	})

	t.Run("non-IPv6 End.X SID is not reachable via NextHop either", func(t *testing.T) {
		t.Parallel()

		nodeA := &table.LsNode{RouterID: testRouterIDA}
		nodeB := &table.LsNode{RouterID: testRouterIDB}
		nodeA.Links = []*table.LsLink{{
			Local:        table.LinkEndpoint{Node: nodeA},
			Remote:       table.LinkEndpoint{Node: nodeB},
			Srv6EndXSIDs: []*table.Srv6EndXSID{{Sids: []string{"10.0.0.1"}}},
		}}
		idx := table.NewSIDIndex(newTestTED(nodeA, nodeB))

		seg := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("10.0.0.1")))
		assert.False(t, idx.Has(seg))
		_, err := idx.NextHop(testRouterIDA, seg)
		assert.Error(t, err, "expected NextHop to agree with Has() for a non-IPv6 advertised End.X SID")
	})
}

func TestSIDIndexHas_EmptyTED(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ted  *table.LsTED
	}{
		{"nil TED", nil},
		{"TED with no nodes", newTestTED()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idx := table.NewSIDIndex(tt.ted)
			assert.False(t, idx.Has(table.NewSegmentSRMPLS(16003)), "expected no match against an empty TED")
			assert.False(t, idx.Has(table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6ExactSID)))), "expected no match against an empty TED")
		})
	}
}

func TestMissingSegments(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := newTestTED(node)

	segmentList := []table.Segment{
		table.NewSegmentSRMPLS(16003),
		table.NewSegmentSRMPLS(16099),
		table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("2001:db8:1::99"))),
	}

	want := []table.MissingSegment{
		{Hop: 2, SID: "16099"},
		{Hop: 3, SID: "2001:db8:1::99"},
	}
	assert.Equal(t, want, table.MissingSegments(ted, segmentList))
}

type fakeUnknownSegment struct{}

func (fakeUnknownSegment) SidString() string       { return "unknown" }
func (fakeUnknownSegment) Family() table.DataPlane { return table.DPUnspecified }

func TestHasUnknownSegmentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		segs []table.Segment
		want bool
	}{
		{
			name: "all known, SR-MPLS",
			segs: []table.Segment{table.NewSegmentSRMPLS(16001), table.NewSegmentSRMPLS(16002)},
			want: false,
		},
		{
			name: "all known, SRv6",
			segs: []table.Segment{table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID1)))},
			want: false,
		},
		{
			name: "contains nil only",
			segs: []table.Segment{nil, nil},
			want: false,
		},
		{
			name: "empty list",
			segs: []table.Segment{},
			want: false,
		},
		{
			name: "contains unknown family",
			segs: []table.Segment{table.NewSegmentSRMPLS(16001), fakeUnknownSegment{}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, table.HasUnknownSegmentType(tt.segs))
		})
	}
}

func TestOutOfRangeSRMPLSLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		segs []table.Segment
		want []table.MissingSegment
	}{
		{
			name: "lower bound is valid",
			segs: []table.Segment{table.NewSegmentSRMPLS(0)},
		},
		{
			name: "upper bound is valid",
			segs: []table.Segment{table.NewSegmentSRMPLS(1048575)},
		},
		{
			name: "one past the upper bound is rejected",
			segs: []table.Segment{table.NewSegmentSRMPLS(1048576)},
			want: []table.MissingSegment{{Hop: 1, SID: "1048576"}},
		},
		{
			name: "reports the offending hop only",
			segs: []table.Segment{
				table.NewSegmentSRMPLS(16001),
				table.NewSegmentSRMPLS(1048576),
			},
			want: []table.MissingSegment{{Hop: 2, SID: "1048576"}},
		},
		{
			name: "SRv6 and nil segments are ignored",
			segs: []table.Segment{nil, table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID1)))},
		},
		{
			name: "empty list",
			segs: []table.Segment{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, table.OutOfRangeSRMPLSLabels(tt.segs))
		})
	}
}

func TestHasMixedSegmentTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		segs []table.Segment
		want bool
	}{
		{
			name: "all SRv6",
			segs: []table.Segment{
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID1))),
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID2))),
			},
			want: false,
		},
		{
			name: "all SR-MPLS",
			segs: []table.Segment{table.NewSegmentSRMPLS(16001), table.NewSegmentSRMPLS(16002)},
			want: false,
		},
		{
			name: "mixed SRv6 then SR-MPLS",
			segs: []table.Segment{
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID1))),
				table.NewSegmentSRMPLS(16001),
			},
			want: true,
		},
		{
			name: "mixed SR-MPLS then SRv6",
			segs: []table.Segment{
				table.NewSegmentSRMPLS(16001),
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID1))),
			},
			want: true,
		},
		{
			name: "SRv6 with unknown family",
			segs: []table.Segment{
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6SID1))),
				fakeUnknownSegment{},
			},
			want: false,
		},
		{
			name: "SR-MPLS with unknown family",
			segs: []table.Segment{table.NewSegmentSRMPLS(16001), fakeUnknownSegment{}},
			want: false,
		},
		{
			name: "nil segment does not count toward either family",
			segs: []table.Segment{nil, table.NewSegmentSRMPLS(16001)},
			want: false,
		},
		{
			name: "empty list",
			segs: []table.Segment{},
			want: false,
		},
		{
			name: "single SR-MPLS",
			segs: []table.Segment{table.NewSegmentSRMPLS(16001)},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, table.HasMixedSegmentTypes(tt.segs))
		})
	}
}

func TestValidateExplicitPath(t *testing.T) {
	t.Parallel()

	// Topology: A --adj24001--> B --adj24002--> C
	// A has node SID 16001, B has node SID 16002, C has node SID 16003.
	nodeA := &table.LsNode{
		RouterID:  testRouterIDA,
		SrgbBegin: 16000,
		Prefixes:  []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.10/32"), SidIndex: 1, HasSidIndex: true}},
	}
	nodeB := &table.LsNode{
		RouterID:  testRouterIDB,
		SrgbBegin: 16000,
		Prefixes:  []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.11/32"), SidIndex: 2, HasSidIndex: true}},
	}
	nodeC := &table.LsNode{
		RouterID:  testRouterIDC,
		SrgbBegin: 16000,
		Prefixes:  []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.12/32"), SidIndex: 3, HasSidIndex: true}},
	}
	nodeA.Links = []*table.LsLink{{
		Local: table.LinkEndpoint{Node: nodeA}, Remote: table.LinkEndpoint{Node: nodeB},
		AdjSids: []table.AdjSID{{Sid: 24001}},
	}}
	nodeB.Links = []*table.LsLink{{
		Local: table.LinkEndpoint{Node: nodeB}, Remote: table.LinkEndpoint{Node: nodeC},
		AdjSids: []table.AdjSID{{Sid: 24002}},
	}}

	ted := newTestTED(nodeA, nodeB, nodeC)

	tests := []struct {
		name    string
		src     string
		segs    []table.Segment
		wantErr string // empty means expect nil error
	}{
		{
			name: "valid: A to B via node SID, B to C via adj SID on B",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRMPLS(16002), // node SID of B
				table.NewSegmentSRMPLS(24002), // adj SID on B -> C
			},
			wantErr: "",
		},
		{
			name: "adj SID on wrong owner: B adj SID used while owner is A",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRMPLS(24002), // belongs to B, not A
			},
			wantErr: "does not have adjacency SID",
		},
		{
			name: "SID not in TED",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRMPLS(99999),
			},
			wantErr: "not found in TED",
		},
		{
			name: "single node SID valid",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRMPLS(16001), // node SID of A
			},
			wantErr: "",
		},
		{
			name:    "empty segment list",
			src:     testRouterIDA,
			segs:    []table.Segment{},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := table.ValidateExplicitPath(ted, tt.src, tt.segs)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestValidateExplicitPathSRv6(t *testing.T) {
	t.Parallel()

	// Topology: A --End.X:fc00::a:b--> B --End.X:fc00::b:c--> C
	// A has End SID fc00::a:1, B has End SID fc00::b:1, C has End SID fc00::c:1.
	nodeA := &table.LsNode{
		RouterID: testRouterIDA,
		SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"fc00::a:1"}}},
	}
	nodeB := &table.LsNode{
		RouterID: testRouterIDB,
		SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"fc00::b:1"}}},
	}
	nodeC := &table.LsNode{
		RouterID: testRouterIDC,
		SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"fc00::c:1"}}},
	}
	nodeA.Links = []*table.LsLink{{Local: table.LinkEndpoint{Node: nodeA}, Remote: table.LinkEndpoint{Node: nodeB}, Srv6EndXSIDs: []*table.Srv6EndXSID{{Sids: []string{"fc00::a:b"}}}}}
	nodeB.Links = []*table.LsLink{{Local: table.LinkEndpoint{Node: nodeB}, Remote: table.LinkEndpoint{Node: nodeC}, Srv6EndXSIDs: []*table.Srv6EndXSID{{Sids: []string{"fc00::b:c"}}}}}

	ted := newTestTED(nodeA, nodeB, nodeC)

	tests := []struct {
		name    string
		src     string
		segs    []table.Segment
		wantErr string // empty means expect nil error
	}{
		{
			name: "valid: A to B via End SID, B to C via End.X on B",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fc00::b:1"))), // End SID of B
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fc00::b:c"))), // End.X on B -> C
			},
			wantErr: "",
		},
		{
			name: "End.X on wrong owner: B End.X used while owner is A",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fc00::b:c"))), // belongs to B, not A
			},
			wantErr: "does not have adjacency SID",
		},
		{
			name: "SRv6 SID not in TED",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fd00::dead:beef"))),
			},
			wantErr: "not found in TED",
		},
		{
			name: "single End SID valid",
			src:  testRouterIDA,
			segs: []table.Segment{
				table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fc00::a:1"))), // End SID of A
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := table.ValidateExplicitPath(ted, tt.src, tt.segs)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

// usidLocatorNode builds a node advertising an SRv6 locator and optional End.X SID.
func usidLocatorNode(routerID, sid string, remote *table.LsNode, endXSid string) *table.LsNode {
	node := &table.LsNode{
		RouterID: routerID,
		SRv6SIDs: []*table.LsSrv6SID{{
			Sids:         []string{sid},
			SIDStructure: &table.SIDStructure{LocalBlock: 32, LocalNode: 16},
		}},
	}
	if remote != nil {
		node.Links = []*table.LsLink{{Remote: table.LinkEndpoint{Node: remote}, Srv6EndXSIDs: []*table.Srv6EndXSID{{Sids: []string{endXSid}}}}}
	}

	return node
}

func usidContainerSeg(addr string, structure *table.SIDStructure) table.Segment {
	seg := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(addr)))
	seg.USid = true
	seg.Structure = structure

	return seg
}

func TestValidateExplicitPathUSID(t *testing.T) {
	t.Parallel()

	const (
		container = "fcbb:bb00:0100:0200:0300::"
		endXToW1  = "fc00::1:2" // owned by the node advertising locator ::0100::
		endXToW3  = "fc00::3:4" // owned by the node advertising locator ::0300::
	)

	t.Run("regression: single-locator container from existing fixture, one hop", func(t *testing.T) {
		t.Parallel()

		nodeW := &table.LsNode{RouterID: "W"}
		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nodeW, endXToW1)
		ted := newTestTED(nodeW, nodeX)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg(container, &table.SIDStructure{LocalBlock: 32, LocalNode: 16}),
			table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(endXToW1))),
		})
		require.NoError(t, err)
	})

	t.Run("single micro-segment container equal to locator, then owner's End.X", func(t *testing.T) {
		t.Parallel()

		nodeW := &table.LsNode{RouterID: "W"}
		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nodeW, endXToW1)
		ted := newTestTED(nodeW, nodeX)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg("fcbb:bb00:0100::", &table.SIDStructure{LocalBlock: 32, LocalNode: 16}),
			table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(endXToW1))),
		})
		require.NoError(t, err)
	})

	t.Run("all micro-segments resolve, then last micro-segment owner's End.X", func(t *testing.T) {
		t.Parallel()

		nodeW := &table.LsNode{RouterID: "W"}
		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nil, "")
		nodeY := usidLocatorNode("Y", "fcbb:bb00:0200::", nil, "")
		nodeZ := usidLocatorNode("Z", "fcbb:bb00:0300::", nodeW, endXToW3)
		ted := newTestTED(nodeW, nodeX, nodeY, nodeZ)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg(container, &table.SIDStructure{LocalBlock: 32, LocalNode: 16}),
			table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(endXToW3))),
		})
		require.NoError(t, err)
	})

	t.Run("all micro-segments resolve, then first micro-segment owner's End.X fails", func(t *testing.T) {
		t.Parallel()

		nodeW := &table.LsNode{RouterID: "W"}
		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nodeW, endXToW1)
		nodeY := usidLocatorNode("Y", "fcbb:bb00:0200::", nil, "")
		nodeZ := usidLocatorNode("Z", "fcbb:bb00:0300::", nil, "")
		ted := newTestTED(nodeW, nodeX, nodeY, nodeZ)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg(container, &table.SIDStructure{LocalBlock: 32, LocalNode: 16}),
			table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(endXToW1))),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not have adjacency SID")
	})

	t.Run("unresolved micro-segment degrades to owner unknown, known End.X still validates", func(t *testing.T) {
		t.Parallel()

		nodeW := &table.LsNode{RouterID: "W"}
		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nil, "")
		nodeZ := usidLocatorNode("Z", "fcbb:bb00:0300::", nodeW, endXToW3)
		// Y's locator is intentionally absent from the TED.
		ted := newTestTED(nodeW, nodeX, nodeZ)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg(container, &table.SIDStructure{LocalBlock: 32, LocalNode: 16}),
			table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(endXToW3))),
		})
		require.NoError(t, err)
	})

	t.Run("unresolved micro-segment degrades to owner unknown, unknown SID after still fails", func(t *testing.T) {
		t.Parallel()

		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nil, "")
		nodeZ := usidLocatorNode("Z", "fcbb:bb00:0300::", nil, "")
		ted := newTestTED(nodeX, nodeZ)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg(container, &table.SIDStructure{LocalBlock: 32, LocalNode: 16}),
			table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr("fd00::dead:beef"))),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in TED")
	})

	t.Run("container outside any known locator", func(t *testing.T) {
		t.Parallel()

		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nil, "")
		ted := newTestTED(nodeX)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg("fd00:bb00:0100:0200:0300::", &table.SIDStructure{LocalBlock: 32, LocalNode: 16}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in TED")
	})

	t.Run("declared locator shorter than TED's", func(t *testing.T) {
		t.Parallel()

		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nil, "")
		ted := newTestTED(nodeX)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg(container, &table.SIDStructure{LocalBlock: 24, LocalNode: 8, LocalFunc: 16}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in TED")
	})

	t.Run("uSID false is not treated as a container", func(t *testing.T) {
		t.Parallel()

		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nil, "")
		ted := newTestTED(nodeX)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(container))),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in TED")
	})

	t.Run("exact End.X SID from wrong owner still errors with uSID enabled", func(t *testing.T) {
		t.Parallel()

		nodeA := &table.LsNode{
			RouterID: testRouterIDA,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"fc00::a:1"}}},
		}
		nodeB := &table.LsNode{
			RouterID: testRouterIDB,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"fc00::b:1"}}},
		}
		nodeA.Links = []*table.LsLink{{Local: table.LinkEndpoint{Node: nodeA}, Remote: table.LinkEndpoint{Node: nodeB}, Srv6EndXSIDs: []*table.Srv6EndXSID{{Sids: []string{"fc00::a:b"}}}}}
		ted := newTestTED(nodeA, nodeB)

		err := table.ValidateExplicitPath(ted, testRouterIDB, []table.Segment{
			usidContainerSeg("fc00::a:b", nil),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not have adjacency SID")
	})

	t.Run("nodeBits zero does not hang and falls back to not found", func(t *testing.T) {
		t.Parallel()

		nodeX := usidLocatorNode("X", "fcbb:bb00:0100::", nil, "")
		ted := newTestTED(nodeX)

		err := table.ValidateExplicitPath(ted, "X", []table.Segment{
			usidContainerSeg("fd00:bb00:0100::", &table.SIDStructure{LocalBlock: 32, LocalFunc: 16}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in TED")
	})

	t.Run("LocalNode unset registers a real locator, not a wildcard match", func(t *testing.T) {
		t.Parallel()

		// LocalBlock=32, LocalNode=0 is a valid structure with no node bits.
		nodeA := &table.LsNode{
			RouterID: testRouterIDA,
			SRv6SIDs: []*table.LsSrv6SID{{
				Sids:         []string{"fc00::a:1"},
				SIDStructure: &table.SIDStructure{LocalBlock: 32},
			}},
		}
		nodeB := &table.LsNode{
			RouterID: testRouterIDB,
			SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{"fc00::b:1"}}},
		}
		nodeA.Links = []*table.LsLink{{Local: table.LinkEndpoint{Node: nodeA}, Remote: table.LinkEndpoint{Node: nodeB}, Srv6EndXSIDs: []*table.Srv6EndXSID{{Sids: []string{"fc00::a:b"}}}}}
		ted := newTestTED(nodeA, nodeB)

		// A /32 locator has no node bits and resolves directly to its owner.
		err := table.ValidateExplicitPath(ted, testRouterIDB, []table.Segment{
			usidContainerSeg("fc00::a:b", nil),
		})
		require.NoError(t, err)
	})
}

func TestSIDIndexNextHop_UnknownSegmentFamily(t *testing.T) {
	t.Parallel()

	idx := table.NewSIDIndex(newTestTED())
	_, err := idx.NextHop(testRouterID1, fakeUnknownSegment{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown segment family")
}

func TestValidateExplicitPath_InputErrors(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{RouterID: testRouterID1}
	ted := newTestTED(node)

	t.Run("nil TED", func(t *testing.T) {
		t.Parallel()

		err := table.ValidateExplicitPath(nil, node.RouterID, []table.Segment{table.NewSegmentSRMPLS(16003)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TED is nil")
	})

	t.Run("empty source router ID", func(t *testing.T) {
		t.Parallel()

		err := table.ValidateExplicitPath(ted, "", []table.Segment{table.NewSegmentSRMPLS(16003)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source router ID is empty")
	})

	t.Run("source router ID not found", func(t *testing.T) {
		t.Parallel()

		err := table.ValidateExplicitPath(ted, "missing", []table.Segment{table.NewSegmentSRMPLS(16003)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source router ID missing not found in TED")
	})

	t.Run("nil segment in list", func(t *testing.T) {
		t.Parallel()

		err := table.ValidateExplicitPath(ted, node.RouterID, []table.Segment{nil})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hop 1: nil segment")
	})
}
