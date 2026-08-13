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

func newTestTED(nodes ...*LsNode) *LsTED {
	m := make(map[string]*LsNode, len(nodes))
	for _, n := range nodes {
		m[n.RouterID] = n
	}
	return &LsTED{Nodes: m}
}

func TestSIDIndexHas_SRMPLS(t *testing.T) {
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
		Links: []*LsLink{
			{AdjSid: 24001},
		},
	}
	ted := newTestTED(node)

	tests := []struct {
		name string
		seg  Segment
		want bool
	}{
		{"prefix SID match", NewSegmentSRMPLS(16003), true},
		{"adj SID match", NewSegmentSRMPLS(24001), true},
		{"unknown label", NewSegmentSRMPLS(16099), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := NewSIDIndex(ted)
			assert.Equal(t, tt.want, idx.Has(tt.seg))
		})
	}
}

func TestSIDIndexHas_SRMPLS_SrgbBeginZero(t *testing.T) {
	// Without an SRGB, a Prefix-SID index cannot be converted to a label.
	node := &LsNode{
		RouterID: "0000.0000.0001",
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 16003, HasSidIndex: true},
		},
	}
	idx := NewSIDIndex(newTestTED(node))
	assert.False(t, idx.Has(NewSegmentSRMPLS(16003)), "expected SidIndex not to be registered when SrgbBegin is unavailable")
}

func TestSIDIndexHas_SRMPLS_PrefixSIDIndexZero(t *testing.T) {
	// Prefix-SID index 0 is a valid index: SRGB begin + 0 must be registered
	// when the Prefix-SID TLV was actually advertised.
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
		},
	}
	idx := NewSIDIndex(newTestTED(node))
	assert.True(t, idx.Has(NewSegmentSRMPLS(16000)), "expected Prefix-SID index 0 to be registered as label 16000")
}

func TestSIDIndexHas_SRMPLS_NoPrefixSID(t *testing.T) {
	// A prefix without a Prefix-SID TLV must not register the SRGB begin label.
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
		},
	}
	idx := NewSIDIndex(newTestTED(node))
	assert.False(t, idx.Has(NewSegmentSRMPLS(16000)), "expected no MPLS SID for a prefix without a Prefix-SID")
}

func TestSIDIndexHas_SRMPLS_PrefixSIDRanges(t *testing.T) {
	tests := []struct {
		name  string
		node  *LsNode
		label uint32
		want  bool
	}{
		{
			name: "index inside the SRGB",
			node: &LsNode{
				RouterID: "0000.0000.0001", SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 3, HasSidIndex: true}},
			},
			label: 16003,
			want:  true,
		},
		{
			name: "last index of the SRGB (SrgbEnd is exclusive)",
			node: &LsNode{
				RouterID: "0000.0000.0001", SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 7999, HasSidIndex: true}},
			},
			label: 23999,
			want:  true,
		},
		{
			name: "index at SrgbEnd is outside the SRGB",
			node: &LsNode{
				RouterID: "0000.0000.0001", SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 8000, HasSidIndex: true}},
			},
			label: 24000,
			want:  false,
		},
		{
			name: "index beyond the SRGB",
			node: &LsNode{
				RouterID: "0000.0000.0001", SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 100000, HasSidIndex: true}},
			},
			label: 116000,
			want:  false,
		},
		{
			name: "label beyond the 20-bit MPLS range without an SRGB end",
			node: &LsNode{
				RouterID: "0000.0000.0001", SrgbBegin: 1000000,
				Prefixes: []*LsPrefix{{SidIndex: 100000, HasSidIndex: true}},
			},
			label: 1100000,
			want:  false,
		},
		{
			name: "index that would overflow uint32",
			node: &LsNode{
				RouterID: "0000.0000.0001", SrgbBegin: 16000,
				Prefixes: []*LsPrefix{{SidIndex: 0xFFFFFFFF, HasSidIndex: true}},
			},
			label: 15999, // 16000 + 0xFFFFFFFF wrapped around
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := NewSIDIndex(newTestTED(tt.node))
			assert.Equal(t, tt.want, idx.Has(NewSegmentSRMPLS(tt.label)))
		})
	}
}

func TestLsPrefixHasPrefixSID(t *testing.T) {
	tests := []struct {
		name   string
		prefix *LsPrefix
		want   bool
	}{
		{"nil prefix", nil, false},
		{"no Prefix-SID", &LsPrefix{}, false},
		{"advertised index 0", &LsPrefix{HasSidIndex: true}, true},
		{"advertised non-zero index", &LsPrefix{SidIndex: 3, HasSidIndex: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.prefix.HasPrefixSID())
		})
	}
}

func TestSIDIndexHas_SRv6Exact(t *testing.T) {
	node := &LsNode{
		RouterID: "0000.0000.0001",
		SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{"2001:db8:1::"}, SIDStructure: SIDStructure{}},
		},
		Links: []*LsLink{
			{
				Srv6EndXSID: &Srv6EndXSID{
					Sids:             []string{"2001:db8:1::1"},
					Srv6SIDStructure: SIDStructure{},
				},
			},
		},
	}
	ted := newTestTED(node)

	tests := []struct {
		name string
		seg  Segment
		want bool
	}{
		{"End SID exact match", NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::")), true},
		{"End.X SID exact match", NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::1")), true},
		{"unknown SID", NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::99")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := NewSIDIndex(ted)
			assert.Equal(t, tt.want, idx.Has(tt.seg))
		})
	}
}

func TestSIDIndexHas_USID(t *testing.T) {
	// TED advertises a locator of block=32, node=16 bits -> fcbb:bb00:0100::/48.
	node := &LsNode{
		RouterID: "0000.0000.0001",
		SRv6SIDs: []*LsSrv6SID{
			{
				Sids:         []string{"fcbb:bb00:0100::"},
				SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16},
			},
		},
	}
	ted := newTestTED(node)

	container := netip.MustParseAddr("fcbb:bb00:0100:0200:0300::")

	t.Run("structure present, container within locator", func(t *testing.T) {
		seg := NewSegmentSRv6(container)
		seg.USid = true
		seg.Structure = []uint8{32, 16, 16, 0}
		assert.True(t, NewSIDIndex(ted).Has(seg), "expected uSID container to be accepted via locator containment")
	})

	t.Run("no structure, falls back to containment", func(t *testing.T) {
		seg := NewSegmentSRv6(container)
		seg.USid = true
		assert.True(t, NewSIDIndex(ted).Has(seg), "expected uSID container without structure to be accepted via containment fallback")
	})

	t.Run("declared locator shorter than TED advertised", func(t *testing.T) {
		seg := NewSegmentSRv6(container)
		seg.USid = true
		// Declares a /32 locator (block=24,node=8), which contradicts the /48
		// the TED actually advertises.
		seg.Structure = []uint8{24, 8, 16, 0}
		assert.False(t, NewSIDIndex(ted).Has(seg), "expected mismatch when declared locator is shorter than TED advertised")
	})

	t.Run("outside any known locator", func(t *testing.T) {
		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:ffff::"))
		seg.USid = true
		assert.False(t, NewSIDIndex(ted).Has(seg), "expected mismatch for a SID outside any known locator")
	})

	t.Run("non-uSID segment does not fall back to locator containment", func(t *testing.T) {
		seg := NewSegmentSRv6(container)
		assert.False(t, NewSIDIndex(ted).Has(seg), "expected non-uSID segment to require an exact SID match")
	})
}

func TestSIDIndexHas_EmptyTED(t *testing.T) {
	tests := []struct {
		name string
		ted  *LsTED
	}{
		{"nil TED", nil},
		{"TED with no nodes", newTestTED()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := NewSIDIndex(tt.ted)
			assert.False(t, idx.Has(NewSegmentSRMPLS(16003)), "expected no match against an empty TED")
			assert.False(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::"))), "expected no match against an empty TED")
		})
	}
}

func TestMissingSegments(t *testing.T) {
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := newTestTED(node)

	segmentList := []Segment{
		NewSegmentSRMPLS(16003),
		NewSegmentSRMPLS(16099),
		NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::99")),
	}

	want := []MissingSegment{
		{Hop: 2, SID: "16099"},
		{Hop: 3, SID: "2001:db8:1::99"},
	}
	assert.Equal(t, want, MissingSegments(ted, segmentList))
}

type fakeUnknownSegment struct{}

func (fakeUnknownSegment) SidString() string        { return "unknown" }
func (fakeUnknownSegment) GetFamily() SegmentFamily { return SegmentUnknown }

func TestHasUnknownSegmentType(t *testing.T) {
	tests := []struct {
		name string
		segs []Segment
		want bool
	}{
		{
			name: "all known, SR-MPLS",
			segs: []Segment{NewSegmentSRMPLS(16001), NewSegmentSRMPLS(16002)},
			want: false,
		},
		{
			name: "all known, SRv6",
			segs: []Segment{NewSegmentSRv6(netip.MustParseAddr("2001:db8::1"))},
			want: false,
		},
		{
			name: "contains nil only",
			segs: []Segment{nil, nil},
			want: false,
		},
		{
			name: "empty list",
			segs: []Segment{},
			want: false,
		},
		{
			name: "contains unknown family",
			segs: []Segment{NewSegmentSRMPLS(16001), fakeUnknownSegment{}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasUnknownSegmentType(tt.segs))
		})
	}
}

func TestOutOfRangeSRMPLSLabels(t *testing.T) {
	tests := []struct {
		name string
		segs []Segment
		want []MissingSegment
	}{
		{
			name: "lower bound is valid",
			segs: []Segment{NewSegmentSRMPLS(0)},
		},
		{
			name: "upper bound is valid",
			segs: []Segment{NewSegmentSRMPLS(1048575)},
		},
		{
			name: "one past the upper bound is rejected",
			segs: []Segment{NewSegmentSRMPLS(1048576)},
			want: []MissingSegment{{Hop: 1, SID: "1048576"}},
		},
		{
			name: "reports the offending hop only",
			segs: []Segment{
				NewSegmentSRMPLS(16001),
				NewSegmentSRMPLS(1048576),
			},
			want: []MissingSegment{{Hop: 2, SID: "1048576"}},
		},
		{
			name: "SRv6 and nil segments are ignored",
			segs: []Segment{nil, NewSegmentSRv6(netip.MustParseAddr("2001:db8::1"))},
		},
		{
			name: "empty list",
			segs: []Segment{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, OutOfRangeSRMPLSLabels(tt.segs))
		})
	}
}

func TestHasMixedSegmentTypes(t *testing.T) {
	tests := []struct {
		name string
		segs []Segment
		want bool
	}{
		{
			name: "all SRv6",
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr("2001:db8::1")),
				NewSegmentSRv6(netip.MustParseAddr("2001:db8::2")),
			},
			want: false,
		},
		{
			name: "all SR-MPLS",
			segs: []Segment{NewSegmentSRMPLS(16001), NewSegmentSRMPLS(16002)},
			want: false,
		},
		{
			name: "mixed SRv6 then SR-MPLS",
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr("2001:db8::1")),
				NewSegmentSRMPLS(16001),
			},
			want: true,
		},
		{
			name: "mixed SR-MPLS then SRv6",
			segs: []Segment{
				NewSegmentSRMPLS(16001),
				NewSegmentSRv6(netip.MustParseAddr("2001:db8::1")),
			},
			want: true,
		},
		{
			name: "SRv6 with unknown family",
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr("2001:db8::1")),
				fakeUnknownSegment{},
			},
			want: false,
		},
		{
			name: "SR-MPLS with unknown family",
			segs: []Segment{NewSegmentSRMPLS(16001), fakeUnknownSegment{}},
			want: false,
		},
		{
			name: "empty list",
			segs: []Segment{},
			want: false,
		},
		{
			name: "single SR-MPLS",
			segs: []Segment{NewSegmentSRMPLS(16001)},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasMixedSegmentTypes(tt.segs))
		})
	}
}
