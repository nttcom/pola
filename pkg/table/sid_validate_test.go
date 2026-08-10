// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"net/netip"
	"testing"
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
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3},
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
			if got := idx.Has(tt.seg); got != tt.want {
				t.Errorf("Has(%v) = %v, want %v", tt.seg, got, tt.want)
			}
		})
	}
}

func TestSIDIndexHas_SRMPLS_SrgbBeginZero(t *testing.T) {
	// A node that hasn't advertised its SRGB yet registers the raw SidIndex
	// value as-is; this is a known limitation, not a correctness guarantee.
	node := &LsNode{
		RouterID: "0000.0000.0001",
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 16003},
		},
	}
	idx := NewSIDIndex(newTestTED(node))
	if !idx.Has(NewSegmentSRMPLS(16003)) {
		t.Errorf("expected SidIndex to be registered verbatim when SrgbBegin is 0")
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
			if got := idx.Has(tt.seg); got != tt.want {
				t.Errorf("Has(%v) = %v, want %v", tt.seg, got, tt.want)
			}
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
		seg.Structure = []uint8{32, 16, 16, 0}
		if !NewSIDIndex(ted).Has(seg) {
			t.Errorf("expected uSID container to be accepted via locator containment")
		}
	})

	t.Run("no structure, falls back to containment", func(t *testing.T) {
		seg := NewSegmentSRv6(container)
		if !NewSIDIndex(ted).Has(seg) {
			t.Errorf("expected uSID container without structure to be accepted via containment fallback")
		}
	})

	t.Run("declared locator shorter than TED advertised", func(t *testing.T) {
		seg := NewSegmentSRv6(container)
		// Declares a /32 locator (block=24,node=8), which contradicts the /48
		// the TED actually advertises.
		seg.Structure = []uint8{24, 8, 16, 0}
		if NewSIDIndex(ted).Has(seg) {
			t.Errorf("expected mismatch when declared locator is shorter than TED advertised")
		}
	})

	t.Run("outside any known locator", func(t *testing.T) {
		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:ffff::"))
		if NewSIDIndex(ted).Has(seg) {
			t.Errorf("expected mismatch for a SID outside any known locator")
		}
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
			if idx.Has(NewSegmentSRMPLS(16003)) {
				t.Errorf("expected no match against an empty TED")
			}
			if idx.Has(NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::"))) {
				t.Errorf("expected no match against an empty TED")
			}
		})
	}
}

func TestMissingSegments(t *testing.T) {
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3},
		},
	}
	ted := newTestTED(node)

	segmentList := []Segment{
		NewSegmentSRMPLS(16003),
		NewSegmentSRMPLS(16099),
		NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::99")),
	}

	missing := MissingSegments(ted, segmentList)
	if len(missing) != 2 {
		t.Fatalf("expected 2 missing segments, got %d: %v", len(missing), missing)
	}
	if missing[0].Hop != 2 || missing[0].SID != "16099" {
		t.Errorf("unexpected first missing segment: %+v", missing[0])
	}
	if missing[1].Hop != 3 || missing[1].SID != "2001:db8:1::99" {
		t.Errorf("unexpected second missing segment: %+v", missing[1])
	}
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
			if got := HasUnknownSegmentType(tt.segs); got != tt.want {
				t.Errorf("HasUnknownSegmentType() = %v, want %v", got, tt.want)
			}
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
			if got := HasMixedSegmentTypes(tt.segs); got != tt.want {
				t.Errorf("HasMixedSegmentTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}
