// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newTestTED(nodes ...*LsNode) *LsTED {
	m := make(map[string]*LsNode, len(nodes))
	for _, n := range nodes {
		m[n.RouterID] = n
	}
	return &LsTED{Nodes: m}
}

func TestSIDIndexHas_SRMPLS(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID:  testRouterID1,
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
			t.Parallel()
			idx := NewSIDIndex(ted)
			assert.Equal(t, tt.want, idx.Has(tt.seg))
		})
	}
}

func TestSIDIndexHas_SRMPLS_SrgbBeginZero(t *testing.T) {
	t.Parallel()

	// Without an SRGB, a Prefix-SID index cannot be converted to a label.
	node := &LsNode{
		RouterID: testRouterID1,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 16003, HasSidIndex: true},
		},
	}
	idx := NewSIDIndex(newTestTED(node))
	assert.False(t, idx.Has(NewSegmentSRMPLS(16003)), "expected SidIndex not to be registered when SrgbBegin is unavailable")
}

func TestSIDIndexHas_SRMPLS_PrefixSIDIndexZero(t *testing.T) {
	t.Parallel()

	// Prefix-SID index 0 is a valid index: SRGB begin + 0 must be registered
	// when the Prefix-SID TLV was actually advertised.
	node := &LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
		},
	}
	idx := NewSIDIndex(newTestTED(node))
	assert.True(t, idx.Has(NewSegmentSRMPLS(16000)), "expected Prefix-SID index 0 to be registered as label 16000")
}

func TestSIDIndexHas_SRMPLS_NoPrefixSID(t *testing.T) {
	t.Parallel()

	// A prefix without a Prefix-SID TLV must not register the SRGB begin label.
	node := &LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
		},
	}
	idx := NewSIDIndex(newTestTED(node))
	assert.False(t, idx.Has(NewSegmentSRMPLS(16000)), "expected no MPLS SID for a prefix without a Prefix-SID")
}

func TestSIDIndexHas_SRMPLS_PrefixSIDRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		node  *LsNode
		label uint32
		want  bool
	}{
		{
			name: "index inside the SRGB",
			node: &LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 3, HasSidIndex: true}},
			},
			label: 16003,
			want:  true,
		},
		{
			name: "last index of the SRGB (SrgbEnd is exclusive)",
			node: &LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 7999, HasSidIndex: true}},
			},
			label: 23999,
			want:  true,
		},
		{
			name: "index at SrgbEnd is outside the SRGB",
			node: &LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 8000, HasSidIndex: true}},
			},
			label: 24000,
			want:  false,
		},
		{
			name: "index beyond the SRGB",
			node: &LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000, SrgbEnd: 24000,
				Prefixes: []*LsPrefix{{SidIndex: 100000, HasSidIndex: true}},
			},
			label: 116000,
			want:  false,
		},
		{
			name: "label beyond the 20-bit MPLS range without an SRGB end",
			node: &LsNode{
				RouterID: testRouterID1, SrgbBegin: 1000000,
				Prefixes: []*LsPrefix{{SidIndex: 100000, HasSidIndex: true}},
			},
			label: 1100000,
			want:  false,
		},
		{
			name: "index that would overflow uint32",
			node: &LsNode{
				RouterID: testRouterID1, SrgbBegin: 16000,
				Prefixes: []*LsPrefix{{SidIndex: 0xFFFFFFFF, HasSidIndex: true}},
			},
			label: 15999, // 16000 + 0xFFFFFFFF wrapped around
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idx := NewSIDIndex(newTestTED(tt.node))
			assert.Equal(t, tt.want, idx.Has(NewSegmentSRMPLS(tt.label)))
		})
	}
}

func TestLsPrefixHasPrefixSID(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			assert.Equal(t, tt.want, tt.prefix.HasPrefixSID())
		})
	}
}

func TestSIDIndexHas_SRv6Exact(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID: testRouterID1,
		SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{testSRv6ExactSID}, SIDStructure: SIDStructure{}},
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
		{"End SID exact match", NewSegmentSRv6(netip.MustParseAddr(testSRv6ExactSID)), true},
		{"End.X SID exact match", NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::1")), true},
		{"unknown SID", NewSegmentSRv6(netip.MustParseAddr("2001:db8:1::99")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idx := NewSIDIndex(ted)
			assert.Equal(t, tt.want, idx.Has(tt.seg))
		})
	}
}

func TestSIDIndexHas_USID(t *testing.T) {
	t.Parallel()

	// TED advertises a locator of block=32, node=16 bits -> fcbb:bb00:0100::/48.
	node := &LsNode{
		RouterID: testRouterID1,
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
		t.Parallel()
		seg := NewSegmentSRv6(container)
		seg.USid = true
		seg.Structure = []uint8{32, 16, 16, 0}
		assert.True(t, NewSIDIndex(ted).Has(seg), "expected uSID container to be accepted via locator containment")
	})

	t.Run("no structure, falls back to containment", func(t *testing.T) {
		t.Parallel()
		seg := NewSegmentSRv6(container)
		seg.USid = true
		assert.True(t, NewSIDIndex(ted).Has(seg), "expected uSID container without structure to be accepted via containment fallback")
	})

	t.Run("declared locator shorter than TED advertised", func(t *testing.T) {
		t.Parallel()
		seg := NewSegmentSRv6(container)
		seg.USid = true
		// Declares a /32 locator (block=24,node=8), which contradicts the /48
		// the TED actually advertises.
		seg.Structure = []uint8{24, 8, 16, 0}
		assert.False(t, NewSIDIndex(ted).Has(seg), "expected mismatch when declared locator is shorter than TED advertised")
	})

	t.Run("outside any known locator", func(t *testing.T) {
		t.Parallel()
		seg := NewSegmentSRv6(netip.MustParseAddr("fcbb:bb00:ffff::"))
		seg.USid = true
		assert.False(t, NewSIDIndex(ted).Has(seg), "expected mismatch for a SID outside any known locator")
	})

	t.Run("non-uSID segment does not fall back to locator containment", func(t *testing.T) {
		t.Parallel()
		seg := NewSegmentSRv6(container)
		assert.False(t, NewSIDIndex(ted).Has(seg), "expected non-uSID segment to require an exact SID match")
	})
}

func TestMissingSegmentString(t *testing.T) {
	t.Parallel()

	m := MissingSegment{Hop: 2, SID: "16099"}
	assert.Equal(t, "hop 2 (16099)", m.String())
}

func TestNewSIDIndex_SkipsNilNode(t *testing.T) {
	t.Parallel()

	ted := &LsTED{Nodes: map[string]*LsNode{testRouterID1: nil}}
	idx := NewSIDIndex(ted)
	assert.False(t, idx.Has(NewSegmentSRMPLS(16003)), "expected no panic and no match when a map entry is nil")
}

func TestSIDIndexAddLinkSIDs_SkipsNilLink(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID: testRouterID1,
		Links:    []*LsLink{nil, {AdjSid: 24001}},
	}
	idx := NewSIDIndex(newTestTED(node))
	assert.True(t, idx.Has(NewSegmentSRMPLS(24001)), "expected the adj SID after the nil link to still be registered")
}

func TestSIDIndexHas_UnknownSegmentType(t *testing.T) {
	t.Parallel()

	idx := NewSIDIndex(newTestTED())
	assert.False(t, idx.Has(fakeUnknownSegment{}))
}

func TestSIDIndexAddSRv6_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("non-IPv6 SID is not registered", func(t *testing.T) {
		t.Parallel()
		node := &LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*LsSrv6SID{{Sids: []string{"10.0.0.1"}}},
		}
		idx := NewSIDIndex(newTestTED(node))
		assert.False(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr("10.0.0.1"))), "expected an IPv4 address advertised as an SRv6 SID to be ignored")
	})

	t.Run("unparsable SID is not registered", func(t *testing.T) {
		t.Parallel()
		node := &LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*LsSrv6SID{{Sids: []string{testInvalidAddr}}},
		}
		idx := NewSIDIndex(newTestTED(node))
		assert.False(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr(testSRv6SID1))))
	})

	t.Run("zero locator length still registers the exact SID but skips the locator", func(t *testing.T) {
		t.Parallel()
		sid := netip.MustParseAddr("fc00:0:1::")
		node := &LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*LsSrv6SID{{Sids: []string{sid.String()}, SIDStructure: SIDStructure{}}},
		}
		idx := NewSIDIndex(newTestTED(node))
		assert.True(t, idx.Has(NewSegmentSRv6(sid)), "expected exact match regardless of locator length")

		other := NewSegmentSRv6(netip.MustParseAddr("fc00:0:1::1234"))
		other.USid = true
		assert.False(t, idx.Has(other), "expected no locator fallback registered when LocalBlock+LocalNode is 0")
	})

	t.Run("locator length beyond 128 bits is not registered", func(t *testing.T) {
		t.Parallel()
		sid := netip.MustParseAddr("fc00:0:1::")
		node := &LsNode{
			RouterID: testRouterID1,
			SRv6SIDs: []*LsSrv6SID{{Sids: []string{sid.String()}, SIDStructure: SIDStructure{LocalBlock: 200, LocalNode: 200}}},
		}
		idx := NewSIDIndex(newTestTED(node))
		assert.True(t, idx.Has(NewSegmentSRv6(sid)), "expected exact match regardless of locator length")

		other := NewSegmentSRv6(netip.MustParseAddr("fc00:0:1::1234"))
		other.USid = true
		assert.False(t, idx.Has(other), "expected no locator fallback registered when LocalBlock+LocalNode exceeds 128 bits")
	})
}

func TestSIDIndexHas_EmptyTED(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ted  *LsTED
	}{
		{"nil TED", nil},
		{"TED with no nodes", newTestTED()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			idx := NewSIDIndex(tt.ted)
			assert.False(t, idx.Has(NewSegmentSRMPLS(16003)), "expected no match against an empty TED")
			assert.False(t, idx.Has(NewSegmentSRv6(netip.MustParseAddr(testSRv6ExactSID))), "expected no match against an empty TED")
		})
	}
}

func TestMissingSegments(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID:  testRouterID1,
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
	t.Parallel()

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
			segs: []Segment{NewSegmentSRv6(netip.MustParseAddr(testSRv6SID1))},
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
			t.Parallel()
			assert.Equal(t, tt.want, HasUnknownSegmentType(tt.segs))
		})
	}
}

func TestOutOfRangeSRMPLSLabels(t *testing.T) {
	t.Parallel()

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
			segs: []Segment{nil, NewSegmentSRv6(netip.MustParseAddr(testSRv6SID1))},
		},
		{
			name: "empty list",
			segs: []Segment{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, OutOfRangeSRMPLSLabels(tt.segs))
		})
	}
}

func TestHasMixedSegmentTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		segs []Segment
		want bool
	}{
		{
			name: "all SRv6",
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr(testSRv6SID1)),
				NewSegmentSRv6(netip.MustParseAddr(testSRv6SID2)),
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
				NewSegmentSRv6(netip.MustParseAddr(testSRv6SID1)),
				NewSegmentSRMPLS(16001),
			},
			want: true,
		},
		{
			name: "mixed SR-MPLS then SRv6",
			segs: []Segment{
				NewSegmentSRMPLS(16001),
				NewSegmentSRv6(netip.MustParseAddr(testSRv6SID1)),
			},
			want: true,
		},
		{
			name: "SRv6 with unknown family",
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr(testSRv6SID1)),
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
			name: "nil segment does not count toward either family",
			segs: []Segment{nil, NewSegmentSRMPLS(16001)},
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
			t.Parallel()
			assert.Equal(t, tt.want, HasMixedSegmentTypes(tt.segs))
		})
	}
}

func TestValidateExplicitPath(t *testing.T) {
	t.Parallel()

	// Topology: A --adj24001--> B --adj24002--> C
	// A has node SID 16001, B has node SID 16002, C has node SID 16003.
	nodeA := &LsNode{
		RouterID:  testRouterIDA,
		SrgbBegin: 16000,
		Prefixes:  []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.10/32"), SidIndex: 1, HasSidIndex: true}},
	}
	nodeB := &LsNode{
		RouterID:  testRouterIDB,
		SrgbBegin: 16000,
		Prefixes:  []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.11/32"), SidIndex: 2, HasSidIndex: true}},
	}
	nodeC := &LsNode{
		RouterID:  testRouterIDC,
		SrgbBegin: 16000,
		Prefixes:  []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.12/32"), SidIndex: 3, HasSidIndex: true}},
	}
	nodeA.Links = []*LsLink{{LocalNode: nodeA, RemoteNode: nodeB, AdjSid: 24001}}
	nodeB.Links = []*LsLink{{LocalNode: nodeB, RemoteNode: nodeC, AdjSid: 24002}}

	ted := newTestTED(nodeA, nodeB, nodeC)

	tests := []struct {
		name    string
		src     string
		segs    []Segment
		wantErr string // empty means expect nil error
	}{
		{
			name: "valid: A to B via node SID, B to C via adj SID on B",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRMPLS(16002), // node SID of B
				NewSegmentSRMPLS(24002), // adj SID on B -> C
			},
			wantErr: "",
		},
		{
			name: "adj SID on wrong owner: B adj SID used while owner is A",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRMPLS(24002), // belongs to B, not A
			},
			wantErr: "does not have adjacency SID",
		},
		{
			name: "SID not in TED",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRMPLS(99999),
			},
			wantErr: "not found in TED",
		},
		{
			name: "single node SID valid",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRMPLS(16001), // node SID of A
			},
			wantErr: "",
		},
		{
			name:    "empty segment list",
			src:     testRouterIDA,
			segs:    []Segment{},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateExplicitPath(ted, tt.src, tt.segs)
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
	nodeA := &LsNode{
		RouterID: testRouterIDA,
		SRv6SIDs: []*LsSrv6SID{{Sids: []string{"fc00::a:1"}}},
	}
	nodeB := &LsNode{
		RouterID: testRouterIDB,
		SRv6SIDs: []*LsSrv6SID{{Sids: []string{"fc00::b:1"}}},
	}
	nodeC := &LsNode{
		RouterID: testRouterIDC,
		SRv6SIDs: []*LsSrv6SID{{Sids: []string{"fc00::c:1"}}},
	}
	nodeA.Links = []*LsLink{{LocalNode: nodeA, RemoteNode: nodeB, Srv6EndXSID: &Srv6EndXSID{Sids: []string{"fc00::a:b"}}}}
	nodeB.Links = []*LsLink{{LocalNode: nodeB, RemoteNode: nodeC, Srv6EndXSID: &Srv6EndXSID{Sids: []string{"fc00::b:c"}}}}

	ted := newTestTED(nodeA, nodeB, nodeC)

	tests := []struct {
		name    string
		src     string
		segs    []Segment
		wantErr string // empty means expect nil error
	}{
		{
			name: "valid: A to B via End SID, B to C via End.X on B",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr("fc00::b:1")), // End SID of B
				NewSegmentSRv6(netip.MustParseAddr("fc00::b:c")), // End.X on B -> C
			},
			wantErr: "",
		},
		{
			name: "End.X on wrong owner: B End.X used while owner is A",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr("fc00::b:c")), // belongs to B, not A
			},
			wantErr: "does not have adjacency SID",
		},
		{
			name: "SRv6 SID not in TED",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr("fd00::dead:beef")),
			},
			wantErr: "not found in TED",
		},
		{
			name: "single End SID valid",
			src:  testRouterIDA,
			segs: []Segment{
				NewSegmentSRv6(netip.MustParseAddr("fc00::a:1")), // End SID of A
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateExplicitPath(ted, tt.src, tt.segs)
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

func TestSIDIndexNextHop_OwnerUnknownBranches(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID: testRouterID1,
		Links: []*LsLink{
			{AdjSid: 24001, Srv6EndXSID: &Srv6EndXSID{Sids: []string{"2001:db8::a"}}},
		},
		SRv6SIDs: []*LsSrv6SID{
			{Sids: []string{testSRv6SID1}},
		},
	}
	idx := NewSIDIndex(newTestTED(node))

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

func TestSIDIndexNextHop_UnknownSegmentFamily(t *testing.T) {
	t.Parallel()

	idx := NewSIDIndex(newTestTED())
	_, err := idx.NextHop(testRouterID1, fakeUnknownSegment{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown segment family")
}

func TestValidateExplicitPath_InputErrors(t *testing.T) {
	t.Parallel()

	node := &LsNode{RouterID: testRouterID1}
	ted := newTestTED(node)

	t.Run("nil TED", func(t *testing.T) {
		t.Parallel()
		err := ValidateExplicitPath(nil, node.RouterID, []Segment{NewSegmentSRMPLS(16003)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TED is nil")
	})

	t.Run("empty source router ID", func(t *testing.T) {
		t.Parallel()
		err := ValidateExplicitPath(ted, "", []Segment{NewSegmentSRMPLS(16003)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source router ID is empty")
	})

	t.Run("source router ID not found", func(t *testing.T) {
		t.Parallel()
		err := ValidateExplicitPath(ted, "missing", []Segment{NewSegmentSRMPLS(16003)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source router ID missing not found in TED")
	})

	t.Run("nil segment in list", func(t *testing.T) {
		t.Parallel()
		err := ValidateExplicitPath(ted, node.RouterID, []Segment{nil})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hop 1: nil segment")
	})
}
