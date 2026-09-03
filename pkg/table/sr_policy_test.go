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

const testSRv6Addr = "fc00:0:1::"

func newTestSegmentSRMPLS(sid uint32, local, remote string) SegmentSRMPLS {
	seg := NewSegmentSRMPLS(sid)
	if local != "" {
		seg.LocalAddr = netip.MustParseAddr(local)
	}
	if remote != "" {
		seg.RemoteAddr = netip.MustParseAddr(remote)
	}
	return seg
}

func newTestSegmentSRv6(sid, local, remote string) SegmentSRv6 {
	seg := NewSegmentSRv6(netip.MustParseAddr(sid))
	if local != "" {
		seg.LocalAddr = netip.MustParseAddr(local)
	}
	if remote != "" {
		seg.RemoteAddr = netip.MustParseAddr(remote)
	}
	return seg
}

func TestSegmentsEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    Segment
		b    Segment
		want bool
	}{
		{
			name: "SR-MPLS same label",
			a:    newTestSegmentSRMPLS(16001, "", ""),
			b:    newTestSegmentSRMPLS(16001, "", ""),
			want: true,
		},
		{
			name: "SR-MPLS same label with different NAI",
			a:    newTestSegmentSRMPLS(16001, "10.0.0.1", ""),
			b:    newTestSegmentSRMPLS(16001, "10.0.0.2", "10.0.0.3"),
			want: false,
		},
		{
			name: "SR-MPLS different label",
			a:    newTestSegmentSRMPLS(16001, "10.0.0.1", ""),
			b:    newTestSegmentSRMPLS(16002, "10.0.0.1", ""),
			want: false,
		},
		{
			name: "SR-MPLS SID-absent vs label 0",
			a:    SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr("10.0.0.1")},
			b:    newTestSegmentSRMPLS(0, "10.0.0.1", ""),
			want: false,
		},
		{
			name: "SR-MPLS both SID-absent with same NAI",
			a:    SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr("10.0.0.1")},
			b:    SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr("10.0.0.1")},
			want: true,
		},
		{
			name: "SR-MPLS same label with different TTL",
			a:    func() SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TTL = 1; return s }(),
			b:    func() SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TTL = 2; return s }(),
			want: false,
		},
		{
			name: "SR-MPLS same label with different TC",
			a:    func() SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TC = 1; return s }(),
			b:    func() SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TC = 2; return s }(),
			want: false,
		},
		{
			name: "SR-MPLS same label with different S",
			a:    func() SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.S = false; return s }(),
			b:    func() SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.S = true; return s }(),
			want: false,
		},
		{
			name: "SRv6 same SID and NAI",
			a:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			b:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			want: true,
		},
		{
			name: "SRv6 same SID with different NAI",
			a:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			b:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::2", ""),
			want: false,
		},
		{
			name: "SRv6 same SID with different USid",
			a:    func() SegmentSRv6 { s := newTestSegmentSRv6("fc00:0:1::", "", ""); s.USid = false; return s }(),
			b:    func() SegmentSRv6 { s := newTestSegmentSRv6("fc00:0:1::", "", ""); s.USid = true; return s }(),
			want: false,
		},
		{
			name: "SRv6 same SID with different Structure",
			a: func() SegmentSRv6 {
				s := newTestSegmentSRv6("fc00:0:1::", "", "")
				s.Structure = SIDStructureBytes{1, 2, 3, 4}
				return s
			}(),
			b: func() SegmentSRv6 {
				s := newTestSegmentSRv6("fc00:0:1::", "", "")
				s.Structure = SIDStructureBytes{5, 6, 7, 8}
				return s
			}(),
			want: false,
		},
		{
			name: "different segment types",
			a:    newTestSegmentSRMPLS(16001, "", ""),
			b:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, SegmentsEqual(tt.a, tt.b))
		})
	}
}

type fakeUnknownSidSegment struct{}

func (fakeUnknownSidSegment) SidString() string { return "unknown" }

func TestSegmentsEqual_UnknownType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    Segment
		b    Segment
	}{
		{"SRv6 vs SR-MPLS", newTestSegmentSRv6("fc00:0:1::", "", ""), newTestSegmentSRMPLS(16001, "", "")},
		{"both unknown", fakeUnknownSidSegment{}, fakeUnknownSidSegment{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.False(t, SegmentsEqual(tt.a, tt.b))
		})
	}
}

func TestNewSRPolicy(t *testing.T) {
	t.Parallel()

	segList := []Segment{NewSegmentSRMPLS(16001)}
	srcAddr := netip.MustParseAddr("10.0.0.1")
	dstAddr := netip.MustParseAddr("10.0.0.2")

	p := NewSRPolicy(1, "policy1", segList, srcAddr, dstAddr, 100, 200, 1, PolicyUp)

	want := &SRPolicy{
		PlspID:      1,
		Name:        "policy1",
		SegmentList: segList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       100,
		Preference:  200,
		LSPID:       1,
		State:       PolicyUp,
	}
	assert.Equal(t, want, p)
}

func TestSRPolicyUpdate(t *testing.T) {
	t.Parallel()

	name := "renamed"
	color := uint32(300)
	preference := uint32(400)
	newSegList := []Segment{NewSegmentSRMPLS(16002)}

	tests := []struct {
		name string
		diff PolicyDiff
		want SRPolicy
	}{
		{
			name: "state and LSPID always applied, optional fields left unset when nil",
			diff: PolicyDiff{State: PolicyDown, LSPID: 5},
			want: SRPolicy{Name: "original", Color: 100, Preference: 200, LSPID: 5, State: PolicyDown, SegmentList: []Segment{NewSegmentSRMPLS(16001)}},
		},
		{
			name: "optional fields applied when set",
			diff: PolicyDiff{Name: &name, Color: &color, Preference: &preference, SegmentList: newSegList, State: PolicyUp, LSPID: 6},
			want: SRPolicy{Name: name, Color: color, Preference: preference, LSPID: 6, State: PolicyUp, SegmentList: newSegList},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &SRPolicy{Name: "original", Color: 100, Preference: 200, SegmentList: []Segment{NewSegmentSRMPLS(16001)}}
			p.Update(tt.diff)
			assert.Equal(t, tt.want, *p)
		})
	}
}

func TestNewSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sid     string
		want    Segment
		wantErr bool
	}{
		{"SRv6 address", testSRv6Addr, NewSegmentSRv6(netip.MustParseAddr(testSRv6Addr)), false},
		{"SR-MPLS label", "16001", NewSegmentSRMPLS(16001), false},
		{"IPv4 address is not a valid SID", "10.0.0.1", nil, true},
		{"non-numeric, non-IP string", "not-a-sid", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			seg, err := NewSegment(tt.sid)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, seg)
		})
	}
}

func TestBehaviorToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		behavior uint16
		want     string
	}{
		{"Reserved", BehaviorReserved, "RESERVED"},
		{"End", BehaviorEND, "END"},
		{"End.X", BehaviorENDX, "ENDX"},
		{"uN", BehaviorUN, "UN"},
		{"uA", BehaviorUA, "UA"},
		{"unassigned value", 0xFFFF, "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, BehaviorToString(tt.behavior))
		})
	}
}

func TestSIDStructureBytesMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    SIDStructureBytes
		want string
	}{
		{"nil structure", nil, "null"},
		{"empty structure", SIDStructureBytes{}, "null"},
		{"populated structure", SIDStructureBytes{32, 16, 0, 80}, `"32,16,0,80"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := tt.s.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(b))
		})
	}
}

func TestSegmentSRv6_Behavior(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		seg  SegmentSRv6
		want uint16
	}{
		{
			name: "no LocalAddr",
			seg:  newTestSegmentSRv6("fc00:0:1::", "", ""),
			want: BehaviorOpaque,
		},
		{
			name: "uSID with remote address is uA",
			seg: func() SegmentSRv6 {
				s := newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", "2001:db8::2")
				s.USid = true
				return s
			}(),
			want: BehaviorUA,
		},
		{
			name: "uSID without remote address is uN",
			seg: func() SegmentSRv6 {
				s := newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", "")
				s.USid = true
				return s
			}(),
			want: BehaviorUN,
		},
		{
			name: "non-uSID with remote address is End.X",
			seg:  newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", "2001:db8::2"),
			want: BehaviorENDX,
		},
		{
			name: "non-uSID without remote address is End",
			seg:  newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			want: BehaviorEND,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.seg.Behavior())
		})
	}
}

func TestIsUSidBehavior(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		behavior uint16
		want     bool
	}{
		{"just below uN range", 0x002A, false},
		{"uN range start", 0x002B, true},
		{"uN behavior", BehaviorUN, true},
		{"uN range end", 0x0032, true},
		{"just above uN range", 0x0033, false},
		{"uA range start", 0x0034, true},
		{"uA behavior", BehaviorUA, true},
		{"uA range end", 0x003B, true},
		{"just above uA range", 0x003C, false},
		{"End behavior", BehaviorEND, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsUSidBehavior(tt.behavior))
		})
	}
}

func TestSIDStructureBytes_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		s       SIDStructureBytes
		wantErr bool
	}{
		{name: "nil structure", s: nil},
		{name: "sum is 128", s: SIDStructureBytes{32, 32, 32, 32}},
		{name: "sum exceeds 128", s: SIDStructureBytes{32, 32, 32, 33}, wantErr: true},
		{name: "wrong element count", s: SIDStructureBytes{32, 32, 32}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.s.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestNewSegmentSRv6WithNodeInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		node    *LsNode
		want    SegmentSRv6
		wantErr bool
	}{
		{
			name: "End SID copies structure and clears USid",
			node: &LsNode{
				SRv6SIDs: []*LsSrv6SID{
					{
						Sids:             []string{testSRv6Addr},
						SIDStructure:     SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
						EndpointBehavior: EndpointBehavior{Behavior: BehaviorEND},
					},
				},
			},
			want: SegmentSRv6{
				Sid:       netip.MustParseAddr("2001:db8::1"),
				LocalAddr: netip.MustParseAddr(testSRv6Addr),
				Structure: SIDStructureBytes{32, 16, 16, 0},
				USid:      false,
			},
		},
		{
			name: "uN behavior sets USid",
			node: &LsNode{
				SRv6SIDs: []*LsSrv6SID{
					{
						Sids:             []string{"fcbb:bb00:0100::"},
						SIDStructure:     SIDStructure{LocalBlock: 32, LocalNode: 16},
						EndpointBehavior: EndpointBehavior{Behavior: BehaviorUN},
					},
				},
			},
			want: SegmentSRv6{
				Sid:       netip.MustParseAddr("2001:db8::1"),
				LocalAddr: netip.MustParseAddr("fcbb:bb00:0100::"),
				Structure: SIDStructureBytes{32, 16, 0, 0},
				USid:      true,
			},
		},
		{
			name: "entries with empty Sids are skipped",
			node: &LsNode{
				SRv6SIDs: []*LsSrv6SID{
					{Sids: []string{}},
					{Sids: []string{testSRv6Addr}, EndpointBehavior: EndpointBehavior{Behavior: BehaviorEND}},
				},
			},
			want: SegmentSRv6{
				Sid:       netip.MustParseAddr("2001:db8::1"),
				LocalAddr: netip.MustParseAddr(testSRv6Addr),
				Structure: SIDStructureBytes{0, 0, 0, 0},
			},
		},
		{
			name: "invalid local SID address",
			node: &LsNode{
				SRv6SIDs: []*LsSrv6SID{{Sids: []string{testInvalidAddr}}},
			},
			wantErr: true,
		},
		{
			name:    "no SRv6 SIDs advertised",
			node:    &LsNode{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewSegmentSRv6WithNodeInfo(netip.MustParseAddr("2001:db8::1"), tt.node)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSegmentSRMPLSHasMPLSStackEntryAttrs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		seg  SegmentSRMPLS
		want bool
	}{
		{"zero value", SegmentSRMPLS{}, false},
		{"TTL set", SegmentSRMPLS{TTL: 255}, true},
		{"TC set", SegmentSRMPLS{TC: 5}, true},
		{"S set", SegmentSRMPLS{S: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.seg.HasMPLSStackEntryAttrs())
		})
	}
}
