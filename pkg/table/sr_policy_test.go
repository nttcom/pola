// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table_test

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

const testSRv6Addr = "fc00:0:1::"

func newTestSegmentSRMPLS(sid uint32, local, remote string) table.SegmentSRMPLS {
	seg := table.NewSegmentSRMPLS(sid)
	if local != "" {
		seg.LocalAddr = netip.MustParseAddr(local)
	}

	if remote != "" {
		seg.RemoteAddr = netip.MustParseAddr(remote)
	}

	return seg
}

func newTestSegmentSRv6(local, remote string) table.SegmentSRv6 {
	seg := table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6Addr)))
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
		a    table.Segment
		b    table.Segment
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
			a:    table.SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr("10.0.0.1")},
			b:    newTestSegmentSRMPLS(0, "10.0.0.1", ""),
			want: false,
		},
		{
			name: "SR-MPLS both SID-absent with same NAI",
			a:    table.SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr("10.0.0.1")},
			b:    table.SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr("10.0.0.1")},
			want: true,
		},
		{
			name: "SR-MPLS same label with different TTL",
			a:    func() table.SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TTL = 1; return s }(),
			b:    func() table.SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TTL = 2; return s }(),
			want: false,
		},
		{
			name: "SR-MPLS same label with different TC",
			a:    func() table.SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TC = 1; return s }(),
			b:    func() table.SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.TC = 2; return s }(),
			want: false,
		},
		{
			name: "SR-MPLS same label with different S",
			a:    func() table.SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.S = false; return s }(),
			b:    func() table.SegmentSRMPLS { s := newTestSegmentSRMPLS(16001, "", ""); s.S = true; return s }(),
			want: false,
		},
		{
			name: "SRv6 same SID and NAI",
			a:    newTestSegmentSRv6("2001:db8::1", ""),
			b:    newTestSegmentSRv6("2001:db8::1", ""),
			want: true,
		},
		{
			name: "SRv6 same SID with different NAI",
			a:    newTestSegmentSRv6("2001:db8::1", ""),
			b:    newTestSegmentSRv6("2001:db8::2", ""),
			want: false,
		},
		{
			name: "SRv6 same SID with different USid",
			a:    func() table.SegmentSRv6 { s := newTestSegmentSRv6("", ""); s.USid = false; return s }(),
			b:    func() table.SegmentSRv6 { s := newTestSegmentSRv6("", ""); s.USid = true; return s }(),
			want: false,
		},
		{
			name: "SRv6 same SID with different Structure",
			a: func() table.SegmentSRv6 {
				s := newTestSegmentSRv6("", "")
				s.Structure = &table.SIDStructure{LocalBlock: 1, LocalNode: 2, LocalFunc: 3, LocalArg: 4}

				return s
			}(),
			b: func() table.SegmentSRv6 {
				s := newTestSegmentSRv6("", "")
				s.Structure = &table.SIDStructure{LocalBlock: 5, LocalNode: 6, LocalFunc: 7, LocalArg: 8}

				return s
			}(),
			want: false,
		},
		{
			name: "different segment types",
			a:    newTestSegmentSRMPLS(16001, "", ""),
			b:    newTestSegmentSRv6("2001:db8::1", ""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, table.SegmentsEqual(tt.a, tt.b))
		})
	}
}

type fakeUnknownSidSegment struct{}

func (fakeUnknownSidSegment) SidString() string       { return "unknown" }
func (fakeUnknownSidSegment) Family() table.DataPlane { return table.DPUnspecified }

func TestSegmentsEqual_UnknownType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    table.Segment
		b    table.Segment
	}{
		{"SRv6 vs SR-MPLS", newTestSegmentSRv6("", ""), newTestSegmentSRMPLS(16001, "", "")},
		{"both unknown", fakeUnknownSidSegment{}, fakeUnknownSidSegment{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.False(t, table.SegmentsEqual(tt.a, tt.b))
		})
	}
}

func TestNewSRPolicy(t *testing.T) {
	t.Parallel()

	segList := []table.Segment{table.NewSegmentSRMPLS(16001)}
	srcAddr := netip.MustParseAddr("10.0.0.1")
	dstAddr := netip.MustParseAddr("10.0.0.2")

	p := table.NewSRPolicy(1, "policy1", segList, srcAddr, dstAddr, 100, 200, 1, table.PolicyUp)

	want := &table.SRPolicy{
		PlspID:      1,
		Name:        "policy1",
		SegmentList: segList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       100,
		Preference:  200,
		LSPID:       1,
		State:       table.PolicyUp,
	}
	assert.Equal(t, want, p)
}

func TestSRPolicyUpdate(t *testing.T) {
	t.Parallel()

	name := "renamed"
	color := uint32(300)
	preference := uint32(400)
	newSegList := []table.Segment{table.NewSegmentSRMPLS(16002)}

	tests := []struct {
		name string
		diff table.PolicyDiff
		want table.SRPolicy
	}{
		{
			name: "state and LSPID always applied, optional fields left unset when nil",
			diff: table.PolicyDiff{State: table.PolicyDown, LSPID: 5},
			want: table.SRPolicy{Name: "original", Color: 100, Preference: 200, LSPID: 5, State: table.PolicyDown, SegmentList: []table.Segment{table.NewSegmentSRMPLS(16001)}},
		},
		{
			name: "optional fields applied when set",
			diff: table.PolicyDiff{Name: &name, Color: &color, Preference: &preference, SegmentList: newSegList, State: table.PolicyUp, LSPID: 6},
			want: table.SRPolicy{Name: name, Color: color, Preference: preference, LSPID: 6, State: table.PolicyUp, SegmentList: newSegList},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := &table.SRPolicy{Name: "original", Color: 100, Preference: 200, SegmentList: []table.Segment{table.NewSegmentSRMPLS(16001)}}
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
		want    table.Segment
		wantErr bool
	}{
		{"SRv6 address", testSRv6Addr, table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6Addr))), false},
		{"SR-MPLS label", "16001", table.NewSegmentSRMPLS(16001), false},
		{"IPv4 address is not a valid SID", "10.0.0.1", nil, true},
		{"non-numeric, non-IP string", "not-a-sid", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			seg, err := table.NewSegment(tt.sid)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, seg)
		})
	}
}

func TestParseSRv6SID_And_NewSegment_RejectsFourInSix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sid     string
		wantErr bool
	}{
		{"IPv4-mapped IPv6 address is rejected", "::ffff:192.0.2.1", true},
		{"ordinary SRv6 SID is accepted", "2001:db8::1", false},
		{"link-local IPv6 address is accepted", "fe80::1", false},
		{"SR-MPLS label is not an SRv6 SID", "16000", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := table.ParseSRv6SID(tt.sid)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("NewSegment rejects an IPv4-mapped IPv6 SID", func(t *testing.T) {
		t.Parallel()

		_, err := table.NewSegment("::ffff:192.0.2.1")
		assert.Error(t, err)
	})

	t.Run("NewSegment accepts an SR-MPLS label", func(t *testing.T) {
		t.Parallel()

		seg, err := table.NewSegment("16000")
		require.NoError(t, err)
		assert.Equal(t, table.NewSegmentSRMPLS(16000), seg)
	})
}

func TestSRv6SID_IsValid(t *testing.T) {
	t.Parallel()

	assert.True(t, table.SRv6SID(netip.MustParseAddr(testSRv6Addr)).IsValid())
	assert.False(t, table.SRv6SID{}.IsValid())
}

func TestSegment_Family(t *testing.T) {
	t.Parallel()

	assert.Equal(t, table.DPSRv6, table.NewSegmentSRv6(table.SRv6SID(netip.MustParseAddr(testSRv6Addr))).Family())
	assert.Equal(t, table.DPSRMPLS, table.NewSegmentSRMPLS(16000).Family())
}

func TestBehaviorToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		behavior uint16
		want     string
	}{
		{"Reserved", table.BehaviorReserved, "RESERVED"},
		{"End", table.BehaviorEND, "END"},
		{"End.X", table.BehaviorENDX, "ENDX"},
		{"uN", table.BehaviorUN, "UN"},
		{"uA", table.BehaviorUA, "UA"},
		{"unassigned value", 0xFFFF, "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, table.BehaviorToString(tt.behavior))
		})
	}
}

func TestSegmentSRv6_StructureMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    *table.SIDStructure
		want string
	}{
		{"not declared", nil, ""},
		{"declared, all zero", &table.SIDStructure{}, `{"localBlock":0,"localNode":0,"localFunc":0,"localArg":0}`},
		{"declared", &table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalArg: 80}, `{"localBlock":32,"localNode":16,"localFunc":0,"localArg":80}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			seg := newTestSegmentSRv6(testSRv6Addr, "")
			seg.Structure = tt.s

			b, err := json.Marshal(seg)
			require.NoError(t, err)

			var got struct {
				SidStructure json.RawMessage `json:"sidStructure"`
			}
			require.NoError(t, json.Unmarshal(b, &got))
			assert.Equal(t, tt.want, string(got.SidStructure))
		})
	}
}

func TestSegmentSRv6_Behavior(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		seg  table.SegmentSRv6
		want uint16
	}{
		{
			name: "no LocalAddr",
			seg:  newTestSegmentSRv6("", ""),
			want: table.BehaviorOpaque,
		},
		{
			name: "uSID with remote address is uA",
			seg: func() table.SegmentSRv6 {
				s := newTestSegmentSRv6("2001:db8::1", "2001:db8::2")
				s.USid = true

				return s
			}(),
			want: table.BehaviorUA,
		},
		{
			name: "uSID without remote address is uN",
			seg: func() table.SegmentSRv6 {
				s := newTestSegmentSRv6("2001:db8::1", "")
				s.USid = true

				return s
			}(),
			want: table.BehaviorUN,
		},
		{
			name: "non-uSID with remote address is End.X",
			seg:  newTestSegmentSRv6("2001:db8::1", "2001:db8::2"),
			want: table.BehaviorENDX,
		},
		{
			name: "non-uSID without remote address is End",
			seg:  newTestSegmentSRv6("2001:db8::1", ""),
			want: table.BehaviorEND,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.seg.BehaviorOrDerived())
		})
	}
}

func TestSegmentSRv6_BehaviorOrDerived_PrefersTEDValue(t *testing.T) {
	t.Parallel()

	seg := newTestSegmentSRv6("2001:db8::1", "")
	seg.Behavior = table.BehaviorENDX
	assert.Equal(t, table.BehaviorENDX, seg.BehaviorOrDerived())
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
		{"uN behavior", table.BehaviorUN, true},
		{"uN range end", 0x0032, true},
		{"just above uN range", 0x0033, false},
		{"uA range start", 0x0034, true},
		{"uA behavior", table.BehaviorUA, true},
		{"uA range end", 0x003B, true},
		{"just above uA range", 0x003C, false},
		{"End behavior", table.BehaviorEND, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, table.IsUSidBehavior(tt.behavior))
		})
	}
}

func TestSIDStructure_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		s       *table.SIDStructure
		wantErr bool
	}{
		{name: "nil (not advertised/declared)", s: nil},
		{name: "sum is 128", s: &table.SIDStructure{LocalBlock: 32, LocalNode: 32, LocalFunc: 32, LocalArg: 32}},
		{name: "sum exceeds 128", s: &table.SIDStructure{LocalBlock: 32, LocalNode: 32, LocalFunc: 32, LocalArg: 33}, wantErr: true},
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
		node    *table.LsNode
		want    table.SegmentSRv6
		wantErr bool
	}{
		{
			name: "End SID copies structure and clears USid",
			node: &table.LsNode{
				SRv6SIDs: []*table.LsSrv6SID{
					{
						Sids:             []string{testSRv6Addr},
						SIDStructure:     &table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
						EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorEND},
					},
				},
			},
			want: table.SegmentSRv6{
				Sid:       table.SRv6SID(netip.MustParseAddr("2001:db8::1")),
				LocalAddr: netip.MustParseAddr(testSRv6Addr),
				Behavior:  table.BehaviorEND,
				Structure: &table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16},
				USid:      false,
			},
		},
		{
			name: "uN behavior sets USid",
			node: &table.LsNode{
				SRv6SIDs: []*table.LsSrv6SID{
					{
						Sids:             []string{"fcbb:bb00:0100::"},
						SIDStructure:     &table.SIDStructure{LocalBlock: 32, LocalNode: 16},
						EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorUN},
					},
				},
			},
			want: table.SegmentSRv6{
				Sid:       table.SRv6SID(netip.MustParseAddr("2001:db8::1")),
				LocalAddr: netip.MustParseAddr("fcbb:bb00:0100::"),
				Behavior:  table.BehaviorUN,
				Structure: &table.SIDStructure{LocalBlock: 32, LocalNode: 16},
				USid:      true,
			},
		},
		{
			name: "entries with empty Sids are skipped",
			node: &table.LsNode{
				SRv6SIDs: []*table.LsSrv6SID{
					{Sids: []string{}},
					{Sids: []string{testSRv6Addr}, EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorEND}},
				},
			},
			want: table.SegmentSRv6{
				Sid:       table.SRv6SID(netip.MustParseAddr("2001:db8::1")),
				LocalAddr: netip.MustParseAddr(testSRv6Addr),
				Behavior:  table.BehaviorEND,
			},
		},
		{
			name: "nil entries are skipped",
			node: &table.LsNode{
				SRv6SIDs: []*table.LsSrv6SID{
					nil,
					{Sids: []string{testSRv6Addr}, EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorEND}},
				},
			},
			want: table.SegmentSRv6{
				Sid:       table.SRv6SID(netip.MustParseAddr("2001:db8::1")),
				LocalAddr: netip.MustParseAddr(testSRv6Addr),
				Behavior:  table.BehaviorEND,
			},
		},
		{
			name: "invalid local SID address",
			node: &table.LsNode{
				SRv6SIDs: []*table.LsSrv6SID{{Sids: []string{testInvalidAddr}}},
			},
			wantErr: true,
		},
		{
			name:    "no SRv6 SIDs advertised",
			node:    &table.LsNode{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := table.NewSegmentSRv6WithNodeInfo(table.SRv6SID(netip.MustParseAddr("2001:db8::1")), tt.node)
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
		seg  table.SegmentSRMPLS
		want bool
	}{
		{"zero value", table.SegmentSRMPLS{}, false},
		{"TTL set", table.SegmentSRMPLS{TTL: 255}, true},
		{"TC set", table.SegmentSRMPLS{TC: 5}, true},
		{"S set", table.SegmentSRMPLS{S: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.seg.HasMPLSStackEntryAttrs())
		})
	}
}
