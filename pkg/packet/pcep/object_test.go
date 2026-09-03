// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep_test

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

const (
	testIPv4Addr1 = "10.0.0.1"
	testIPv4Addr2 = "10.0.0.2"
	testIPv6Addr1 = "2001:db8::1"
	testIPv6Addr2 = "2001:db8::2"
)

// fakeSegment is used to test unsupported segment types.
type fakeSegment struct{}

func (fakeSegment) SidString() string { return "fake" }

func TestSREroSubobject_RoundTrip(t *testing.T) {
	t.Parallel()

	mkSRMPLS := func(sid uint32, tc uint8, s bool, ttl uint8) table.SegmentSRMPLS {
		seg := table.NewSegmentSRMPLS(sid)
		seg.TC, seg.S, seg.TTL = tc, s, ttl

		return seg
	}
	mkSRMPLSWithNAI := func(sid uint32, local, remote string) table.SegmentSRMPLS {
		seg := table.NewSegmentSRMPLS(sid)

		seg.LocalAddr = netip.MustParseAddr(local)
		if remote != "" {
			seg.RemoteAddr = netip.MustParseAddr(remote)
		}

		return seg
	}

	cases := map[string]pcep.SREroSubobject{
		"NAIAbsent_LabelOnly": {
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRAbsent,
			FFlag:         true, MFlag: true,
			Segment: table.NewSegmentSRMPLS(16000),
		},
		"NAIAbsent_LFlag": {
			LFlag:         true,
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRAbsent,
			FFlag:         true, MFlag: true,
			Segment: table.NewSegmentSRMPLS(24),
		},
		"NAIAbsent_CFlag_MPLSStackAttrs": {
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRAbsent,
			FFlag:         true, CFlag: true, MFlag: true,
			Segment: mkSRMPLS(100500, 5, true, 64),
		},
		"IPv4Node": {
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRIPv4Node,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(16001, testIPv4Addr1, ""),
		},
		"IPv6Node": {
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRIPv6Node,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(16002, testIPv6Addr1, ""),
		},
		"IPv4Adjacency": {
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRIPv4Adjacency,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(24001, testIPv4Addr1, testIPv4Addr2),
		},
		"IPv6AdjacencyGlobal": {
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRIPv6AdjacencyGlobal,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(24002, testIPv6Addr1, testIPv6Addr2),
		},
		"IPv4Node_CFlag_MPLSStackAttrs": {
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRIPv4Node,
			CFlag:         true, MFlag: true,
			Segment: func() table.SegmentSRMPLS {
				seg := mkSRMPLSWithNAI(16003, "10.0.0.3", "")
				seg.TC, seg.S, seg.TTL = 3, true, 10

				return seg
			}(),
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l, err := want.Len()
			require.NoError(t, err, "Len failed")

			want.Length = uint8(l)

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, raw, int(l), "Len() must match serialized size")

			var got pcep.SREroSubobject
			require.NoError(t, got.DecodeFromBytes(raw), "DecodeFromBytes failed")
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestNewSREroSubobject_NAIFromSegment(t *testing.T) {
	t.Parallel()

	mk := func(local, remote string) table.SegmentSRMPLS {
		seg := table.NewSegmentSRMPLS(16001)
		if local != "" {
			seg.LocalAddr = netip.MustParseAddr(local)
		}

		if remote != "" {
			seg.RemoteAddr = netip.MustParseAddr(remote)
		}

		return seg
	}

	cases := map[string]struct {
		seg         table.SegmentSRMPLS
		wantNAIType pcep.NAITypeSR
		wantFFlag   bool
		wantLength  uint8
		wantErr     bool
	}{
		"NoAddr": {
			seg: mk("", ""), wantNAIType: pcep.NAITypeSRAbsent, wantFFlag: true, wantLength: 8,
		},
		"IPv4Local": {
			seg: mk(testIPv4Addr1, ""), wantNAIType: pcep.NAITypeSRIPv4Node, wantLength: 12,
		},
		"IPv6Local": {
			seg: mk(testIPv6Addr1, ""), wantNAIType: pcep.NAITypeSRIPv6Node, wantLength: 24,
		},
		"IPv4LocalRemote": {
			seg: mk(testIPv4Addr1, testIPv4Addr2), wantNAIType: pcep.NAITypeSRIPv4Adjacency, wantLength: 16,
		},
		"IPv6LocalRemote": {
			seg: mk(testIPv6Addr1, testIPv6Addr2), wantNAIType: pcep.NAITypeSRIPv6AdjacencyGlobal, wantLength: 40,
		},
		"RemoteWithoutLocal": {
			seg: mk("", testIPv4Addr2), wantErr: true,
		},
		"MixedAddressFamily": {
			seg: mk(testIPv4Addr1, testIPv6Addr2), wantErr: true,
		},
		"LinkLocalAdjacency": {
			seg: mk("fe80::1", "fe80::2"), wantErr: true,
		},
		"LinkLocalRemoteOnly": {
			seg: mk(testIPv6Addr1, "fe80::2"), wantErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			subo, err := pcep.NewSREroSubobject(tc.seg)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantNAIType, subo.NAIType, "NAI type")
			assert.Equal(t, tc.wantFFlag, subo.FFlag, "F flag")
			assert.Equal(t, tc.wantLength, subo.Length, "length")

			raw, err := subo.Serialize()
			require.NoError(t, err, "Serialize failed")
			assert.Len(t, raw, int(tc.wantLength), "serialized size")
		})
	}
}

func TestSREroSubobject_DecodeErrors(t *testing.T) {
	t.Parallel()

	// Type, Length, NT/Flags (4byte) + SID (4byte) [+ NAI]
	cases := map[string][]uint8{
		"TooShort":                {0x24, 0x08, 0x00},
		"ShorterThanHeaderAndSID": {0x24, 0x08, 0x00, 0x08, 0x00, 0x00},
		"TruncatedIPv4NodeNAI":    {0x24, 0x0c, 0x10, 0x01, 0x03, 0xe8, 0x10, 0x00, 0x0a, 0x00},
		"UnsupportedNAIType":      {0x24, 0x08, 0x50, 0x01, 0x03, 0xe8, 0x10, 0x00},
		"UndefinedNAIType":        {0x24, 0x08, 0x70, 0x01, 0x00, 0x00, 0x00, 0x00},
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var subo pcep.SREroSubobject
			assert.Error(t, subo.DecodeFromBytes(raw))
		})
	}
}

// RFC 8664 §4.3.1: S and F MUST NOT both be set.
func TestSREroSubobject_DecodeFromBytes_BothSIDAndNAIAbsent(t *testing.T) {
	t.Parallel()

	raw := []uint8{0x24, 0x04, 0x00, 0x0c} // Length=4, S=1, F=1

	var subo pcep.SREroSubobject
	assert.EqualError(t, subo.DecodeFromBytes(raw), "SREroSubobject: both SID and NAI are absent")
}

// RFC 8664 §4.3.1 requires a non-absent NAI when S=1.
func TestSREroSubobject_DecodeFromBytes_SIDAbsentWithoutNAI(t *testing.T) {
	t.Parallel()

	raw := []uint8{0x24, 0x04, 0x00, 0x04} // S=1, F=0, NAIType=Absent

	var subo pcep.SREroSubobject
	assert.Error(t, subo.DecodeFromBytes(raw))
}

func TestSREroSubobject_SerializeRejectsNAIMismatch(t *testing.T) {
	t.Parallel()

	mkSubo := func(naiType pcep.NAITypeSR, local, remote string) *pcep.SREroSubobject {
		seg := table.NewSegmentSRMPLS(16001)
		if local != "" {
			seg.LocalAddr = netip.MustParseAddr(local)
		}

		if remote != "" {
			seg.RemoteAddr = netip.MustParseAddr(remote)
		}

		return &pcep.SREroSubobject{
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       naiType,
			MFlag:         true,
			Segment:       seg,
		}
	}

	cases := map[string]*pcep.SREroSubobject{
		"IPv4NodeWithoutLocalAddr":   mkSubo(pcep.NAITypeSRIPv4Node, "", ""),
		"IPv4NodeWithIPv6LocalAddr":  mkSubo(pcep.NAITypeSRIPv4Node, testIPv6Addr1, ""),
		"IPv6NodeWithIPv4LocalAddr":  mkSubo(pcep.NAITypeSRIPv6Node, testIPv4Addr1, ""),
		"AdjacencyWithoutRemoteAddr": mkSubo(pcep.NAITypeSRIPv4Adjacency, testIPv4Addr1, ""),
		"IPv6AdjacencyWithIPv4Addrs": mkSubo(
			pcep.NAITypeSRIPv6AdjacencyGlobal, testIPv4Addr1, testIPv4Addr2,
		),
		"UnsupportedNAIType": mkSubo(pcep.NAITypeSRUnnumberedAdjacency, testIPv4Addr1, testIPv4Addr2),
	}

	for name, subo := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := subo.Serialize()
			assert.Error(t, err)
		})
	}

	_, err := mkSubo(pcep.NAITypeSR(0x07), testIPv4Addr1, testIPv4Addr2).Len()
	assert.Error(t, err)
}

func TestSREroSubobject_DecodeFromBytes_SIDAbsent(t *testing.T) {
	t.Parallel()

	mkSegment := func(local, remote string) table.SegmentSRMPLS {
		var seg table.SegmentSRMPLS
		if local != "" {
			seg.LocalAddr = netip.MustParseAddr(local)
		}

		if remote != "" {
			seg.RemoteAddr = netip.MustParseAddr(remote)
		}

		return seg
	}

	cases := map[string]struct {
		naiType   pcep.NAITypeSR
		sFlag     bool
		local     string
		remote    string
		naiLength uint16
	}{
		"IPv4Node_S0":            {pcep.NAITypeSRIPv4Node, false, testIPv4Addr1, "", 4},
		"IPv4Node_S1":            {pcep.NAITypeSRIPv4Node, true, testIPv4Addr1, "", 4},
		"IPv6Node_S0":            {pcep.NAITypeSRIPv6Node, false, testIPv6Addr1, "", 16},
		"IPv6Node_S1":            {pcep.NAITypeSRIPv6Node, true, testIPv6Addr1, "", 16},
		"IPv4Adjacency_S0":       {pcep.NAITypeSRIPv4Adjacency, false, testIPv4Addr1, testIPv4Addr2, 8},
		"IPv4Adjacency_S1":       {pcep.NAITypeSRIPv4Adjacency, true, testIPv4Addr1, testIPv4Addr2, 8},
		"IPv6AdjacencyGlobal_S0": {pcep.NAITypeSRIPv6AdjacencyGlobal, false, testIPv6Addr1, testIPv6Addr2, 32},
		"IPv6AdjacencyGlobal_S1": {pcep.NAITypeSRIPv6AdjacencyGlobal, true, testIPv6Addr1, testIPv6Addr2, 32},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			seg := mkSegment(tc.local, tc.remote)
			if !tc.sFlag {
				seg.Sid = 16001
			}

			subo := &pcep.SREroSubobject{
				SubobjectType: pcep.SubobjectTypeEROSR,
				NAIType:       tc.naiType,
				SFlag:         tc.sFlag,
				MFlag:         true,
				Segment:       seg,
			}

			l, err := subo.Len()
			require.NoError(t, err)

			wantLen := uint16(4) + tc.naiLength
			if !tc.sFlag {
				wantLen += 4
			}

			require.Equal(t, wantLen, l, "Len()")
			subo.Length = uint8(l)

			raw, err := subo.Serialize()
			require.NoError(t, err)
			require.Len(t, raw, int(l), "Serialize() size must match Len()")

			var got pcep.SREroSubobject
			require.NoError(t, got.DecodeFromBytes(raw))
			assert.Equal(t, tc.sFlag, got.SFlag)
			assert.Equal(t, seg.LocalAddr, got.Segment.LocalAddr, "NAI read position after SID")
			assert.Equal(t, seg.RemoteAddr, got.Segment.RemoteAddr, "NAI read position after SID")

			if tc.sFlag {
				assert.Zero(t, got.Segment.Sid, "SID must not be decoded when S=1")
			} else {
				assert.Equal(t, seg.Sid, got.Segment.Sid)
			}
		})
	}
}

func TestSREroSubobject_TableRoundTrip_SIDAbsent(t *testing.T) {
	t.Parallel()

	seg := table.SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr(testIPv4Addr1)}
	subo := &pcep.SREroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSR,
		NAIType:       pcep.NAITypeSRIPv4Node,
		SFlag:         true,
		MFlag:         true,
		Segment:       seg,
	}
	l, err := subo.Len()
	require.NoError(t, err)

	subo.Length = uint8(l)
	raw, err := subo.Serialize()
	require.NoError(t, err)

	var decoded pcep.SREroSubobject
	require.NoError(t, decoded.DecodeFromBytes(raw))
	assert.True(t, decoded.SFlag)

	tableSeg, ok := decoded.ToSegment().(table.SegmentSRMPLS)
	require.True(t, ok)
	assert.True(t, tableSeg.SidAbsent, "SID-absent must survive conversion to the table layer")
	assert.Zero(t, tableSeg.Sid, "SID-absent must not be mistaken for label 0")

	rebuilt, err := pcep.NewSREroSubobject(tableSeg)
	require.NoError(t, err)
	assert.True(t, rebuilt.SFlag, "NewSREroSubobject must restore S=1 from SidAbsent")

	raw2, err := rebuilt.Serialize()
	require.NoError(t, err)
	assert.Equal(t, raw, raw2, "re-serialized bytes must match the original SID-absent encoding")
}

func TestNewSREroSubobject_SidAbsentWithoutNAI(t *testing.T) {
	t.Parallel()

	_, err := pcep.NewSREroSubobject(table.SegmentSRMPLS{SidAbsent: true})
	assert.Error(t, err)
}

func TestNewSREroSubobject_SidAbsentWithMPLSStackEntryAttrs(t *testing.T) {
	t.Parallel()

	seg := table.SegmentSRMPLS{
		SidAbsent: true,
		LocalAddr: netip.MustParseAddr(testIPv4Addr1),
		TTL:       1,
	}
	_, err := pcep.NewSREroSubobject(seg)
	assert.Error(t, err, "MPLS stack entry attributes are unrepresentable without a SID")
}

func TestSREroSubobject_DecodeFromBytes_TruncatedAfterHeader(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"SIDWordCutShort": {0x24, 0x04, 0x00, 0x00},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var subo pcep.SREroSubobject
			assert.Error(t, subo.DecodeFromBytes(raw))
		})
	}

	t.Run("NAICutShortAfterSID", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x24, 0x0a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		var subo pcep.SREroSubobject
		assert.ErrorContains(t, subo.DecodeFromBytes(raw), "truncated NAI")
	})

	t.Run("TrailingByteAfterSID", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x24, 0x09, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}

		var subo pcep.SREroSubobject
		assert.EqualError(t, subo.DecodeFromBytes(raw), "SREroSubobject: declared length does not match S/F flags")
	})
}

func TestSRv6EroSubobject_RoundTrip(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")
	local := netip.MustParseAddr(testIPv6Addr1)
	remote := netip.MustParseAddr(testIPv6Addr2)

	cases := map[string]pcep.SRv6EroSubobject{
		"IPv6Node_END": {
			SubobjectType: pcep.SubobjectTypeEROSRv6,
			NAIType:       pcep.NAITypeSRv6IPv6Node,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local},
		},
		"IPv6AdjGlobal_ENDX": {
			SubobjectType: pcep.SubobjectTypeEROSRv6,
			NAIType:       pcep.NAITypeSRv6IPv6AdjacencyGlobal,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local, RemoteAddr: remote},
		},
		"IPv6Node_USid_WithStructure": {
			SubobjectType: pcep.SubobjectTypeEROSRv6,
			NAIType:       pcep.NAITypeSRv6IPv6Node,
			TFlag:         true,
			Segment: table.SegmentSRv6{
				Sid: sid, LocalAddr: local, USid: true,
				Structure: []uint8{32, 16, 16, 0},
			},
		},
		"LFlag_IPv6Node": {
			LFlag:         true,
			SubobjectType: pcep.SubobjectTypeEROSRv6,
			NAIType:       pcep.NAITypeSRv6IPv6Node,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local},
		},
		// SID is absent (S=1); the NAI identifies the segment.
		"SIDAbsent_NAIPresent": {
			SubobjectType: pcep.SubobjectTypeEROSRv6,
			NAIType:       pcep.NAITypeSRv6IPv6Node,
			VFlag:         true, SFlag: true,
			Segment: table.SegmentSRv6{LocalAddr: local},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l, err := want.Len()
			require.NoError(t, err, "Len failed")

			want.Length = uint8(l)

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, raw, int(l), "Len() must match serialized size")

			var got pcep.SRv6EroSubobject
			require.NoError(t, got.DecodeFromBytes(raw), "DecodeFromBytes failed")
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestRSVPIPv4PrefixEroSubobject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]pcep.RSVPIPv4PrefixEroSubobject{
		"HostPrefix": {
			SubobjectType: pcep.SubobjectTypeEROIPv4Prefix,
			Address:       netip.MustParseAddr(testIPv4Addr1),
			PrefixLen:     32,
		},
		"NetworkPrefix": {
			SubobjectType: pcep.SubobjectTypeEROIPv4Prefix,
			Address:       netip.MustParseAddr("192.0.2.0"),
			PrefixLen:     24,
		},
		"LFlag": {
			LFlag:         true,
			SubobjectType: pcep.SubobjectTypeEROIPv4Prefix,
			Address:       netip.MustParseAddr("172.16.0.1"),
			PrefixLen:     32,
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l, err := want.Len()
			require.NoError(t, err, "Len failed")

			want.Length = uint8(l)

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, raw, int(l), "Len() must match serialized size")

			var got pcep.RSVPIPv4PrefixEroSubobject
			require.NoError(t, got.DecodeFromBytes(raw), "DecodeFromBytes failed")
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestSrpObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := pcep.SrpObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestSrpObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	// 4(header) + 8(fixed SRP fields) + pcep.TLVValueOffset(4)+65531(value) = 65547: exceeds the 16-bit Object-Length field.
	o := pcep.SrpObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestOpenObject_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"Empty":     {},
		"OneByte":   {0x20},
		"ThreeByte": {0x20, 0x1e, 0x78},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.OpenObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectTypeOpenOpen, body))
		})
	}
}

func TestOpenObject_DecodeFromBytes_UnsupportedVersion(t *testing.T) {
	t.Parallel()

	var o pcep.OpenObject
	assert.Error(t, o.DecodeFromBytes(pcep.ObjectTypeOpenOpen, []uint8{0x40, 0x1e, 0x78, 0x01}))
}

func TestOpenObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := pcep.OpenObject{Caps: []pcep.CapabilityInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestOpenObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	o := pcep.OpenObject{Caps: []pcep.CapabilityInterface{&pcep.UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestValidateTimers(t *testing.T) {
	t.Parallel()

	uint8Ptr := func(v uint8) *uint8 { return &v }

	cases := map[string]struct {
		keepalive uint8
		deadTimer *uint8
		wantErr   bool
	}{
		"NilDeadTimer_KeepaliveZero":       {keepalive: 0, deadTimer: nil, wantErr: false},
		"NilDeadTimer_KeepaliveNonzero":    {keepalive: 30, deadTimer: nil, wantErr: false},
		"ExplicitZero_KeepaliveZero":       {keepalive: 0, deadTimer: uint8Ptr(0), wantErr: false},
		"ExplicitNonzero_KeepaliveZero":    {keepalive: 0, deadTimer: uint8Ptr(1), wantErr: true},
		"ExplicitGreater_KeepaliveNonzero": {keepalive: 30, deadTimer: uint8Ptr(60), wantErr: false},
		"ExplicitEqual_KeepaliveNonzero":   {keepalive: 30, deadTimer: uint8Ptr(30), wantErr: true},
		"ExplicitLess_KeepaliveNonzero":    {keepalive: 30, deadTimer: uint8Ptr(10), wantErr: true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := pcep.ValidateTimers(tt.keepalive, tt.deadTimer)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLSPAObject_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"Empty":       {},
		"PartialBody": make([]uint8, 14), // LSPA object body requires at least 15 bytes
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.LSPAObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectType(1), body))
		})
	}
}

func TestErrorObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := pcep.ErrorObject{Tlvs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestErrorObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	// 4(header) + 4(fixed error fields) + pcep.TLVValueOffset(4)+65531(value) = 65543: exceeds the 16-bit Object-Length field.
	o := pcep.ErrorObject{Tlvs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestCloseObject_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"Empty":       {},
		"PartialBody": {0x00, 0x00, 0x00},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.CloseObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectTypeCloseClose, body))
		})
	}
}

func TestLSPObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := pcep.LSPObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestLSPObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	// 4(header) + 4(fixed LSP fields) + pcep.TLVValueOffset(4)+65531(value) = 65543: exceeds the 16-bit Object-Length field.
	o := pcep.LSPObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

// Ensures pcep.NewAssociationObject preserves the existing wire format.
func TestNewAssociationObject_DefaultCandidatePathIdentifier(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	o, err := pcep.NewAssociationObject(srcAddr, dstAddr, 100, 200)
	require.NoError(t, err, "NewAssociationObject failed")

	expected := []byte{
		0x28, 0x10, 0x00, 0x44, // common object header: class=ASSOCIATION, type=1, length=0x44
		0x00, 0x00, 0x00, 0x00, // reserved + flags
		0x00, 0x06, 0x00, 0x01, // assoc type=6 (SRPolicyAssociation), assoc id=1
		0xc0, 0x00, 0x02, 0x01, // assoc source=192.0.2.1
		0x00, 0x1f, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xc0, 0x00, 0x02, 0x02, // pcep.ExtendedAssociationID TLV: color=100, endpoint=192.0.2.2
		0x00, 0x39, 0x00, 0x1c, // SRPOLICY-CPATH-ID TLV: type=0x0039, len=28
		0x0a, 0x00, 0x00, 0x00, // protocol=0x0a + mbz
		0x00, 0x00, 0x00, 0x00, // ASN=0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originator addr padding
		0xc0, 0x00, 0x02, 0x02, // dstAddr=192.0.2.2
		0x00, 0x00, 0x00, 0x01, // discriminator=1
		0x00, 0x3b, 0x00, 0x04, 0x00, 0x00, 0x00, 0xc8, // SRPOLICY-CPATH-PREFERENCE TLV: preference=200
	}

	raw, err := o.Serialize()
	require.NoError(t, err, "Serialize failed")
	assert.Equal(t, expected, raw, "AssociationObject wire bytes changed")
}

// Verifies the Originator ASN option is reflected in the Juniper CP-ID TLV.
func TestNewAssociationObject_JuniperLegacy_OriginatorASN(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	cases := map[string]struct {
		opts        []pcep.Opt
		expectedASN uint32
	}{
		"OriginatorASNSet": {
			opts:        []pcep.Opt{pcep.VendorSpecific(pcep.JuniperLegacy), pcep.OriginatorASN(65001)},
			expectedASN: 65001,
		},
		"OriginatorASNOmitted": {
			opts:        []pcep.Opt{pcep.VendorSpecific(pcep.JuniperLegacy)},
			expectedASN: 0,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o, err := pcep.NewAssociationObject(srcAddr, dstAddr, 100, 200, tt.opts...)
			require.NoError(t, err)

			require.Len(t, o.TLVs, 3)

			cpID, ok := o.TLVs[1].(*pcep.SRPolicyCandidatePathIdentifierJuniper)
			require.True(t, ok, "CP-ID TLV must be represented as SRPolicyCandidatePathIdentifierJuniper")

			assert.Equal(t, tt.expectedASN, cpID.OriginatorASN)
		})
	}
}

// pcep.JuniperLegacy uses the IPv4 Extended Association ID TLV format.
// IPv6 endpoints must be rejected during object construction.
func TestNewAssociationObject_JuniperLegacy_RejectsIPv6(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr(testIPv6Addr1)
	dstAddr := netip.MustParseAddr(testIPv6Addr2)

	_, err := pcep.NewAssociationObject(srcAddr, dstAddr, 100, 200, pcep.VendorSpecific(pcep.JuniperLegacy))
	assert.Error(t, err)
}

// Verifies Juniper vendor-specific TLVs preserve typed fields and legacy wire format.
func TestNewAssociationObject_JuniperLegacy_TypedTLV(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	o, err := pcep.NewAssociationObject(srcAddr, dstAddr, 100, 200, pcep.VendorSpecific(pcep.JuniperLegacy))
	require.NoError(t, err, "NewAssociationObject failed")

	require.Len(t, o.TLVs, 3)
	require.IsType(t, &pcep.ExtendedAssociationIDIPv4Juniper{}, o.TLVs[0])

	cpID, ok := o.TLVs[1].(*pcep.SRPolicyCandidatePathIdentifierJuniper)
	require.True(t, ok, "CP-ID TLV must be represented as SRPolicyCandidatePathIdentifierJuniper")

	require.IsType(t, &pcep.SRPolicyCandidatePathPreferenceJuniper{}, o.TLVs[2])

	assert.Equal(t, uint8(pcep.ProtocolOriginPCEP), cpID.ProtocolOrigin)
	assert.Equal(t, uint32(0), cpID.OriginatorASN)
	assert.Equal(t, netip.IPv4Unspecified(), cpID.OriginatorAddr)
	assert.Equal(t, uint32(1), cpID.Discriminator)
}

// Ensures typed TLV conversion preserves the existing Juniper wire format byte-for-byte.
func TestNewAssociationObject_JuniperLegacy_WireFormat(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	o, err := pcep.NewAssociationObject(srcAddr, dstAddr, 100, 200, pcep.VendorSpecific(pcep.JuniperLegacy))
	require.NoError(t, err, "NewAssociationObject failed")

	expected := []byte{
		0x28, 0x10, 0x00, 0x44, // common object header: class=ASSOCIATION, type=1, length=0x44
		0x00, 0x00, 0x00, 0x00, // reserved + flags
		0xff, 0xe1, 0x00, 0x00, // assoc type=0xffe1 (SRPolicyAssociationJuniper), assoc id=0
		0xc0, 0x00, 0x02, 0x01, // assoc source=192.0.2.1

		0xff, 0xe3, 0x00, 0x08, // pcep.ExtendedAssociationID TLV (Juniper): type=0xffe3, length=8
		0x00, 0x00, 0x00, 0x64, // color=100
		0xc0, 0x00, 0x02, 0x02, // endpoint=192.0.2.2

		0xff, 0xe4, 0x00, 0x1c, // SRPOLICY-CPATH-ID TLV (Juniper): type=0xffe4, length=28
		byte(pcep.ProtocolOriginPCEP), 0x00, 0x00, 0x00, // protocol origin + MBZ
		0x00, 0x00, 0x00, 0x00, // ASN=0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originator address: zero-filled (Juniper wire format)
		0x00, 0x00, 0x00, 0x01, // discriminator=1

		0xff, 0xe5, 0x00, 0x04, // SRPOLICY-CPATH-PREFERENCE TLV (Juniper): type=0xffe5, length=4
		0x00, 0x00, 0x00, 0xc8, // preference=200
	}

	raw, err := o.Serialize()
	require.NoError(t, err, "Serialize failed")
	assert.Equal(t, expected, raw, "AssociationObject wire bytes changed")
}

// Ensures Juniper legacy pcep.AssociationObject round-trips through serialization and decoding with typed TLVs.
func TestAssociationObject_ColorPreferenceFromTLVs(t *testing.T) {
	t.Parallel()

	dstAddr := netip.MustParseAddr("192.0.2.2")

	cases := map[string]struct {
		object         *pcep.AssociationObject
		wantColor      uint32
		wantPreference uint32
	}{
		"NoMatch": {
			object:    &pcep.AssociationObject{},
			wantColor: 0, wantPreference: 0,
		},
		"RFCTypedTLV": {
			object: &pcep.AssociationObject{
				TLVs: []pcep.TLVInterface{
					&pcep.ExtendedAssociationID{Color: 100, Endpoint: dstAddr},
					&pcep.SRPolicyCandidatePathPreference{Preference: 200},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
		"JuniperTypedTLV": {
			object: &pcep.AssociationObject{
				TLVs: []pcep.TLVInterface{
					&pcep.ExtendedAssociationIDIPv4Juniper{Color: 100, Endpoint: dstAddr},
					&pcep.SRPolicyCandidatePathPreferenceJuniper{Preference: 200},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
		// pcep.UnknownTLV fallback path must still work for vendor TLVs that are not decoded as typed TLVs.
		"UnknownTLVDecodePath": {
			object: &pcep.AssociationObject{
				TLVs: []pcep.TLVInterface{
					&pcep.UnknownTLV{
						Typ:   pcep.TLVExtendedAssociationIDIPv4Juniper,
						Value: pcep.AppendByteSlices(pcep.Uint32ToByteSlice(100), dstAddr.AsSlice()),
					},
					&pcep.UnknownTLV{
						Typ:   pcep.TLVSRPolicyCPathPreferenceJuniper,
						Value: pcep.Uint32ToByteSlice(200),
					},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.wantColor, tt.object.Color(), "color mismatch for '%s'", name)
			assert.Equal(t, tt.wantPreference, tt.object.Preference(), "preference mismatch for '%s'", name)
		})
	}
}

func TestNewVendorInformationObject(t *testing.T) {
	t.Parallel()

	t.Run("CiscoLegacy", func(t *testing.T) {
		t.Parallel()

		got, err := pcep.NewVendorInformationObject(pcep.CiscoLegacy, 100, 200)
		require.NoError(t, err, "NewVendorInformationObject failed")

		want := &pcep.VendorInformationObject{
			ObjectType:       pcep.ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: pcep.EnterpriseNumberCisco,
			TLVs: []pcep.TLVInterface{
				&pcep.UnknownTLV{Typ: pcep.SubTLVColorCisco, Value: pcep.Uint32ToByteSlice(100)},
				&pcep.UnknownTLV{Typ: pcep.SubTLVPreferenceCisco, Value: pcep.Uint32ToByteSlice(200)},
			},
		}
		assert.Equal(t, want, got, "unexpected VendorInformationObject")
		assert.Equal(t, uint32(100), got.Color(), "Color mismatch")
		assert.Equal(t, uint32(200), got.Preference(), "Preference mismatch")
	})

	t.Run("UnknownVendor", func(t *testing.T) {
		t.Parallel()

		_, err := pcep.NewVendorInformationObject(pcep.JuniperLegacy, 100, 200)
		assert.Error(t, err, "expected error for unsupported vendor")
	})
}

func TestVendorInformationObject_ColorPreference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		object         *pcep.VendorInformationObject
		wantColor      uint32
		wantPreference uint32
	}{
		"NoSubTLVs": {
			object:    &pcep.VendorInformationObject{EnterpriseNumber: pcep.EnterpriseNumberCisco},
			wantColor: 0, wantPreference: 0,
		},
		"ColorAndPreference": {
			object: &pcep.VendorInformationObject{
				EnterpriseNumber: pcep.EnterpriseNumberCisco,
				TLVs: []pcep.TLVInterface{
					&pcep.UnknownTLV{Typ: pcep.SubTLVColorCisco, Value: pcep.Uint32ToByteSlice(100)},
					&pcep.UnknownTLV{Typ: pcep.SubTLVPreferenceCisco, Value: pcep.Uint32ToByteSlice(200)},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
		// Values too short to hold a uint32 must yield 0 instead of panicking.
		"ShortSubTLVValues": {
			object: &pcep.VendorInformationObject{
				EnterpriseNumber: pcep.EnterpriseNumberCisco,
				TLVs: []pcep.TLVInterface{
					&pcep.UnknownTLV{Typ: pcep.SubTLVColorCisco, Value: []uint8{}},
					&pcep.UnknownTLV{Typ: pcep.SubTLVPreferenceCisco, Value: []uint8{0x00, 0x01}},
				},
			},
			wantColor: 0, wantPreference: 0,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.wantColor, tt.object.Color(), "color mismatch for '%s'", name)
			assert.Equal(t, tt.wantPreference, tt.object.Preference(), "preference mismatch for '%s'", name)
		})
	}
}

func TestVendorInformationObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := pcep.VendorInformationObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestVendorInformationObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	o := pcep.VendorInformationObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestObjectClass_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		class pcep.ObjectClass
		want  string
	}{
		"Open":    {pcep.ObjectClassOpen, "Open (0x01)"},
		"ERO":     {pcep.ObjectClassERO, "ERO (0x07)"},
		"Unknown": {pcep.ObjectClass(0x99), "Unknown Object Class (0x99)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.class.String())
		})
	}
}

func TestObjectClass_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		class pcep.ObjectClass
		want  string
	}{
		"Open":    {pcep.ObjectClassOpen, "Open (0x01) [RFC5440]"},
		"Unknown": {pcep.ObjectClass(0x99), "Unknown Object Class (0x99)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.class.StringWithReference())
		})
	}
}

func TestCommonObjectHeader_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	var h pcep.CommonObjectHeader
	assert.Error(t, h.DecodeFromBytes([]uint8{0x01, 0x02, 0x03}))
}

func TestNewOpenObject(t *testing.T) {
	t.Parallel()

	caps := []pcep.CapabilityInterface{&pcep.SRPCECapability{MaximumSidDepth: 10}}
	o := pcep.NewOpenObject(7, 30, pcep.DeadTimerFor(30), caps)

	want := &pcep.OpenObject{
		ObjectType: pcep.ObjectTypeOpenOpen,
		Version:    1,
		Keepalive:  30,
		Deadtime:   120, // RFC 5440 §7.3: 4 × Keepalive
		Sid:        7,
		Caps:       caps,
	}
	assert.Equal(t, want, o)
}

func TestNewOpenObject_UsesGivenDeadtime(t *testing.T) {
	t.Parallel()

	o := pcep.NewOpenObject(7, 30, 0, nil)
	assert.Zero(t, o.Deadtime)
}

func TestDeadTimerFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		keepalive uint8
		want      uint8
	}{
		{0, 0},
		{30, 120},
		{63, 252},
		{64, math.MaxUint8},
		{255, math.MaxUint8},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, pcep.DeadTimerFor(tt.keepalive))
	}
}

func TestBandwidthObject_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		objectType pcep.ObjectType
		body       []uint8
		want       uint32
	}{
		"RequestedBandwidth": {pcep.ObjectType(1), []uint8{0x00, 0x00, 0x03, 0xe8}, 1000},
		"ZeroBandwidth":      {pcep.ObjectType(2), []uint8{0x00, 0x00, 0x00, 0x00}, 0},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.BandwidthObject
			require.NoError(t, o.DecodeFromBytes(tt.objectType, tt.body))
			assert.Equal(t, pcep.BandwidthObject{ObjectType: tt.objectType, Bandwidth: tt.want}, o)
		})
	}
}

func TestBandwidthObject_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"Empty":       {},
		"PartialBody": {0x00, 0x00, 0x03},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.BandwidthObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectType(1), body))
		})
	}
}

func TestMetricObject_Serialize(t *testing.T) {
	t.Parallel()

	o := pcep.MetricObject{ObjectType: pcep.ObjectType(1), CFlag: true, BFlag: true, MetricType: 2, MetricValue: 30}
	raw := o.Serialize()
	require.Len(t, raw, int(o.Len()))

	// RFC 5440 §7.8: Metric Value is a 32-bit IEEE floating-point number.
	want := pcep.AppendByteSlices(
		[]uint8{0x06, 0x10, 0x00, 0x0c}, // common object header: class=METRIC, type=1, length=12
		[]uint8{0x00, 0x00, 0x03, 0x02}, // reserved(2) + flags(C=1,B=1) + metric-type=2
		pcep.Uint32ToByteSlice(math.Float32bits(30)),
	)
	assert.Equal(t, want, raw)
}

func TestMetricObject_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	body := pcep.AppendByteSlices([]uint8{0x00, 0x00, 0x02, 0x02}, pcep.Uint32ToByteSlice(math.Float32bits(200)))

	var o pcep.MetricObject
	require.NoError(t, o.DecodeFromBytes(pcep.ObjectType(1), body))
	assert.Equal(t, pcep.MetricObject{ObjectType: pcep.ObjectType(1), CFlag: true, MetricType: 2, MetricValue: 200}, o)
}

func TestMetricObject_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"Empty":       {},
		"PartialBody": {0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.MetricObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectType(1), body))
		})
	}
}

func TestMetricObject_Len(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint16(12), (&pcep.MetricObject{}).Len())
}

func TestNewMetricObject(t *testing.T) {
	t.Parallel()

	o := pcep.NewMetricObject()
	assert.Equal(t, &pcep.MetricObject{ObjectType: pcep.ObjectType(1), MetricType: 2, MetricValue: 30}, o)
}

func TestNewLSPAObject(t *testing.T) {
	t.Parallel()

	o := pcep.NewLSPAObject()
	assert.Equal(t, &pcep.LSPAObject{ObjectType: pcep.ObjectType(1), SetupPriority: 7, HoldingPriority: 7, LFlag: true}, o)
}

func TestErrorObject_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	var o pcep.ErrorObject
	assert.Error(t, o.DecodeFromBytes(pcep.ObjectTypeErrorError, []uint8{0x00, 0x00, 0x01}))
}

func TestNewErrorObject(t *testing.T) {
	t.Parallel()

	tlvs := []pcep.TLVInterface{&pcep.SymbolicPathName{Name: "err"}}
	o := pcep.NewErrorObject(6, 1, tlvs)
	assert.Equal(t, &pcep.ErrorObject{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1, Tlvs: tlvs}, o)
}

func TestCloseReason_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		reason pcep.CloseReason
		want   string
	}{
		"DeadTimerExpired": {pcep.CloseReasonDeadTimerExpired, "DeadTimer expired (0x02)"},
		"Unknown":          {pcep.CloseReason(0x99), "Unknown Close Reason (0x99)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.reason.String())
		})
	}
}

func TestCloseReason_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		reason pcep.CloseReason
		want   string
	}{
		"DeadTimerExpired": {pcep.CloseReasonDeadTimerExpired, "DeadTimer expired (0x02) [RFC5440]"},
		"Unknown":          {pcep.CloseReason(0x99), "Unknown Close Reason (0x99)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.reason.StringWithReference())
		})
	}
}

func TestNewCloseObject(t *testing.T) {
	t.Parallel()

	o := pcep.NewCloseObject(pcep.CloseReasonMalformedPCEPMessage)
	assert.Equal(t, &pcep.CloseObject{ObjectType: pcep.ObjectTypeCloseClose, Reason: pcep.CloseReasonMalformedPCEPMessage}, o)
}

func TestSrpObject_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"TooShort":     {0x00, 0x00, 0x00, 0x00},
		"MalformedTLV": {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xff},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.SrpObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectTypeSRPSRP, body))
		})
	}
}

func TestNewSrpObject(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		segs    []table.Segment
		srpID   uint32
		remove  bool
		want    *pcep.SrpObject
		wantErr bool
	}{
		"NoSegments": {
			segs: nil, srpID: 1,
			want: &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, SrpID: 1, TLVs: []pcep.TLVInterface{}},
		},
		"SRMPLS": {
			segs: []table.Segment{table.NewSegmentSRMPLS(16001)}, srpID: 2,
			want: &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, SrpID: 2, TLVs: []pcep.TLVInterface{&pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRTE}}},
		},
		"SRv6": {
			segs: []table.Segment{table.NewSegmentSRv6(netip.MustParseAddr("fc00:0:1::"))}, srpID: 3, remove: true,
			want: &pcep.SrpObject{ObjectType: pcep.ObjectTypeSRPSRP, RFlag: true, SrpID: 3, TLVs: []pcep.TLVInterface{&pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRv6TE}}},
		},
		"InvalidSegmentType": {
			segs: []table.Segment{fakeSegment{}}, srpID: 4, wantErr: true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := pcep.NewSrpObject(tt.segs, tt.srpID, tt.remove)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLSPObject_Color(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		object *pcep.LSPObject
		want   uint32
	}{
		"NoTLVs":    {&pcep.LSPObject{}, 0},
		"WithColor": {&pcep.LSPObject{TLVs: []pcep.TLVInterface{&pcep.Color{Color: 42}}}, 42},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.object.Color())
		})
	}
}

func TestEroObject_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	srv6AbsentNAIWithoutFFlag := append(
		[]uint8{0x28, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		make([]uint8, 16)...,
	)

	cases := map[string][]uint8{
		"UnknownSubobjectType":      {0x50, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"TruncatedSubobject":        {0x24, 0x0c, 0x10, 0x01, 0x03, 0xe8, 0x10, 0x00, 0x0a, 0x00},
		"SRv6AbsentNAIWithoutFFlag": srv6AbsentNAIWithoutFFlag,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.EroObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectTypeEROExplicitRoute, body))
		})
	}
}

func TestEroObject_Len_Error(t *testing.T) {
	t.Parallel()

	badSubo := &pcep.SREroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSR,
		NAIType:       pcep.NAITypeSR(0x07),
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	o := pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{badSubo}}

	_, err := o.Len()
	assert.Error(t, err)
}

func TestEroObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	badSubo := &pcep.SREroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSR,
		NAIType:       pcep.NAITypeSRIPv4Node,
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	o := pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{badSubo}}

	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestEroObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	newSubobjects := func(n int) []pcep.EroSubobject {
		subobjects := make([]pcep.EroSubobject, n)
		for i := range subobjects {
			subobjects[i] = &pcep.SREroSubobject{
				SubobjectType: pcep.SubobjectTypeEROSR,
				NAIType:       pcep.NAITypeSRAbsent,
				Segment:       table.NewSegmentSRMPLS(16001),
			}
		}

		return subobjects
	}

	t.Run("AtObjectLengthLimit", func(t *testing.T) {
		t.Parallel()

		ero := &pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: newSubobjects(8191)}
		raw, err := ero.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, 65532)

		var header pcep.CommonObjectHeader
		require.NoError(t, header.DecodeFromBytes(raw))
		assert.Equal(t, uint16(65532), header.ObjectLength)
	})

	t.Run("ExceedsObjectLengthLimit", func(t *testing.T) {
		t.Parallel()

		ero := &pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: newSubobjects(8192)}
		_, err := ero.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

func TestNewEroObject_InvalidSegment(t *testing.T) {
	t.Parallel()

	_, err := pcep.NewEroObject([]table.Segment{fakeSegment{}})
	assert.Error(t, err)
}

func TestNewEroSubobject(t *testing.T) {
	t.Parallel()

	t.Run("SRMPLSError", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRMPLS(16001)
		seg.LocalAddr = netip.MustParseAddr(testIPv4Addr1)
		seg.RemoteAddr = netip.MustParseAddr(testIPv6Addr1) // mismatched address families
		_, err := pcep.NewEroSubobject(seg)
		assert.Error(t, err)
	})

	t.Run("SRv6", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(netip.MustParseAddr("fc00:0:1::"))
		subo, err := pcep.NewEroSubobject(seg)
		require.NoError(t, err)
		assert.IsType(t, &pcep.SRv6EroSubobject{}, subo)
	})

	t.Run("InvalidType", func(t *testing.T) {
		t.Parallel()

		_, err := pcep.NewEroSubobject(fakeSegment{})
		assert.Error(t, err)
	})

	t.Run("SRv6LinkLocalError", func(t *testing.T) {
		t.Parallel()

		seg := table.SegmentSRv6{
			Sid:        netip.MustParseAddr("fc00:0:1::"),
			LocalAddr:  netip.MustParseAddr("fe80::1"),
			RemoteAddr: netip.MustParseAddr("fe80::2"),
		}
		_, err := pcep.NewEroSubobject(seg)
		assert.Error(t, err)
	})
}

func TestEroObject_ToSegmentList(t *testing.T) {
	t.Parallel()

	srMPLSSubo, err := pcep.NewSREroSubobject(table.NewSegmentSRMPLS(16001))
	require.NoError(t, err)
	rsvpSubo, err := pcep.NewRSVPIPv4PrefixEroSubobject(netip.MustParseAddr(testIPv4Addr1), 32)
	require.NoError(t, err)

	o := pcep.EroObject{
		ObjectType:    pcep.ObjectTypeEROExplicitRoute,
		EroSubobjects: []pcep.EroSubobject{srMPLSSubo, rsvpSubo},
	}

	assert.Equal(t, []table.Segment{table.NewSegmentSRMPLS(16001)}, o.ToSegmentList())
}

func TestNAITypeSR_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		nt   pcep.NAITypeSR
		want string
	}{
		"IPv4Node": {pcep.NAITypeSRIPv4Node, "NAI is an IPv4 node ID (0x01)"},
		"Unknown":  {pcep.NAITypeSR(0x07), "Unknown NAI Type (0x07)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.nt.String())
		})
	}
}

func TestNAITypeSR_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		nt   pcep.NAITypeSR
		want string
	}{
		"IPv4Node": {pcep.NAITypeSRIPv4Node, "NAI is an IPv4 node ID (0x01) [RFC8664]"},
		"Unknown":  {pcep.NAITypeSR(0x07), "Unknown NAI Type (0x07)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.nt.StringWithReference())
		})
	}
}

func TestSREroSubobject_ToSegment(t *testing.T) {
	t.Parallel()

	seg := table.NewSegmentSRMPLS(16001)
	subo := &pcep.SREroSubobject{Segment: seg}
	assert.Equal(t, seg, subo.ToSegment())
}

func TestNAITypeSRv6_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		nt   pcep.NAITypeSRv6
		want string
	}{
		"IPv6Node": {pcep.NAITypeSRv6IPv6Node, "NAI is an IPv6 node ID (0x02)"},
		"Unknown":  {pcep.NAITypeSRv6(0x01), "Unknown NAI Type (0x01)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.nt.String())
		})
	}
}

func TestNAITypeSRv6_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		nt   pcep.NAITypeSRv6
		want string
	}{
		"IPv6Node": {pcep.NAITypeSRv6IPv6Node, "NAI is an IPv6 node ID (0x02) [RFC9603]"},
		"Unknown":  {pcep.NAITypeSRv6(0x01), "Unknown NAI Type (0x01)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.nt.StringWithReference())
		})
	}
}

func TestSRv6EroSubobject_ToSegment(t *testing.T) {
	t.Parallel()

	seg := table.NewSegmentSRv6(netip.MustParseAddr("fc00:0:1::"))
	subo := &pcep.SRv6EroSubobject{Segment: seg}
	assert.Equal(t, seg, subo.ToSegment())
}

func TestSRv6EroSubobject_Len_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.SRv6EroSubobject{
		// RFC 9603 §4.3.1: when NAI Type is 0 (absent), F MUST be 1.
		"AbsentNAIWithoutFFlag": {NAIType: pcep.NAITypeSRv6Absent, FFlag: false},
		"UnsupportedNAIType":    {NAIType: pcep.NAITypeSRv6(0x01), FFlag: false},
	}

	for name, subo := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := subo.Len()
			assert.Error(t, err)
		})
	}
}

// Serialize still requires LocalAddr even when the NAI is absent (F=1).
func TestSRv6EroSubobject_Serialize_UnknownBehavior(t *testing.T) {
	t.Parallel()

	o := &pcep.SRv6EroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSRv6,
		NAIType:       pcep.NAITypeSRv6Absent,
		FFlag:         true,
		Segment:       table.SegmentSRv6{Sid: netip.MustParseAddr("fc00:0:1::")},
	}

	b, err := o.Serialize()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(b), 8)
	assert.Equal(t, table.BehaviorOpaque, binary.BigEndian.Uint16(b[6:8]))
}

func TestEndpointsObject_Len_Error(t *testing.T) {
	t.Parallel()

	o := pcep.EndpointsObject{SrcAddr: netip.MustParseAddr(testIPv4Addr1), DstAddr: netip.MustParseAddr(testIPv6Addr1)}
	_, err := o.Len()
	assert.Error(t, err)
}

func TestEndpointsObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := pcep.EndpointsObject{SrcAddr: netip.MustParseAddr(testIPv4Addr1), DstAddr: netip.MustParseAddr(testIPv6Addr1)}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestDeterminePccType(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		caps []pcep.CapabilityInterface
		want pcep.PccType
	}{
		"NoCaps":          {nil, pcep.RFCCompliant},
		"NoAssocTypeList": {[]pcep.CapabilityInterface{&pcep.SRPCECapability{}}, pcep.RFCCompliant},
		"CiscoAssocType": {
			[]pcep.CapabilityInterface{&pcep.AssocTypeList{AssocTypes: []pcep.AssocType{pcep.AssocTypeSRPolicyAssociationCisco}}},
			pcep.CiscoLegacy,
		},
		"JuniperAssocType": {
			[]pcep.CapabilityInterface{&pcep.AssocTypeList{AssocTypes: []pcep.AssocType{pcep.AssocTypeSRPolicyAssociationJuniper}}},
			pcep.JuniperLegacy,
		},
		"JuniperWinsOverCisco": {
			[]pcep.CapabilityInterface{&pcep.AssocTypeList{AssocTypes: []pcep.AssocType{
				pcep.AssocTypeSRPolicyAssociationCisco, pcep.AssocTypeSRPolicyAssociationJuniper,
			}}},
			pcep.JuniperLegacy,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, pcep.DeterminePccType(tt.caps))
		})
	}
}

func TestAssociationObject_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	v4Body := []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0xc0, 0x00, 0x02, 0x01}
	v6Body := pcep.AppendByteSlices(
		make([]uint8, 4),
		pcep.Uint16ToByteSlice(uint16(pcep.AssocTypeSRPolicyAssociation)),
		pcep.Uint16ToByteSlice(uint16(1)),
		netip.MustParseAddr(testIPv6Addr1).AsSlice(),
	)

	cases := map[string]struct {
		objectType pcep.ObjectType
		body       []uint8
	}{
		"UnknownObjectType": {pcep.ObjectType(99), v4Body},
		"MalformedIPv4TLV":  {pcep.ObjectTypeAssociationIPv4, pcep.AppendByteSlices(v4Body, []uint8{0x00, 0x27, 0x00, 0xff})},
		"MalformedIPv6TLV":  {pcep.ObjectTypeAssociationIPv6, pcep.AppendByteSlices(v6Body, []uint8{0x00, 0x27, 0x00, 0xff})},
		"EmptyBody":         {pcep.ObjectTypeAssociationIPv4, []uint8{}},
		"PartialCommonBody": {pcep.ObjectTypeAssociationIPv4, make([]uint8, 7)},
		"PartialIPv4Body":   {pcep.ObjectTypeAssociationIPv4, make([]uint8, 11)},
		"PartialIPv6Body":   {pcep.ObjectTypeAssociationIPv6, make([]uint8, 23)},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.AssociationObject
			assert.Error(t, o.DecodeFromBytes(tt.objectType, tt.body))
		})
	}
}

func TestAssociationObject_Len_Error(t *testing.T) {
	t.Parallel()

	o := pcep.AssociationObject{}
	_, err := o.Len()
	assert.Error(t, err)
}

func TestAssociationObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := pcep.AssociationObject{}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestAssociationObject_Serialize_TLVError(t *testing.T) {
	t.Parallel()

	o := pcep.AssociationObject{
		AssocSrc: netip.MustParseAddr("192.0.2.1"),
		TLVs:     []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}},
	}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestAssociationObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	o := pcep.AssociationObject{
		AssocSrc: netip.MustParseAddr("192.0.2.1"),
		TLVs:     []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65531)}},
	}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestNewAssociationObject_MismatchedFamilies(t *testing.T) {
	t.Parallel()

	_, err := pcep.NewAssociationObject(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr(testIPv6Addr1), 100, 200)
	assert.Error(t, err)
}

func TestNewAssociationObject_ObjectType(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		srcAddr netip.Addr
		dstAddr netip.Addr
		want    pcep.ObjectType
	}{
		"IPv4": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), pcep.ObjectTypeAssociationIPv4},
		"IPv6": {netip.MustParseAddr(testIPv6Addr1), netip.MustParseAddr(testIPv6Addr2), pcep.ObjectTypeAssociationIPv6},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o, err := pcep.NewAssociationObject(tt.srcAddr, tt.dstAddr, 100, 200)
			require.NoError(t, err)
			assert.Equal(t, tt.want, o.ObjectType)
		})
	}
}

func TestAssociationObject_Endpoint(t *testing.T) {
	t.Parallel()

	dstAddr := netip.MustParseAddr("192.0.2.2")

	cases := map[string]struct {
		object *pcep.AssociationObject
		want   netip.Addr
	}{
		"NoMatch": {&pcep.AssociationObject{}, netip.Addr{}},
		"ExtendedAssociationID": {
			&pcep.AssociationObject{TLVs: []pcep.TLVInterface{&pcep.ExtendedAssociationID{Endpoint: dstAddr}}},
			dstAddr,
		},
		"JuniperTLV": {
			&pcep.AssociationObject{TLVs: []pcep.TLVInterface{
				&pcep.ExtendedAssociationIDIPv4Juniper{Endpoint: dstAddr},
			}},
			dstAddr,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.object.Endpoint())
		})
	}
}

func TestLSPObject_DecodeFromBytes_Error(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"MalformedTLV": pcep.AppendByteSlices(
			make([]uint8, 4),
			[]uint8{0x00, 0x27, 0x00, 0xff}, // TLV length exceeds available data
		),
		"Empty":       {},
		"PartialBody": {0x00, 0x00, 0x00},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.LSPObject
			assert.Error(t, o.DecodeFromBytes(pcep.ObjectTypeLSPLSP, body))
		})
	}
}

func TestEroObject_Serialize_LenError(t *testing.T) {
	t.Parallel()

	badSubo := &pcep.SREroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSR,
		NAIType:       pcep.NAITypeSRUnnumberedAdjacency,
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	o := pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{badSubo}}

	_, err := o.Serialize()
	assert.Error(t, err)
}

// RFC 9603 §4.3.1: NAI Type 0 requires F=1.
func TestEroObject_Serialize_LenError_SRv6AbsentNAI(t *testing.T) {
	t.Parallel()

	badSubo := &pcep.SRv6EroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSRv6,
		NAIType:       pcep.NAITypeSRv6Absent,
		FFlag:         false,
		Segment:       table.SegmentSRv6{Sid: netip.MustParseAddr("fc00:0:1::")},
	}
	o := pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: []pcep.EroSubobject{badSubo}}

	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestSRv6EroSubobject_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	nodeType := uint8(pcep.NAITypeSRv6IPv6Node) << 4
	adjGlobalType := uint8(pcep.NAITypeSRv6IPv6AdjacencyGlobal) << 4
	adjLinkLocalType := uint8(pcep.NAITypeSRv6IPv6AdjacencyLinkLocal) << 4

	cases := map[string][]uint8{
		"TooShort":     {0x28, 0x00, 0x00},
		"TruncatedSID": pcep.AppendByteSlices([]uint8{0x28, 0x00, 0x00, 0x00}, make([]uint8, 4)),
		"TruncatedNodeNAI": pcep.AppendByteSlices(
			[]uint8{0x28, 0x00, nodeType, 0x00}, make([]uint8, 4+16),
		),
		"TruncatedAdjGlobalNAI": pcep.AppendByteSlices(
			[]uint8{0x28, 0x00, adjGlobalType, 0x00}, make([]uint8, 4+16+16),
		),
		"TruncatedAdjLinkLocalNAI": pcep.AppendByteSlices(
			[]uint8{0x28, 0x00, adjLinkLocalType, 0x00}, make([]uint8, 4+16+16),
		),
		// TFlag requires an additional 4-byte SID-Structure field.
		"TruncatedSIDStructure": pcep.AppendByteSlices(
			[]uint8{0x28, 0x00, 0x00, 0x04}, make([]uint8, 4+16),
		),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.SRv6EroSubobject
			assert.Error(t, o.DecodeFromBytes(raw))
		})
	}
}

func TestSRv6EroSubobject_DecodeFromBytes_SIDStructureOverflow(t *testing.T) {
	t.Parallel()

	raw := pcep.AppendByteSlices(
		[]uint8{0x28, 0x00, 0x00, 0x06}, // NAIType=Absent, T=1, F=1
		make([]uint8, 4),                // reserved + behavior
		netip.MustParseAddr("fc00:0:1::").AsSlice(),
		[]uint8{200, 200, 200, 200}, // sum exceeds 128 bits
		make([]uint8, 4),
	)

	var o pcep.SRv6EroSubobject
	assert.Error(t, o.DecodeFromBytes(raw))
}

func TestSRv6EroSubobject_DecodeFromBytes_BothSIDAndNAIAbsent(t *testing.T) {
	t.Parallel()

	raw := []uint8{0x28, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00}

	var o pcep.SRv6EroSubobject
	assert.Error(t, o.DecodeFromBytes(raw))
}

func TestSRv6EroSubobject_DecodeFromBytes_LinkLocalAdjacency(t *testing.T) {
	t.Parallel()

	local := netip.MustParseAddr(testIPv6Addr1)
	remote := netip.MustParseAddr(testIPv6Addr2)

	raw := pcep.AppendByteSlices(
		[]uint8{0x28, 8 + 16 + 40, uint8(pcep.NAITypeSRv6IPv6AdjacencyLinkLocal) << 4, 0x00},
		make([]uint8, 4),
		netip.MustParseAddr("fc00:0:1::").AsSlice(),
		local.AsSlice(), make([]uint8, 4),
		remote.AsSlice(), make([]uint8, 4),
	)

	var o pcep.SRv6EroSubobject
	require.NoError(t, o.DecodeFromBytes(raw))
	assert.Equal(t, local, o.Segment.LocalAddr)
	assert.Equal(t, remote, o.Segment.RemoteAddr)

	l, err := o.Len()
	require.NoError(t, err)
	assert.Equal(t, uint16(8+16+40), l)
}

func TestSRv6EroSubobject_DecodeFromBytes_TruncatedAfterHeader(t *testing.T) {
	t.Parallel()

	t.Run("SIDCutShort", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x28, 10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		var o pcep.SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated SID")
	})

	t.Run("NodeNAICutShort", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x28, 10, uint8(pcep.NAITypeSRv6IPv6Node) << 4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		var o pcep.SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated NAI (Node)")
	})

	t.Run("AdjGlobalNAICutShort", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x28, 10, uint8(pcep.NAITypeSRv6IPv6AdjacencyGlobal) << 4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		var o pcep.SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated NAI (AdjGlobal)")
	})

	t.Run("AdjLinkLocalNAICutShort", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x28, 10, uint8(pcep.NAITypeSRv6IPv6AdjacencyLinkLocal) << 4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		var o pcep.SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated NAI (AdjLinkLocal)")
	})

	t.Run("SIDStructureCutShort", func(t *testing.T) {
		t.Parallel()

		raw := pcep.AppendByteSlices(
			[]uint8{0x28, 26, 0x00, 0x06},
			make([]uint8, 4),
			netip.MustParseAddr("fc00:0:1::").AsSlice(),
			make([]uint8, 2),
		)

		var o pcep.SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated SID-Structure")
	})

	t.Run("SIDStructureInvalidSum", func(t *testing.T) {
		t.Parallel()

		// The SID-Structure field is complete, but its four lengths sum to 800 bits.
		raw := pcep.AppendByteSlices(
			[]uint8{0x28, 32, 0x00, 0x06},
			make([]uint8, 4),
			netip.MustParseAddr("fc00:0:1::").AsSlice(),
			[]uint8{200, 200, 200, 200},
			make([]uint8, 4),
		)

		var o pcep.SRv6EroSubobject
		assert.ErrorContains(t, o.DecodeFromBytes(raw), "exceeds")
	})

	t.Run("TrailingByteAfterNAI", func(t *testing.T) {
		t.Parallel()

		raw := pcep.AppendByteSlices(
			[]uint8{0x28, 25, uint8(pcep.NAITypeSRv6IPv6Node) << 4, 0x01},
			make([]uint8, 4),
			netip.MustParseAddr(testIPv6Addr1).AsSlice(),
			make([]uint8, 1),
		)

		var o pcep.SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: declared length does not match V/T/F/S flags")
	})
}

func TestNewSRv6EroSubobject_NAIFromSegment(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")
	local := netip.MustParseAddr(testIPv6Addr1)
	remote := netip.MustParseAddr(testIPv6Addr2)

	cases := map[string]struct {
		seg         table.SegmentSRv6
		wantNAIType pcep.NAITypeSRv6
		wantFFlag   bool
		wantTFlag   bool
	}{
		"NoAddr": {
			seg: table.SegmentSRv6{Sid: sid}, wantNAIType: pcep.NAITypeSRv6Absent, wantFFlag: true,
		},
		"LocalOnly": {
			seg: table.SegmentSRv6{Sid: sid, LocalAddr: local}, wantNAIType: pcep.NAITypeSRv6IPv6Node,
		},
		"LocalAndRemote": {
			seg:         table.SegmentSRv6{Sid: sid, LocalAddr: local, RemoteAddr: remote},
			wantNAIType: pcep.NAITypeSRv6IPv6AdjacencyGlobal,
		},
		"WithStructure": {
			seg:         table.SegmentSRv6{Sid: sid, LocalAddr: local, Structure: []uint8{32, 16, 16, 0}},
			wantNAIType: pcep.NAITypeSRv6IPv6Node, wantTFlag: true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			subo, err := pcep.NewSRv6EroSubobject(tt.seg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantNAIType, subo.NAIType)
			assert.Equal(t, tt.wantFFlag, subo.FFlag)
			assert.Equal(t, tt.wantTFlag, subo.TFlag)
		})
	}
}

func TestNewSRv6EroSubobject_LinkLocalRejected(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")

	cases := map[string]table.SegmentSRv6{
		"LinkLocalAdjacency": {
			Sid: sid, LocalAddr: netip.MustParseAddr("fe80::1"), RemoteAddr: netip.MustParseAddr("fe80::2"),
		},
		"LinkLocalRemoteOnly": {
			Sid: sid, LocalAddr: netip.MustParseAddr(testIPv6Addr1), RemoteAddr: netip.MustParseAddr("fe80::2"),
		},
	}

	for name, seg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := pcep.NewSRv6EroSubobject(seg)
			assert.Error(t, err)
		})
	}
}

func TestNewSRv6EroSubobject_AddressFamilyRejected(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")

	cases := map[string]table.SegmentSRv6{
		"IPv4LocalAddr": {
			Sid: sid, LocalAddr: netip.MustParseAddr(testIPv4Addr1),
		},
		"IPv4RemoteAddr": {
			Sid: sid, LocalAddr: netip.MustParseAddr(testIPv6Addr1), RemoteAddr: netip.MustParseAddr(testIPv4Addr2),
		},
		"RemoteAddrWithoutLocalAddr": {
			Sid: sid, RemoteAddr: netip.MustParseAddr(testIPv6Addr2),
		},
	}

	for name, seg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := pcep.NewSRv6EroSubobject(seg)
			assert.Error(t, err)
		})
	}
}

func TestNewSRv6EroSubobject_StructureValidation(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")
	local := netip.MustParseAddr(testIPv6Addr1)

	t.Run("EmptyStructureIsAbsent", func(t *testing.T) {
		t.Parallel()

		subo, err := pcep.NewSRv6EroSubobject(table.SegmentSRv6{Sid: sid, LocalAddr: local, Structure: []uint8{}})
		require.NoError(t, err)
		assert.False(t, subo.TFlag)
	})

	t.Run("InvalidLengthRejected", func(t *testing.T) {
		t.Parallel()

		_, err := pcep.NewSRv6EroSubobject(table.SegmentSRv6{Sid: sid, LocalAddr: local, Structure: []uint8{32, 16, 16}})
		assert.Error(t, err)
	})
}

func TestRSVPIPv4PrefixEroSubobject_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"TooShort":            {0x01, 0x08, 0x0a, 0x00, 0x00, 0x01},
		"InvalidLengthField":  {0x01, 0x07, 0x0a, 0x00, 0x00, 0x01, 0x20, 0x00},
		"InvalidPrefixLength": {0x01, 0x08, 0x0a, 0x00, 0x00, 0x01, 0x21, 0x00},
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o pcep.RSVPIPv4PrefixEroSubobject
			assert.Error(t, o.DecodeFromBytes(raw))
		})
	}
}

func TestRSVPIPv4PrefixEroSubobject_Serialize_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.RSVPIPv4PrefixEroSubobject{
		"NotIPv4":             {Address: netip.MustParseAddr(testIPv6Addr1)},
		"InvalidPrefixLength": {Address: netip.MustParseAddr(testIPv4Addr1), PrefixLen: 33},
	}

	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := o.Serialize()
			assert.Error(t, err)
		})
	}
}

func TestNewRSVPIPv4PrefixEroSubobject_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		address   netip.Addr
		prefixLen uint8
	}{
		"NotIPv4":             {netip.MustParseAddr(testIPv6Addr1), 32},
		"InvalidPrefixLength": {netip.MustParseAddr(testIPv4Addr1), 33},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := pcep.NewRSVPIPv4PrefixEroSubobject(tt.address, tt.prefixLen)
			assert.Error(t, err)
		})
	}
}
