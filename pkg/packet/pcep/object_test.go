// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
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

	cases := map[string]SREroSubobject{
		"NAIAbsent_LabelOnly": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			FFlag:         true, MFlag: true,
			Segment: table.NewSegmentSRMPLS(16000),
		},
		"NAIAbsent_LFlag": {
			LFlag:         true,
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			FFlag:         true, MFlag: true,
			Segment: table.NewSegmentSRMPLS(24),
		},
		"NAIAbsent_CFlag_MPLSStackAttrs": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			FFlag:         true, CFlag: true, MFlag: true,
			Segment: mkSRMPLS(100500, 5, true, 64),
		},
		"IPv4Node": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRIPv4Node,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(16001, "10.0.0.1", ""),
		},
		"IPv6Node": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRIPv6Node,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(16002, "2001:db8::1", ""),
		},
		"IPv4Adjacency": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRIPv4Adjacency,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(24001, "10.0.0.1", "10.0.0.2"),
		},
		"IPv6AdjacencyGlobal": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRIPv6AdjacencyGlobal,
			MFlag:         true,
			Segment:       mkSRMPLSWithNAI(24002, "2001:db8::1", "2001:db8::2"),
		},
		"IPv4Node_CFlag_MPLSStackAttrs": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRIPv4Node,
			CFlag:         true, MFlag: true,
			Segment: func() table.SegmentSRMPLS {
				seg := mkSRMPLSWithNAI(16003, "10.0.0.3", "")
				seg.TC, seg.S, seg.TTL = 3, true, 10
				return seg
			}(),
		},
		"AbsentNAIType_FFlagFalse_SFlagTrue": {
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			SFlag:         true, MFlag: true,
			Segment: table.SegmentSRMPLS{},
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
			require.Equal(t, int(l), len(raw), "Len() must match serialized size")

			var got SREroSubobject
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
		wantNAIType NAITypeSR
		wantFFlag   bool
		wantLength  uint8
		wantErr     bool
	}{
		"NoAddr": {
			seg: mk("", ""), wantNAIType: NAITypeSRAbsent, wantFFlag: true, wantLength: 8,
		},
		"IPv4Local": {
			seg: mk("10.0.0.1", ""), wantNAIType: NAITypeSRIPv4Node, wantLength: 12,
		},
		"IPv6Local": {
			seg: mk("2001:db8::1", ""), wantNAIType: NAITypeSRIPv6Node, wantLength: 24,
		},
		"IPv4LocalRemote": {
			seg: mk("10.0.0.1", "10.0.0.2"), wantNAIType: NAITypeSRIPv4Adjacency, wantLength: 16,
		},
		"IPv6LocalRemote": {
			seg: mk("2001:db8::1", "2001:db8::2"), wantNAIType: NAITypeSRIPv6AdjacencyGlobal, wantLength: 40,
		},
		"RemoteWithoutLocal": {
			seg: mk("", "10.0.0.2"), wantErr: true,
		},
		"MixedAddressFamily": {
			seg: mk("10.0.0.1", "2001:db8::2"), wantErr: true,
		},
		"LinkLocalAdjacency": {
			seg: mk("fe80::1", "fe80::2"), wantErr: true,
		},
		"LinkLocalRemoteOnly": {
			seg: mk("2001:db8::1", "fe80::2"), wantErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			subo, err := NewSREroSubobject(tc.seg)
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
			assert.Equal(t, int(tc.wantLength), len(raw), "serialized size")
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

			var subo SREroSubobject
			assert.Error(t, subo.DecodeFromBytes(raw))
		})
	}
}

// RFC 8664 §4.3.1: S and F MUST NOT both be set.
func TestSREroSubobject_DecodeFromBytes_BothSIDAndNAIAbsent(t *testing.T) {
	t.Parallel()

	raw := []uint8{0x24, 0x08, 0x00, 0x0c} // S=1, F=1

	var subo SREroSubobject
	assert.Error(t, subo.DecodeFromBytes(raw))
}

func TestSREroSubobject_SerializeRejectsNAIMismatch(t *testing.T) {
	t.Parallel()

	mkSubo := func(naiType NAITypeSR, local, remote string) *SREroSubobject {
		seg := table.NewSegmentSRMPLS(16001)
		if local != "" {
			seg.LocalAddr = netip.MustParseAddr(local)
		}
		if remote != "" {
			seg.RemoteAddr = netip.MustParseAddr(remote)
		}
		return &SREroSubobject{
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       naiType,
			MFlag:         true,
			Segment:       seg,
		}
	}

	cases := map[string]*SREroSubobject{
		"IPv4NodeWithoutLocalAddr":   mkSubo(NAITypeSRIPv4Node, "", ""),
		"IPv4NodeWithIPv6LocalAddr":  mkSubo(NAITypeSRIPv4Node, "2001:db8::1", ""),
		"IPv6NodeWithIPv4LocalAddr":  mkSubo(NAITypeSRIPv6Node, "10.0.0.1", ""),
		"AdjacencyWithoutRemoteAddr": mkSubo(NAITypeSRIPv4Adjacency, "10.0.0.1", ""),
		"IPv6AdjacencyWithIPv4Addrs": mkSubo(
			NAITypeSRIPv6AdjacencyGlobal, "10.0.0.1", "10.0.0.2",
		),
		"UnsupportedNAIType": mkSubo(NAITypeSRUnnumberedAdjacency, "10.0.0.1", "10.0.0.2"),
	}

	for name, subo := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := subo.Serialize()
			assert.Error(t, err)
		})
	}

	_, err := mkSubo(NAITypeSR(0x07), "10.0.0.1", "10.0.0.2").Len()
	assert.Error(t, err)
}

func TestNAITypeSR_naiLength(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		nt      NAITypeSR
		want    uint16
		wantErr bool
	}{
		"Absent":                 {nt: NAITypeSRAbsent, want: 0},
		"IPv4Node":               {nt: NAITypeSRIPv4Node, want: 4},
		"IPv6Node":               {nt: NAITypeSRIPv6Node, want: 16},
		"IPv4Adjacency":          {nt: NAITypeSRIPv4Adjacency, want: 8},
		"IPv6AdjacencyGlobal":    {nt: NAITypeSRIPv6AdjacencyGlobal, want: 32},
		"UnnumberedAdjacency":    {nt: NAITypeSRUnnumberedAdjacency, wantErr: true},
		"IPv6AdjacencyLinkLocal": {nt: NAITypeSRIPv6AdjacencyLinkLocal, wantErr: true},
		"Unknown":                {nt: NAITypeSR(0x07), wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.nt.naiLength()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
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
		naiType   NAITypeSR
		sFlag     bool
		local     string
		remote    string
		naiLength uint16
	}{
		"IPv4Node_S0":            {NAITypeSRIPv4Node, false, "10.0.0.1", "", 4},
		"IPv4Node_S1":            {NAITypeSRIPv4Node, true, "10.0.0.1", "", 4},
		"IPv6Node_S0":            {NAITypeSRIPv6Node, false, "2001:db8::1", "", 16},
		"IPv6Node_S1":            {NAITypeSRIPv6Node, true, "2001:db8::1", "", 16},
		"IPv4Adjacency_S0":       {NAITypeSRIPv4Adjacency, false, "10.0.0.1", "10.0.0.2", 8},
		"IPv4Adjacency_S1":       {NAITypeSRIPv4Adjacency, true, "10.0.0.1", "10.0.0.2", 8},
		"IPv6AdjacencyGlobal_S0": {NAITypeSRIPv6AdjacencyGlobal, false, "2001:db8::1", "2001:db8::2", 32},
		"IPv6AdjacencyGlobal_S1": {NAITypeSRIPv6AdjacencyGlobal, true, "2001:db8::1", "2001:db8::2", 32},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			seg := mkSegment(tc.local, tc.remote)
			if !tc.sFlag {
				seg.Sid = 16001
			}
			subo := &SREroSubobject{
				SubobjectType: SubobjectTypeEROSR,
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
			require.Equal(t, int(l), len(raw), "Serialize() size must match Len()")

			var got SREroSubobject
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

func TestSREroSubobject_DecodeFromBytes_TruncatedAfterHeader(t *testing.T) {

	t.Parallel()

	cases := map[string][]uint8{
		"SIDWordCutShort": {0x24, 0x04, 0x00, 0x00},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var subo SREroSubobject
			assert.Error(t, subo.DecodeFromBytes(raw))
		})
	}

	t.Run("NAICutShortAfterSID", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x24, 0x0a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		var subo SREroSubobject
		assert.ErrorContains(t, subo.DecodeFromBytes(raw), "truncated NAI")
	})

	t.Run("TrailingByteAfterSID", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x24, 0x09, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
		var subo SREroSubobject
		assert.EqualError(t, subo.DecodeFromBytes(raw), "SREroSubobject: declared length does not match S/F flags")
	})
}

func TestSRv6EroSubobject_RoundTrip(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")

	cases := map[string]SRv6EroSubobject{
		"IPv6Node_END": {
			SubobjectType: SubobjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6Node,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local},
		},
		"IPv6AdjGlobal_ENDX": {
			SubobjectType: SubobjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6AdjacencyGlobal,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local, RemoteAddr: remote},
		},
		"IPv6Node_USid_WithStructure": {
			SubobjectType: SubobjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6Node,
			TFlag:         true,
			Segment: table.SegmentSRv6{
				Sid: sid, LocalAddr: local, USid: true,
				Structure: []uint8{32, 16, 16, 0},
			},
		},
		"LFlag_IPv6Node": {
			LFlag:         true,
			SubobjectType: SubobjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6Node,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local},
		},
		// SID is absent (S=1); the NAI identifies the segment.
		"SIDAbsent_NAIPresent": {
			SubobjectType: SubobjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6Node,
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
			require.Equal(t, int(l), len(raw), "Len() must match serialized size")

			var got SRv6EroSubobject
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

	cases := map[string]RSVPIPv4PrefixEroSubobject{
		"HostPrefix": {
			SubobjectType: SubobjectTypeEROIPv4Prefix,
			Address:       netip.MustParseAddr("10.0.0.1"),
			PrefixLen:     32,
		},
		"NetworkPrefix": {
			SubobjectType: SubobjectTypeEROIPv4Prefix,
			Address:       netip.MustParseAddr("192.0.2.0"),
			PrefixLen:     24,
		},
		"LFlag": {
			LFlag:         true,
			SubobjectType: SubobjectTypeEROIPv4Prefix,
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
			require.Equal(t, int(l), len(raw), "Len() must match serialized size")

			var got RSVPIPv4PrefixEroSubobject
			require.NoError(t, got.DecodeFromBytes(raw), "DecodeFromBytes failed")
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestSrpObject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]SrpObject{
		"NoTLVs_RFalse": {
			ObjectType: ObjectTypeSRPSRP, SrpID: 42,
		},
		"NoTLVs_RTrue": {
			ObjectType: ObjectTypeSRPSRP, RFlag: true, SrpID: 0xDEADBEEF,
		},
		"PathSetupType_SRTE": {
			ObjectType: ObjectTypeSRPSRP, SrpID: 1,
			TLVs: []TLVInterface{&PathSetupType{PathSetupType: PathSetupTypeSRTE}},
		},
		"PathSetupType_SRv6TE": {
			ObjectType: ObjectTypeSRPSRP, RFlag: true, SrpID: 100,
			TLVs: []TLVInterface{&PathSetupType{PathSetupType: PathSetupTypeSRv6TE}},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Equal(t, want.Len(), len(raw), "Len() must match serialized size")

			// DecodeFromBytes expects the object body without the CommonObjectHeader.
			var got SrpObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeSRPSRP, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestSrpObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := SrpObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestSrpObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	// 4(header) + 8(fixed SRP fields) + TLVValueOffset(4)+65531(value) = 65547: exceeds the 16-bit Object-Length field.
	o := SrpObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestOpenObject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]OpenObject{
		"NoCaps": {
			ObjectType: ObjectTypeOpenOpen,
			Version:    1,
			Keepalive:  30,
			Deadtime:   120,
			Sid:        1,
		},
		"FlagNonZero": {
			ObjectType: ObjectTypeOpenOpen,
			Version:    1,
			Flag:       0x1f,
			Keepalive:  30,
			Deadtime:   120,
			Sid:        1,
		},
		"WithSRPCECapability": {
			ObjectType: ObjectTypeOpenOpen,
			Version:    1,
			Keepalive:  60,
			Deadtime:   240,
			Sid:        7,
			Caps: []CapabilityInterface{
				&SRPCECapability{
					HasUnlimitedMaxSIDDepth: true,
					IsNAISupported:          true,
					MaximumSidDepth:         10,
				},
			},
		},
		"WithMultipleCaps": {
			ObjectType: ObjectTypeOpenOpen,
			Version:    1,
			Keepalive:  30,
			Deadtime:   120,
			Sid:        42,
			Caps: []CapabilityInterface{
				&SRPCECapability{
					HasUnlimitedMaxSIDDepth: false,
					IsNAISupported:          false,
					MaximumSidDepth:         16,
				},
				&SRv6PCECapability{
					IsNAISupported: true,
				},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Equal(t, want.Len(), len(raw), "Len() must match serialized size")

			var got OpenObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeOpenOpen, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
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

			var o OpenObject
			assert.Error(t, o.DecodeFromBytes(ObjectTypeOpenOpen, body))
		})
	}
}

func TestOpenObject_DecodeFromBytes_UnsupportedVersion(t *testing.T) {
	t.Parallel()

	var o OpenObject
	assert.Error(t, o.DecodeFromBytes(ObjectTypeOpenOpen, []uint8{0x40, 0x1e, 0x78, 0x01}))
}

func TestOpenObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := OpenObject{Caps: []CapabilityInterface{&UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestOpenObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	o := OpenObject{Caps: []CapabilityInterface{&UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestLSPAObject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]LSPAObject{
		"AllZero": {
			ObjectType: ObjectType(1),
		},
		"WithPriorities": {
			ObjectType:      ObjectType(1),
			ExcludeAny:      0x000000ff,
			IncludeAny:      0x0000ff00,
			IncludeAll:      0x00ff0000,
			SetupPriority:   3,
			HoldingPriority: 5,
		},
		"LFlag": {
			ObjectType:      ObjectType(1),
			SetupPriority:   7,
			HoldingPriority: 7,
			LFlag:           true,
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := want.Serialize()
			require.Equal(t, int(want.Len()), len(raw), "Len() must match serialized size")

			var got LSPAObject
			require.NoError(t,
				got.DecodeFromBytes(want.ObjectType, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
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

			var o LSPAObject
			assert.Error(t, o.DecodeFromBytes(ObjectType(1), body))
		})
	}
}

func TestPCEPErrorObject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]PCEPErrorObject{
		"SessionFailure": {
			ObjectType: ObjectTypeErrorError,
			ErrorType:  1,
			ErrorValue: 1,
		},
		"CapabilityNotSupported": {
			ObjectType: ObjectTypeErrorError,
			ErrorType:  2,
			ErrorValue: 0,
		},
		"InvalidObject": {
			ObjectType: ObjectTypeErrorError,
			ErrorType:  3,
			ErrorValue: 5,
		},
		"WithSymbolicPathNameTLV": {
			ObjectType: ObjectTypeErrorError,
			ErrorType:  19,
			ErrorValue: 1,
			Tlvs: []TLVInterface{
				&SymbolicPathName{Name: "lsp-err"},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Equal(t, want.Len(), len(raw), "Len() must match serialized size")

			var got PCEPErrorObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeErrorError, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestPCEPErrorObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := PCEPErrorObject{Tlvs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestPCEPErrorObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	// 4(header) + 4(fixed error fields) + TLVValueOffset(4)+65531(value) = 65543: exceeds the 16-bit Object-Length field.
	o := PCEPErrorObject{Tlvs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestCloseObject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]CloseObject{
		"NoExplanation": {
			ObjectType: ObjectTypeCloseClose,
			Reason:     CloseReasonNoExplanationProvided,
		},
		"DeadTimerExpired": {
			ObjectType: ObjectTypeCloseClose,
			Reason:     CloseReasonDeadTimerExpired,
		},
		"MalformedPCEPMessage": {
			ObjectType: ObjectTypeCloseClose,
			Reason:     CloseReasonMalformedPCEPMessage,
		},
		"TooManyUnknownRequestsReplies": {
			ObjectType: ObjectTypeCloseClose,
			Reason:     CloseReasonTooManyUnknownRequestsReplies,
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := want.Serialize()
			require.Equal(t, int(want.Len()), len(raw), "Len() must match serialized size")

			var got CloseObject
			require.NoError(t, got.DecodeFromBytes(ObjectTypeCloseClose, raw[commonObjectHeaderLength:]))
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
		})
	}
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

			var o CloseObject
			assert.Error(t, o.DecodeFromBytes(ObjectTypeCloseClose, body))
		})
	}
}

func TestLSPObject_RoundTrip(t *testing.T) {
	t.Parallel()

	v4Src := netip.MustParseAddr("10.0.0.1")
	v4Dst := netip.MustParseAddr("10.0.0.2")
	v6Src := netip.MustParseAddr("2001:db8::1")
	v6Dst := netip.MustParseAddr("2001:db8::2")

	cases := map[string]LSPObject{
		"NoTLVs": {
			ObjectType: ObjectTypeLSPLSP,
			PlspID:     0x12345,
			OFlag:      1,
			AFlag:      true,
			DFlag:      true,
		},
		"CFlag": {
			ObjectType: ObjectTypeLSPLSP,
			PlspID:     0x12345,
			CFlag:      true,
			OFlag:      1,
			AFlag:      true,
			DFlag:      true,
		},
		"SymbolicPathNameOnly": {
			ObjectType: ObjectTypeLSPLSP,
			Name:       "lsp-1",
			PlspID:     1,
			OFlag:      1,
			AFlag:      true,
			DFlag:      true,
			TLVs: []TLVInterface{
				&SymbolicPathName{Name: "lsp-1"},
			},
		},
		"SymbolicPathNameAndColor": {
			ObjectType: ObjectTypeLSPLSP,
			Name:       "lsp-color",
			PlspID:     2,
			OFlag:      1,
			AFlag:      true,
			DFlag:      true,
			TLVs: []TLVInterface{
				&SymbolicPathName{Name: "lsp-color"},
				&Color{Color: 100},
			},
		},
		"IPv4LSPIdentifiers": {
			ObjectType: ObjectTypeLSPLSP,
			Name:       "lsp-v4",
			SrcAddr:    v4Src,
			DstAddr:    v4Dst,
			PlspID:     3,
			LSPID:      7,
			OFlag:      1,
			AFlag:      true,
			SFlag:      true,
			DFlag:      true,
			TLVs: []TLVInterface{
				&SymbolicPathName{Name: "lsp-v4"},
				&IPv4LSPIdentifiers{
					IPv4TunnelSenderAddress:   v4Src,
					IPv4TunnelEndpointAddress: v4Dst,
					LSPID:                     7,
					TunnelID:                  11,
					ExtendedTunnelID:          0xdeadbeef,
				},
			},
		},
		"IPv6LSPIdentifiers": {
			ObjectType: ObjectTypeLSPLSP,
			Name:       "lsp-v6",
			SrcAddr:    v6Src,
			DstAddr:    v6Dst,
			PlspID:     4,
			LSPID:      9,
			OFlag:      1,
			AFlag:      true,
			RFlag:      true,
			DFlag:      true,
			TLVs: []TLVInterface{
				&SymbolicPathName{Name: "lsp-v6"},
				&IPv6LSPIdentifiers{
					IPv6TunnelSenderAddress:   v6Src,
					IPv6TunnelEndpointAddress: v6Dst,
					LSPID:                     9,
					TunnelID:                  13,
					ExtendedTunnelID:          [16]byte{0x01, 0x02, 0x03, 0x04},
				},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Equal(t, want.Len(), len(raw), "Len() must match serialized size")

			var got LSPObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeLSPLSP, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestLSPObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := LSPObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestLSPObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	// 4(header) + 4(fixed LSP fields) + TLVValueOffset(4)+65531(value) = 65543: exceeds the 16-bit Object-Length field.
	o := LSPObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestEroObject_RoundTrip(t *testing.T) {
	t.Parallel()

	mkSREro := func(sid uint32) *SREroSubobject {
		subo, err := NewSREroSubobject(table.NewSegmentSRMPLS(sid))
		require.NoError(t, err)
		return subo
	}
	mkSRv6Ero := func(sidStr, localStr string) *SRv6EroSubobject {
		seg := table.NewSegmentSRv6(netip.MustParseAddr(sidStr))
		seg.LocalAddr = netip.MustParseAddr(localStr)
		subo, err := NewSRv6EroSubobject(seg)
		require.NoError(t, err)
		return subo
	}
	mkRSVPIPv4PrefixEro := func(addrStr string, prefixLen uint8) *RSVPIPv4PrefixEroSubobject {
		subo, err := NewRSVPIPv4PrefixEroSubobject(netip.MustParseAddr(addrStr), prefixLen)
		require.NoError(t, err)
		return subo
	}

	cases := map[string]EroObject{
		"Empty": {
			ObjectType:    ObjectTypeEROExplicitRoute,
			EroSubobjects: []EroSubobject{},
		},
		"SingleSRMPLS": {
			ObjectType: ObjectTypeEROExplicitRoute,
			EroSubobjects: []EroSubobject{
				mkSREro(16001),
			},
		},
		"MultipleSRMPLS": {
			ObjectType: ObjectTypeEROExplicitRoute,
			EroSubobjects: []EroSubobject{
				mkSREro(16001),
				mkSREro(16002),
				mkSREro(16003),
			},
		},
		"SingleSRv6": {
			ObjectType: ObjectTypeEROExplicitRoute,
			EroSubobjects: []EroSubobject{
				mkSRv6Ero("fc00:0:1::", "2001:db8::1"),
			},
		},
		"SingleRSVPIPv4Prefix": {
			ObjectType: ObjectTypeEROExplicitRoute,
			EroSubobjects: []EroSubobject{
				mkRSVPIPv4PrefixEro("10.0.0.1", 32),
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")

			l, err := want.Len()
			require.NoError(t, err, "Len failed")
			require.Equal(t, int(l), len(raw), "Len() must match serialized size")

			var got EroObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeEROExplicitRoute, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			if len(want.EroSubobjects) == 0 {
				assert.Empty(t, got.EroSubobjects, "decoded subobjects must be empty")
			} else {
				assert.Equal(t, want, got, "round-trip value mismatch")
			}

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestAssociationObject_RoundTrip(t *testing.T) {
	t.Parallel()

	v4 := netip.MustParseAddr("192.0.2.1")
	v4Endpoint := netip.MustParseAddr("192.0.2.2")
	v6 := netip.MustParseAddr("2001:db8::1")
	v6Endpoint := netip.MustParseAddr("2001:db8::2")

	cases := map[string]AssociationObject{
		"IPv4_NoTLVs": {
			ObjectType: ObjectTypeAssociationIPv4,
			AssocType:  AssocType(AssociationTypeSRPolicyAssociation),
			AssocID:    1,
			AssocSrc:   v4,
		},
		"IPv4_RFlag": {
			ObjectType: ObjectTypeAssociationIPv4,
			RFlag:      true,
			AssocType:  AssocType(AssociationTypeSRPolicyAssociation),
			AssocID:    1,
			AssocSrc:   v4,
		},
		"IPv4_WithSRPolicyTLVs": {
			ObjectType: ObjectTypeAssociationIPv4,
			AssocType:  AssocType(AssociationTypeSRPolicyAssociation),
			AssocID:    1,
			AssocSrc:   v4,
			TLVs: []TLVInterface{
				&ExtendedAssociationID{
					Color:    100,
					Endpoint: v4Endpoint,
				},
				&SRPolicyCandidatePathIdentifier{
					ProtocolOrigin: ProtocolOriginPCEP,
					OriginatorASN:  65000,
					OriginatorAddr: v4Endpoint,
					Discriminator:  7,
				},
				&SRPolicyCandidatePathPreference{
					Preference: 200,
				},
			},
		},
		"IPv6_NoTLVs": {
			ObjectType: ObjectTypeAssociationIPv6,
			AssocType:  AssocType(AssociationTypeSRPolicyAssociation),
			AssocID:    1,
			AssocSrc:   v6,
		},
		"IPv6_WithExtendedAssociationID": {
			ObjectType: ObjectTypeAssociationIPv6,
			AssocType:  AssocType(AssociationTypeSRPolicyAssociation),
			AssocID:    1,
			AssocSrc:   v6,
			TLVs: []TLVInterface{
				&ExtendedAssociationID{
					Color:    300,
					Endpoint: v6Endpoint,
				},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")

			l, err := want.Len()
			require.NoError(t, err, "Len failed")
			require.Equal(t, int(l), len(raw), "Len() must match serialized size")

			var got AssociationObject
			require.NoError(t,
				got.DecodeFromBytes(want.ObjectType, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

// Ensures NewAssociationObject preserves the existing wire format.
func TestNewAssociationObject_DefaultCandidatePathIdentifier(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	o, err := NewAssociationObject(srcAddr, dstAddr, 100, 200)
	require.NoError(t, err, "NewAssociationObject failed")

	expected := []byte{
		0x28, 0x10, 0x00, 0x44, // common object header: class=ASSOCIATION, type=1, length=0x44
		0x00, 0x00, 0x00, 0x00, // reserved + flags
		0x00, 0x06, 0x00, 0x01, // assoc type=6 (SRPolicyAssociation), assoc id=1
		0xc0, 0x00, 0x02, 0x01, // assoc source=192.0.2.1
		0x00, 0x1f, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xc0, 0x00, 0x02, 0x02, // ExtendedAssociationID TLV: color=100, endpoint=192.0.2.2
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
		opts        []Opt
		expectedASN uint32
	}{
		"OriginatorASNSet": {
			opts:        []Opt{VendorSpecific(JuniperLegacy), OriginatorASN(65001)},
			expectedASN: 65001,
		},
		"OriginatorASNOmitted": {
			opts:        []Opt{VendorSpecific(JuniperLegacy)},
			expectedASN: 0,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o, err := NewAssociationObject(srcAddr, dstAddr, 100, 200, tt.opts...)
			require.NoError(t, err)

			require.Len(t, o.TLVs, 3)

			cpID, ok := o.TLVs[1].(*SRPolicyCandidatePathIdentifierJuniper)
			require.True(t, ok, "CP-ID TLV must be represented as SRPolicyCandidatePathIdentifierJuniper")

			assert.Equal(t, tt.expectedASN, cpID.OriginatorASN)
		})
	}
}

// JuniperLegacy uses the IPv4 Extended Association ID TLV format.
// IPv6 endpoints must be rejected during object construction.
func TestNewAssociationObject_JuniperLegacy_RejectsIPv6(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("2001:db8::1")
	dstAddr := netip.MustParseAddr("2001:db8::2")

	_, err := NewAssociationObject(srcAddr, dstAddr, 100, 200, VendorSpecific(JuniperLegacy))
	assert.Error(t, err)
}

// Verifies Juniper vendor-specific TLVs preserve typed fields and legacy wire format.
func TestNewAssociationObject_JuniperLegacy_TypedTLV(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	o, err := NewAssociationObject(srcAddr, dstAddr, 100, 200, VendorSpecific(JuniperLegacy))
	require.NoError(t, err, "NewAssociationObject failed")

	require.Len(t, o.TLVs, 3)
	require.IsType(t, &ExtendedAssociationIDIPv4Juniper{}, o.TLVs[0])

	cpID, ok := o.TLVs[1].(*SRPolicyCandidatePathIdentifierJuniper)
	require.True(t, ok, "CP-ID TLV must be represented as SRPolicyCandidatePathIdentifierJuniper")

	require.IsType(t, &SRPolicyCandidatePathPreferenceJuniper{}, o.TLVs[2])

	assert.Equal(t, uint8(ProtocolOriginPCEP), cpID.ProtocolOrigin)
	assert.Equal(t, uint32(0), cpID.OriginatorASN)
	assert.Equal(t, netip.IPv4Unspecified(), cpID.OriginatorAddr)
	assert.Equal(t, uint32(1), cpID.Discriminator)
}

// Ensures typed TLV conversion preserves the existing Juniper wire format byte-for-byte.
func TestNewAssociationObject_JuniperLegacy_WireFormat(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	o, err := NewAssociationObject(srcAddr, dstAddr, 100, 200, VendorSpecific(JuniperLegacy))
	require.NoError(t, err, "NewAssociationObject failed")

	expected := []byte{
		0x28, 0x10, 0x00, 0x44, // common object header: class=ASSOCIATION, type=1, length=0x44
		0x00, 0x00, 0x00, 0x00, // reserved + flags
		0xff, 0xe1, 0x00, 0x00, // assoc type=0xffe1 (SRPolicyAssociationJuniper), assoc id=0
		0xc0, 0x00, 0x02, 0x01, // assoc source=192.0.2.1

		0xff, 0xe3, 0x00, 0x08, // ExtendedAssociationID TLV (Juniper): type=0xffe3, length=8
		0x00, 0x00, 0x00, 0x64, // color=100
		0xc0, 0x00, 0x02, 0x02, // endpoint=192.0.2.2

		0xff, 0xe4, 0x00, 0x1c, // SRPOLICY-CPATH-ID TLV (Juniper): type=0xffe4, length=28
		byte(ProtocolOriginPCEP), 0x00, 0x00, 0x00, // protocol origin + MBZ
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

// Ensures Juniper legacy AssociationObject round-trips through serialization and decoding with typed TLVs.
func TestAssociationObject_JuniperLegacyRoundTrip(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	o, err := NewAssociationObject(srcAddr, dstAddr, 100, 200, VendorSpecific(JuniperLegacy))
	require.NoError(t, err, "NewAssociationObject failed")

	raw, err := o.Serialize()
	require.NoError(t, err, "Serialize failed")

	var got AssociationObject
	err = got.DecodeFromBytes(ObjectTypeAssociationIPv4, raw[commonObjectHeaderLength:])
	require.NoError(t, err, "DecodeFromBytes failed")

	require.Len(t, got.TLVs, 3)

	// Verify Juniper vendor TLVs survive decoding as typed TLVs.
	require.IsType(t, &ExtendedAssociationIDIPv4Juniper{}, got.TLVs[0])

	cpID, ok := got.TLVs[1].(*SRPolicyCandidatePathIdentifierJuniper)
	require.True(t, ok, "CP-ID TLV must be represented as SRPolicyCandidatePathIdentifierJuniper")

	require.IsType(t, &SRPolicyCandidatePathPreferenceJuniper{}, got.TLVs[2])

	assert.Equal(t, uint32(100), got.Color())
	assert.Equal(t, uint32(200), got.Preference())
	assert.Equal(t, dstAddr, got.Endpoint())

	assert.Equal(t, uint8(ProtocolOriginPCEP), cpID.ProtocolOrigin)
	assert.Equal(t, uint32(0), cpID.OriginatorASN)
	assert.Equal(t, netip.IPv4Unspecified(), cpID.OriginatorAddr)
	assert.Equal(t, uint32(1), cpID.Discriminator)
}

func TestAssociationObject_ColorPreferenceFromTLVs(t *testing.T) {
	t.Parallel()

	dstAddr := netip.MustParseAddr("192.0.2.2")

	cases := map[string]struct {
		object         *AssociationObject
		wantColor      uint32
		wantPreference uint32
	}{
		"NoMatch": {
			object:    &AssociationObject{},
			wantColor: 0, wantPreference: 0,
		},
		"RFCTypedTLV": {
			object: &AssociationObject{
				TLVs: []TLVInterface{
					&ExtendedAssociationID{Color: 100, Endpoint: dstAddr},
					&SRPolicyCandidatePathPreference{Preference: 200},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
		"JuniperTypedTLV": {
			object: &AssociationObject{
				TLVs: []TLVInterface{
					&ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: ExtendedAssociationID{Color: 100, Endpoint: dstAddr}},
					&SRPolicyCandidatePathPreferenceJuniper{SRPolicyCandidatePathPreference: SRPolicyCandidatePathPreference{Preference: 200}},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
		// UnknownTLV fallback path must still work for vendor TLVs that are not decoded as typed TLVs.
		"UnknownTLVDecodePath": {
			object: &AssociationObject{
				TLVs: []TLVInterface{
					&UnknownTLV{
						Typ:   TLVExtendedAssociationIDIPv4Juniper,
						Value: AppendByteSlices(Uint32ToByteSlice(100), dstAddr.AsSlice()),
					},
					&UnknownTLV{
						Typ:   TLVSRPolicyCPathPreferenceJuniper,
						Value: Uint32ToByteSlice(200),
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

		got, err := NewVendorInformationObject(CiscoLegacy, 100, 200)
		require.NoError(t, err, "NewVendorInformationObject failed")

		want := &VendorInformationObject{
			ObjectType:       ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: EnterpriseNumberCisco,
			TLVs: []TLVInterface{
				&UnknownTLV{Typ: SubTLVColorCisco, Value: Uint32ToByteSlice(100)},
				&UnknownTLV{Typ: SubTLVPreferenceCisco, Value: Uint32ToByteSlice(200)},
			},
		}
		assert.Equal(t, want, got, "unexpected VendorInformationObject")
		assert.Equal(t, uint32(100), got.Color(), "Color mismatch")
		assert.Equal(t, uint32(200), got.Preference(), "Preference mismatch")
	})

	t.Run("UnknownVendor", func(t *testing.T) {
		t.Parallel()

		_, err := NewVendorInformationObject(JuniperLegacy, 100, 200)
		assert.Error(t, err, "expected error for unsupported vendor")
	})
}

func TestVendorInformationObject_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		objectBody []uint8
		expected   *VendorInformationObject
		wantErr    bool
	}{
		"EnterpriseNumberOnly": {
			objectBody: []uint8{0x00, 0x00, 0x00, 0x09},
			expected: &VendorInformationObject{
				ObjectType:       ObjectTypeVendorSpecificConstraints,
				EnterpriseNumber: EnterpriseNumberCisco,
			},
		},
		"CiscoColorSubTLV": {
			objectBody: []uint8{0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64},
			expected: &VendorInformationObject{
				ObjectType:       ObjectTypeVendorSpecificConstraints,
				EnterpriseNumber: EnterpriseNumberCisco,
				TLVs: []TLVInterface{
					&UnknownTLV{Typ: SubTLVColorCisco, Value: []uint8{0x00, 0x00, 0x00, 0x64}},
				},
			},
		},
		// The enterprise-specific type space must not be resolved against tlvMap: type 0x07 is
		// VENDOR-INFORMATION and type 0x10 is STATEFUL-PCE-CAPABILITY in the standard space.
		"SubTLVCollidingWithStandardType": {
			objectBody: []uint8{0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x00, 0x02, 0xde, 0xad, 0x00, 0x00},
			expected: &VendorInformationObject{
				ObjectType:       ObjectTypeVendorSpecificConstraints,
				EnterpriseNumber: EnterpriseNumberCisco,
				TLVs: []TLVInterface{
					&UnknownTLV{Typ: TLVVendorInformation, Value: []uint8{0xde, 0xad}},
				},
			},
		},
		// A body shorter than the mandatory Enterprise Number must be rejected, not panic.
		"EmptyBody":                 {objectBody: []uint8{}, wantErr: true},
		"TruncatedEnterpriseNumber": {objectBody: []uint8{0x00, 0x00, 0x09}, wantErr: true},
		"TruncatedSubTLV":           {objectBody: []uint8{0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x08, 0x00}, wantErr: true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := &VendorInformationObject{}
			err := got.DecodeFromBytes(ObjectTypeVendorSpecificConstraints, tt.objectBody)
			if tt.wantErr {
				assert.Error(t, err, "expected error for '%s'", name)
				return
			}
			require.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, got, "decoded value mismatch for '%s'", name)
		})
	}
}

func TestVendorInformationObject_ColorPreference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		object         *VendorInformationObject
		wantColor      uint32
		wantPreference uint32
	}{
		"NoSubTLVs": {
			object:    &VendorInformationObject{EnterpriseNumber: EnterpriseNumberCisco},
			wantColor: 0, wantPreference: 0,
		},
		"ColorAndPreference": {
			object: &VendorInformationObject{
				EnterpriseNumber: EnterpriseNumberCisco,
				TLVs: []TLVInterface{
					&UnknownTLV{Typ: SubTLVColorCisco, Value: Uint32ToByteSlice(100)},
					&UnknownTLV{Typ: SubTLVPreferenceCisco, Value: Uint32ToByteSlice(200)},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
		// Values too short to hold a uint32 must yield 0 instead of panicking.
		"ShortSubTLVValues": {
			object: &VendorInformationObject{
				EnterpriseNumber: EnterpriseNumberCisco,
				TLVs: []TLVInterface{
					&UnknownTLV{Typ: SubTLVColorCisco, Value: []uint8{}},
					&UnknownTLV{Typ: SubTLVPreferenceCisco, Value: []uint8{0x00, 0x01}},
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

func TestVendorInformationObject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]VendorInformationObject{
		"NoTLVs": {
			ObjectType:       ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: EnterpriseNumberCisco,
		},
		"CiscoColorOnly": {
			ObjectType:       ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: EnterpriseNumberCisco,
			TLVs: []TLVInterface{
				&UnknownTLV{
					Typ:   SubTLVColorCisco,
					Value: Uint32ToByteSlice(100),
				},
			},
		},
		"CiscoColorAndPreference": {
			ObjectType:       ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: EnterpriseNumberCisco,
			TLVs: []TLVInterface{
				&UnknownTLV{
					Typ:   SubTLVColorCisco,
					Value: Uint32ToByteSlice(100),
				},
				&UnknownTLV{
					Typ:   SubTLVPreferenceCisco,
					Value: Uint32ToByteSlice(200),
				},
			},
		},
		"CiscoZeroValues": {
			ObjectType:       ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: EnterpriseNumberCisco,
			TLVs: []TLVInterface{
				&UnknownTLV{
					Typ:   SubTLVColorCisco,
					Value: Uint32ToByteSlice(0),
				},
				&UnknownTLV{
					Typ:   SubTLVPreferenceCisco,
					Value: Uint32ToByteSlice(0),
				},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Equal(t, want.Len(), len(raw), "Len() must match serialized size")

			var got VendorInformationObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeVendorSpecificConstraints, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestVendorInformationObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := VendorInformationObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestVendorInformationObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	o := VendorInformationObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65531)}}}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestObjectClass_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		class ObjectClass
		want  string
	}{
		"Open":    {ObjectClassOpen, "Open (0x01)"},
		"ERO":     {ObjectClassERO, "ERO (0x07)"},
		"Unknown": {ObjectClass(0x99), "Unknown Object Class (0x99)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.class.String())
		})
	}
}

// Pin the current incorrect hex-encoding of the Stringer result.
func TestObjectClass_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		class ObjectClass
		want  string
	}{
		"Open":    {ObjectClassOpen, "Open (0x4f70656e20283078303129) [RFC5440]"},
		"Unknown": {ObjectClass(0x99), "Unknown Object Class (0x99)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.class.StringWithReference())
		})
	}
}

func TestCommonObjectHeader_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]CommonObjectHeader{
		"NoFlags":       {ObjectClass: ObjectClassOpen, ObjectType: ObjectTypeOpenOpen, ObjectLength: 8},
		"PFlagOnly":     {ObjectClass: ObjectClassOpen, ObjectType: ObjectTypeOpenOpen, PFlag: true, ObjectLength: 8},
		"IFlagOnly":     {ObjectClass: ObjectClassOpen, ObjectType: ObjectTypeOpenOpen, IFlag: true, ObjectLength: 8},
		"PFlagAndIFlag": {ObjectClass: ObjectClassOpen, ObjectType: ObjectTypeOpenOpen, PFlag: true, IFlag: true, ObjectLength: 8},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := want.Serialize()
			require.Len(t, raw, int(commonObjectHeaderLength))

			var got CommonObjectHeader
			require.NoError(t, got.DecodeFromBytes(raw))
			assert.Equal(t, want, got)
		})
	}
}

func TestCommonObjectHeader_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	var h CommonObjectHeader
	assert.Error(t, h.DecodeFromBytes([]uint8{0x01, 0x02, 0x03}))
}

func TestNewOpenObject(t *testing.T) {
	t.Parallel()

	caps := []CapabilityInterface{&SRPCECapability{MaximumSidDepth: 10}}
	o := NewOpenObject(7, 30, caps)

	want := &OpenObject{
		ObjectType: ObjectTypeOpenOpen,
		Version:    1,
		Keepalive:  30,
		Deadtime:   120, // RFC 5440 §7.3: 4 × Keepalive
		Sid:        7,
		Caps:       caps,
	}
	assert.Equal(t, want, o)
}

func TestNewOpenObject_DeadtimeClampsInsteadOfWrapping(t *testing.T) {
	t.Parallel()

	o := NewOpenObject(7, 65, nil)
	assert.Equal(t, uint8(math.MaxUint8), o.Deadtime)
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
		assert.Equal(t, tt.want, DeadTimerFor(tt.keepalive))
	}
}

func TestBandwidthObject_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		objectType ObjectType
		body       []uint8
		want       uint32
	}{
		"RequestedBandwidth": {ObjectType(1), []uint8{0x00, 0x00, 0x03, 0xe8}, 1000},
		"ZeroBandwidth":      {ObjectType(2), []uint8{0x00, 0x00, 0x00, 0x00}, 0},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o BandwidthObject
			require.NoError(t, o.DecodeFromBytes(tt.objectType, tt.body))
			assert.Equal(t, BandwidthObject{ObjectType: tt.objectType, Bandwidth: tt.want}, o)
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

			var o BandwidthObject
			assert.Error(t, o.DecodeFromBytes(ObjectType(1), body))
		})
	}
}

func TestMetricObject_Serialize(t *testing.T) {
	t.Parallel()

	o := MetricObject{ObjectType: ObjectType(1), CFlag: true, BFlag: true, MetricType: 2, MetricValue: 30}
	raw := o.Serialize()
	require.Len(t, raw, int(o.Len()))

	// RFC 5440 §7.8: Metric Value is a 32-bit IEEE floating-point number.
	want := AppendByteSlices(
		[]uint8{0x06, 0x10, 0x00, 0x0c}, // common object header: class=METRIC, type=1, length=12
		[]uint8{0x00, 0x00, 0x03, 0x02}, // reserved(2) + flags(C=1,B=1) + metric-type=2
		Uint32ToByteSlice(math.Float32bits(30)),
	)
	assert.Equal(t, want, raw)
}

func TestMetricObject_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	body := AppendByteSlices([]uint8{0x00, 0x00, 0x02, 0x02}, Uint32ToByteSlice(math.Float32bits(200)))
	var o MetricObject
	require.NoError(t, o.DecodeFromBytes(ObjectType(1), body))
	assert.Equal(t, MetricObject{ObjectType: ObjectType(1), CFlag: true, MetricType: 2, MetricValue: 200}, o)
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

			var o MetricObject
			assert.Error(t, o.DecodeFromBytes(ObjectType(1), body))
		})
	}
}

func TestMetricObject_Len(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint16(12), (&MetricObject{}).Len())
}

func TestNewMetricObject(t *testing.T) {
	t.Parallel()

	o := NewMetricObject()
	assert.Equal(t, &MetricObject{ObjectType: ObjectType(1), MetricType: 2, MetricValue: 30}, o)
}

func TestNewLSPAObject(t *testing.T) {
	t.Parallel()

	o := NewLSPAObject()
	assert.Equal(t, &LSPAObject{ObjectType: ObjectType(1), SetupPriority: 7, HoldingPriority: 7, LFlag: true}, o)
}

func TestPCEPErrorObject_DecodeFromBytes_TooShort(t *testing.T) {
	t.Parallel()

	var o PCEPErrorObject
	assert.Error(t, o.DecodeFromBytes(ObjectTypeErrorError, []uint8{0x00, 0x00, 0x01}))
}

func TestNewPCEPErrorObject(t *testing.T) {
	t.Parallel()

	tlvs := []TLVInterface{&SymbolicPathName{Name: "err"}}
	o := NewPCEPErrorObject(6, 1, tlvs)
	assert.Equal(t, &PCEPErrorObject{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1, Tlvs: tlvs}, o)
}

func TestCloseReason_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		reason CloseReason
		want   string
	}{
		"DeadTimerExpired": {CloseReasonDeadTimerExpired, "DeadTimer expired (0x02)"},
		"Unknown":          {CloseReason(0x99), "Unknown Close Reason (0x99)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.reason.String())
		})
	}
}

// Pin the current incorrect hex-encoding of the Stringer result.
func TestCloseReason_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		reason CloseReason
		want   string
	}{
		"DeadTimerExpired": {CloseReasonDeadTimerExpired, "DeadTimer expired (0x4465616454696d6572206578706972656420283078303229) [RFC5440]"},
		"Unknown":          {CloseReason(0x99), "Unknown Close Reason (0x99)"},
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

	o := NewCloseObject(CloseReasonMalformedPCEPMessage)
	assert.Equal(t, &CloseObject{ObjectType: ObjectTypeCloseClose, Reason: CloseReasonMalformedPCEPMessage}, o)
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

			var o SrpObject
			assert.Error(t, o.DecodeFromBytes(ObjectTypeSRPSRP, body))
		})
	}
}

func TestNewSrpObject(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		segs    []table.Segment
		srpID   uint32
		remove  bool
		want    *SrpObject
		wantErr bool
	}{
		"NoSegments": {
			segs: nil, srpID: 1,
			want: &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 1, TLVs: []TLVInterface{}},
		},
		"SRMPLS": {
			segs: []table.Segment{table.NewSegmentSRMPLS(16001)}, srpID: 2,
			want: &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 2, TLVs: []TLVInterface{&PathSetupType{PathSetupType: PathSetupTypeSRTE}}},
		},
		"SRv6": {
			segs: []table.Segment{table.NewSegmentSRv6(netip.MustParseAddr("fc00:0:1::"))}, srpID: 3, remove: true,
			want: &SrpObject{ObjectType: ObjectTypeSRPSRP, RFlag: true, SrpID: 3, TLVs: []TLVInterface{&PathSetupType{PathSetupType: PathSetupTypeSRv6TE}}},
		},
		"InvalidSegmentType": {
			segs: []table.Segment{fakeSegment{}}, srpID: 4, wantErr: true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := NewSrpObject(tt.segs, tt.srpID, tt.remove)
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
		object *LSPObject
		want   uint32
	}{
		"NoTLVs":    {&LSPObject{}, 0},
		"WithColor": {&LSPObject{TLVs: []TLVInterface{&Color{Color: 42}}}, 42},
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

			var o EroObject
			assert.Error(t, o.DecodeFromBytes(ObjectTypeEROExplicitRoute, body))
		})
	}
}

func TestEroObject_Len_Error(t *testing.T) {
	t.Parallel()

	badSubo := &SREroSubobject{
		SubobjectType: SubobjectTypeEROSR,
		NAIType:       NAITypeSR(0x07),
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	o := EroObject{ObjectType: ObjectTypeEROExplicitRoute, EroSubobjects: []EroSubobject{badSubo}}

	_, err := o.Len()
	assert.Error(t, err)
}

func TestEroObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	badSubo := &SREroSubobject{
		SubobjectType: SubobjectTypeEROSR,
		NAIType:       NAITypeSRIPv4Node,
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	o := EroObject{ObjectType: ObjectTypeEROExplicitRoute, EroSubobjects: []EroSubobject{badSubo}}

	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestObjectLength_Boundary(t *testing.T) {
	t.Parallel()

	length, err := objectLength(make([]uint8, 65531))
	require.NoError(t, err, "65535 total bytes must fit the Object-Length field")
	assert.Equal(t, uint16(65535), length)

	_, err = objectLength(make([]uint8, 65532))
	assert.ErrorContains(t, err, "exceeds", "65536 total bytes must be rejected")
}

func TestEroObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	newSubobjects := func(n int) []EroSubobject {
		subobjects := make([]EroSubobject, n)
		for i := range subobjects {
			subobjects[i] = &SREroSubobject{
				SubobjectType: SubobjectTypeEROSR,
				NAIType:       NAITypeSRAbsent,
				Segment:       table.NewSegmentSRMPLS(16001),
			}
		}
		return subobjects
	}

	t.Run("AtObjectLengthLimit", func(t *testing.T) {
		t.Parallel()

		ero := &EroObject{ObjectType: ObjectTypeEROExplicitRoute, EroSubobjects: newSubobjects(8191)}
		raw, err := ero.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, 65532)

		var header CommonObjectHeader
		require.NoError(t, header.DecodeFromBytes(raw))
		assert.Equal(t, uint16(65532), header.ObjectLength)
	})

	t.Run("ExceedsObjectLengthLimit", func(t *testing.T) {
		t.Parallel()

		ero := &EroObject{ObjectType: ObjectTypeEROExplicitRoute, EroSubobjects: newSubobjects(8192)}
		_, err := ero.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

func TestNewEroObject_InvalidSegment(t *testing.T) {
	t.Parallel()

	_, err := NewEroObject([]table.Segment{fakeSegment{}})
	assert.Error(t, err)
}

func TestNewEroSubobject(t *testing.T) {
	t.Parallel()

	t.Run("SRMPLSError", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRMPLS(16001)
		seg.LocalAddr = netip.MustParseAddr("10.0.0.1")
		seg.RemoteAddr = netip.MustParseAddr("2001:db8::1") // mismatched address families
		_, err := NewEroSubobject(seg)
		assert.Error(t, err)
	})

	t.Run("SRv6", func(t *testing.T) {
		t.Parallel()

		seg := table.NewSegmentSRv6(netip.MustParseAddr("fc00:0:1::"))
		subo, err := NewEroSubobject(seg)
		require.NoError(t, err)
		assert.IsType(t, &SRv6EroSubobject{}, subo)
	})

	t.Run("InvalidType", func(t *testing.T) {
		t.Parallel()

		_, err := NewEroSubobject(fakeSegment{})
		assert.Error(t, err)
	})

	t.Run("SRv6LinkLocalError", func(t *testing.T) {
		t.Parallel()

		seg := table.SegmentSRv6{
			Sid:        netip.MustParseAddr("fc00:0:1::"),
			LocalAddr:  netip.MustParseAddr("fe80::1"),
			RemoteAddr: netip.MustParseAddr("fe80::2"),
		}
		_, err := NewEroSubobject(seg)
		assert.Error(t, err)
	})
}

func TestEroObject_ToSegmentList(t *testing.T) {
	t.Parallel()

	srMPLSSubo, err := NewSREroSubobject(table.NewSegmentSRMPLS(16001))
	require.NoError(t, err)
	rsvpSubo, err := NewRSVPIPv4PrefixEroSubobject(netip.MustParseAddr("10.0.0.1"), 32)
	require.NoError(t, err)

	o := EroObject{
		ObjectType:    ObjectTypeEROExplicitRoute,
		EroSubobjects: []EroSubobject{srMPLSSubo, rsvpSubo},
	}

	assert.Equal(t, []table.Segment{table.NewSegmentSRMPLS(16001)}, o.ToSegmentList())
}

func TestNAITypeSR_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		nt   NAITypeSR
		want string
	}{
		"IPv4Node": {NAITypeSRIPv4Node, "NAI is an IPv4 node ID (0x01)"},
		"Unknown":  {NAITypeSR(0x07), "Unknown NAI Type (0x07)"},
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
		nt   NAITypeSR
		want string
	}{
		"IPv4Node": {NAITypeSRIPv4Node, "NAI is an IPv4 node ID (0x01) [RFC8664]"},
		"Unknown":  {NAITypeSR(0x07), "Unknown NAI Type (0x07)"},
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
	subo := &SREroSubobject{Segment: seg}
	assert.Equal(t, seg, subo.ToSegment())
}

func TestNAITypeSRv6_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		nt   NAITypeSRv6
		want string
	}{
		"IPv6Node": {NAITypeSRv6IPv6Node, "NAI is an IPv6 node ID (0x02)"},
		"Unknown":  {NAITypeSRv6(0x01), "Unknown NAI Type (0x01)"},
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
		nt   NAITypeSRv6
		want string
	}{
		"IPv6Node": {NAITypeSRv6IPv6Node, "NAI is an IPv6 node ID (0x02) [RFC9603]"},
		"Unknown":  {NAITypeSRv6(0x01), "Unknown NAI Type (0x01)"},
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
	subo := &SRv6EroSubobject{Segment: seg}
	assert.Equal(t, seg, subo.ToSegment())
}

func TestSRv6EroSubobject_Len_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string]*SRv6EroSubobject{
		// RFC9603 §4.3.1: when NAI Type is 0 (absent), F MUST be 1.
		"AbsentNAIWithoutFFlag": {NAIType: NAITypeSRv6Absent, FFlag: false},
		"UnsupportedNAIType":    {NAIType: NAITypeSRv6(0x01), FFlag: false},
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

	o := &SRv6EroSubobject{
		SubobjectType: SubobjectTypeEROSRv6,
		NAIType:       NAITypeSRv6Absent,
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

	o := EndpointsObject{SrcAddr: netip.MustParseAddr("10.0.0.1"), DstAddr: netip.MustParseAddr("2001:db8::1")}
	_, err := o.Len()
	assert.Error(t, err)
}

func TestEndpointsObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := EndpointsObject{SrcAddr: netip.MustParseAddr("10.0.0.1"), DstAddr: netip.MustParseAddr("2001:db8::1")}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestNewEndpointsObject(t *testing.T) {
	t.Parallel()

	v4a, v4b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	v6a, v6b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")

	cases := map[string]struct {
		dst, src netip.Addr
		wantType ObjectType
		wantLen  uint16
		wantErr  bool
	}{
		"IPv4":       {v4b, v4a, ObjectTypeEndpointIPv4, commonObjectHeaderLength + 4 + 4, false},
		"IPv6":       {v6b, v6a, ObjectTypeEndpointIPv6, commonObjectHeaderLength + 16 + 16, false},
		"Mismatched": {v6b, v4a, 0, 0, true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o, err := NewEndpointsObject(tt.dst, tt.src)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, &EndpointsObject{ObjectType: tt.wantType, DstAddr: tt.dst, SrcAddr: tt.src}, o)

			l, err := o.Len()
			require.NoError(t, err)
			assert.Equal(t, tt.wantLen, l)
		})
	}
}

func TestDeterminePccType(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		caps []CapabilityInterface
		want PccType
	}{
		"NoCaps":          {nil, RFCCompliant},
		"NoAssocTypeList": {[]CapabilityInterface{&SRPCECapability{}}, RFCCompliant},
		"CiscoAssocType": {
			[]CapabilityInterface{&AssocTypeList{AssocTypes: []AssocType{AssociationTypeSRPolicyAssociationCisco}}},
			CiscoLegacy,
		},
		"JuniperAssocType": {
			[]CapabilityInterface{&AssocTypeList{AssocTypes: []AssocType{AssociationTypeSRPolicyAssociationJuniper}}},
			JuniperLegacy,
		},
		"JuniperWinsOverCisco": {
			[]CapabilityInterface{&AssocTypeList{AssocTypes: []AssocType{
				AssociationTypeSRPolicyAssociationCisco, AssociationTypeSRPolicyAssociationJuniper,
			}}},
			JuniperLegacy,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, DeterminePccType(tt.caps))
		})
	}
}

func TestAssociationObject_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	v4Body := []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0xc0, 0x00, 0x02, 0x01}
	v6Body := AppendByteSlices(
		make([]uint8, 4),
		Uint16ToByteSlice(uint16(AssociationTypeSRPolicyAssociation)),
		Uint16ToByteSlice(uint16(1)),
		netip.MustParseAddr("2001:db8::1").AsSlice(),
	)

	cases := map[string]struct {
		objectType ObjectType
		body       []uint8
	}{
		"UnknownObjectType": {ObjectType(99), v4Body},
		"MalformedIPv4TLV":  {ObjectTypeAssociationIPv4, AppendByteSlices(v4Body, []uint8{0x00, 0x27, 0x00, 0xff})},
		"MalformedIPv6TLV":  {ObjectTypeAssociationIPv6, AppendByteSlices(v6Body, []uint8{0x00, 0x27, 0x00, 0xff})},
		"EmptyBody":         {ObjectTypeAssociationIPv4, []uint8{}},
		"PartialCommonBody": {ObjectTypeAssociationIPv4, make([]uint8, 7)},
		"PartialIPv4Body":   {ObjectTypeAssociationIPv4, make([]uint8, 11)},
		"PartialIPv6Body":   {ObjectTypeAssociationIPv6, make([]uint8, 23)},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o AssociationObject
			assert.Error(t, o.DecodeFromBytes(tt.objectType, tt.body))
		})
	}
}

func TestAssociationObject_Len_Error(t *testing.T) {
	t.Parallel()

	o := AssociationObject{}
	_, err := o.Len()
	assert.Error(t, err)
}

func TestAssociationObject_Serialize_Error(t *testing.T) {
	t.Parallel()

	o := AssociationObject{}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestAssociationObject_Serialize_TLVError(t *testing.T) {
	t.Parallel()

	o := AssociationObject{
		AssocSrc: netip.MustParseAddr("192.0.2.1"),
		TLVs:     []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}},
	}
	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestAssociationObject_Serialize_ObjectLengthBoundary(t *testing.T) {
	t.Parallel()

	o := AssociationObject{
		AssocSrc: netip.MustParseAddr("192.0.2.1"),
		TLVs:     []TLVInterface{&UnknownTLV{Value: make([]byte, 65531)}},
	}
	_, err := o.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestNewAssociationObject_MismatchedFamilies(t *testing.T) {
	t.Parallel()

	_, err := NewAssociationObject(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), 100, 200)
	assert.Error(t, err)
}

func TestNewAssociationObject_ObjectType(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		srcAddr netip.Addr
		dstAddr netip.Addr
		want    ObjectType
	}{
		"IPv4": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), ObjectTypeAssociationIPv4},
		"IPv6": {netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), ObjectTypeAssociationIPv6},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o, err := NewAssociationObject(tt.srcAddr, tt.dstAddr, 100, 200)
			require.NoError(t, err)
			assert.Equal(t, tt.want, o.ObjectType)
		})
	}
}

func TestAssociationObject_Endpoint(t *testing.T) {
	t.Parallel()

	dstAddr := netip.MustParseAddr("192.0.2.2")

	cases := map[string]struct {
		object *AssociationObject
		want   netip.Addr
	}{
		"NoMatch": {&AssociationObject{}, netip.Addr{}},
		"ExtendedAssociationID": {
			&AssociationObject{TLVs: []TLVInterface{&ExtendedAssociationID{Endpoint: dstAddr}}},
			dstAddr,
		},
		"JuniperTLV": {
			&AssociationObject{TLVs: []TLVInterface{
				&ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: ExtendedAssociationID{Endpoint: dstAddr}},
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
		"MalformedTLV": AppendByteSlices(
			make([]uint8, 4),
			[]uint8{0x00, 0x27, 0x00, 0xff}, // TLV length exceeds available data
		),
		"Empty":       {},
		"PartialBody": {0x00, 0x00, 0x00},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o LSPObject
			assert.Error(t, o.DecodeFromBytes(ObjectTypeLSPLSP, body))
		})
	}
}

func TestLSPObject_Serialize_MasksPlspIDAndOFlag(t *testing.T) {
	t.Parallel()

	o := &LSPObject{
		ObjectType: ObjectTypeLSPLSP,
		PlspID:     0x1FFFFF,
		OFlag:      0x0F,
		CFlag:      false,
		TLVs:       []TLVInterface{},
	}

	raw, err := o.Serialize()
	require.NoError(t, err)
	body := raw[commonObjectHeaderLength:]
	require.Len(t, body, 4)
	assert.False(t, body[3]&0x80 != 0, "PLSP-ID/OFlag overflow must not set the C flag")

	var got LSPObject
	require.NoError(t, got.DecodeFromBytes(o.ObjectType, body))
	assert.Equal(t, o.PlspID&0xFFFFF, got.PlspID)
	assert.Equal(t, o.OFlag&0x07, got.OFlag)
	assert.False(t, got.CFlag)
}

func TestEroObject_Serialize_LenError(t *testing.T) {
	t.Parallel()

	badSubo := &SREroSubobject{
		SubobjectType: SubobjectTypeEROSR,
		NAIType:       NAITypeSRUnnumberedAdjacency,
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	o := EroObject{ObjectType: ObjectTypeEROExplicitRoute, EroSubobjects: []EroSubobject{badSubo}}

	_, err := o.Serialize()
	assert.Error(t, err)
}

// RFC 9603 §4.3.1: NAI Type 0 requires F=1.
func TestEroObject_Serialize_LenError_SRv6AbsentNAI(t *testing.T) {
	t.Parallel()

	badSubo := &SRv6EroSubobject{
		SubobjectType: SubobjectTypeEROSRv6,
		NAIType:       NAITypeSRv6Absent,
		FFlag:         false,
		Segment:       table.SegmentSRv6{Sid: netip.MustParseAddr("fc00:0:1::")},
	}
	o := EroObject{ObjectType: ObjectTypeEROExplicitRoute, EroSubobjects: []EroSubobject{badSubo}}

	_, err := o.Serialize()
	assert.Error(t, err)
}

func TestSRv6EroSubobject_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	nodeType := uint8(NAITypeSRv6IPv6Node) << 4
	adjGlobalType := uint8(NAITypeSRv6IPv6AdjacencyGlobal) << 4
	adjLinkLocalType := uint8(NAITypeSRv6IPv6AdjacencyLinkLocal) << 4

	cases := map[string][]uint8{
		"TooShort":     {0x28, 0x00, 0x00},
		"TruncatedSID": AppendByteSlices([]uint8{0x28, 0x00, 0x00, 0x00}, make([]uint8, 4)),
		"TruncatedNodeNAI": AppendByteSlices(
			[]uint8{0x28, 0x00, nodeType, 0x00}, make([]uint8, 4+16),
		),
		"TruncatedAdjGlobalNAI": AppendByteSlices(
			[]uint8{0x28, 0x00, adjGlobalType, 0x00}, make([]uint8, 4+16+16),
		),
		"TruncatedAdjLinkLocalNAI": AppendByteSlices(
			[]uint8{0x28, 0x00, adjLinkLocalType, 0x00}, make([]uint8, 4+16+16),
		),
		// TFlag requires an additional 4-byte SID-Structure field.
		"TruncatedSIDStructure": AppendByteSlices(
			[]uint8{0x28, 0x00, 0x00, 0x04}, make([]uint8, 4+16),
		),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var o SRv6EroSubobject
			assert.Error(t, o.DecodeFromBytes(raw))
		})
	}
}

func TestSRv6EroSubobject_DecodeFromBytes_SIDStructureOverflow(t *testing.T) {
	t.Parallel()

	raw := AppendByteSlices(
		[]uint8{0x28, 0x00, 0x00, 0x06}, // NAIType=Absent, T=1, F=1
		make([]uint8, 4),                // reserved + behavior
		netip.MustParseAddr("fc00:0:1::").AsSlice(),
		[]uint8{200, 200, 200, 200}, // sum exceeds 128 bits
		make([]uint8, 4),
	)

	var o SRv6EroSubobject
	assert.Error(t, o.DecodeFromBytes(raw))
}

func TestSRv6EroSubobject_DecodeFromBytes_BothSIDAndNAIAbsent(t *testing.T) {
	t.Parallel()

	raw := []uint8{0x28, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00}

	var o SRv6EroSubobject
	assert.Error(t, o.DecodeFromBytes(raw))
}

func TestSRv6EroSubobject_DecodeFromBytes_LinkLocalAdjacency(t *testing.T) {
	t.Parallel()

	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")

	raw := AppendByteSlices(
		[]uint8{0x28, 8 + 16 + 40, uint8(NAITypeSRv6IPv6AdjacencyLinkLocal) << 4, 0x00},
		make([]uint8, 4),
		netip.MustParseAddr("fc00:0:1::").AsSlice(),
		local.AsSlice(), make([]uint8, 4),
		remote.AsSlice(), make([]uint8, 4),
	)

	var o SRv6EroSubobject
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
		var o SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated SID")
	})

	t.Run("NodeNAICutShort", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x28, 10, uint8(NAITypeSRv6IPv6Node) << 4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		var o SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated NAI (Node)")
	})

	t.Run("AdjGlobalNAICutShort", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x28, 10, uint8(NAITypeSRv6IPv6AdjacencyGlobal) << 4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		var o SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated NAI (AdjGlobal)")
	})

	t.Run("AdjLinkLocalNAICutShort", func(t *testing.T) {
		t.Parallel()

		raw := []uint8{0x28, 10, uint8(NAITypeSRv6IPv6AdjacencyLinkLocal) << 4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		var o SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated NAI (AdjLinkLocal)")
	})

	t.Run("SIDStructureCutShort", func(t *testing.T) {
		t.Parallel()

		raw := AppendByteSlices(
			[]uint8{0x28, 26, 0x00, 0x06},
			make([]uint8, 4),
			netip.MustParseAddr("fc00:0:1::").AsSlice(),
			make([]uint8, 2),
		)
		var o SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: truncated SID-Structure")
	})

	t.Run("SIDStructureInvalidSum", func(t *testing.T) {
		t.Parallel()

		// The SID-Structure field is complete, but its four lengths sum to 800 bits.
		raw := AppendByteSlices(
			[]uint8{0x28, 32, 0x00, 0x06},
			make([]uint8, 4),
			netip.MustParseAddr("fc00:0:1::").AsSlice(),
			[]uint8{200, 200, 200, 200},
			make([]uint8, 4),
		)
		var o SRv6EroSubobject
		assert.ErrorContains(t, o.DecodeFromBytes(raw), "exceeds")
	})

	t.Run("TrailingByteAfterNAI", func(t *testing.T) {
		t.Parallel()

		raw := AppendByteSlices(
			[]uint8{0x28, 25, uint8(NAITypeSRv6IPv6Node) << 4, 0x01},
			make([]uint8, 4),
			netip.MustParseAddr("2001:db8::1").AsSlice(),
			make([]uint8, 1),
		)
		var o SRv6EroSubobject
		assert.EqualError(t, o.DecodeFromBytes(raw), "SRv6EroSubobject: declared length does not match V/T/F/S flags")
	})
}

func TestNewSRv6EroSubobject_NAIFromSegment(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")

	cases := map[string]struct {
		seg         table.SegmentSRv6
		wantNAIType NAITypeSRv6
		wantFFlag   bool
		wantTFlag   bool
	}{
		"NoAddr": {
			seg: table.SegmentSRv6{Sid: sid}, wantNAIType: NAITypeSRv6Absent, wantFFlag: true,
		},
		"LocalOnly": {
			seg: table.SegmentSRv6{Sid: sid, LocalAddr: local}, wantNAIType: NAITypeSRv6IPv6Node,
		},
		"LocalAndRemote": {
			seg:         table.SegmentSRv6{Sid: sid, LocalAddr: local, RemoteAddr: remote},
			wantNAIType: NAITypeSRv6IPv6AdjacencyGlobal,
		},
		"WithStructure": {
			seg:         table.SegmentSRv6{Sid: sid, LocalAddr: local, Structure: []uint8{32, 16, 16, 0}},
			wantNAIType: NAITypeSRv6IPv6Node, wantTFlag: true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			subo, err := NewSRv6EroSubobject(tt.seg)
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
			Sid: sid, LocalAddr: netip.MustParseAddr("2001:db8::1"), RemoteAddr: netip.MustParseAddr("fe80::2"),
		},
	}

	for name, seg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewSRv6EroSubobject(seg)
			assert.Error(t, err)
		})
	}
}

func TestNewSRv6EroSubobject_AddressFamilyRejected(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")

	cases := map[string]table.SegmentSRv6{
		"IPv4LocalAddr": {
			Sid: sid, LocalAddr: netip.MustParseAddr("10.0.0.1"),
		},
		"IPv4RemoteAddr": {
			Sid: sid, LocalAddr: netip.MustParseAddr("2001:db8::1"), RemoteAddr: netip.MustParseAddr("10.0.0.2"),
		},
		"RemoteAddrWithoutLocalAddr": {
			Sid: sid, RemoteAddr: netip.MustParseAddr("2001:db8::2"),
		},
	}

	for name, seg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewSRv6EroSubobject(seg)
			assert.Error(t, err)
		})
	}
}

func TestNewSRv6EroSubobject_StructureValidation(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")
	local := netip.MustParseAddr("2001:db8::1")

	t.Run("EmptyStructureIsAbsent", func(t *testing.T) {
		t.Parallel()

		subo, err := NewSRv6EroSubobject(table.SegmentSRv6{Sid: sid, LocalAddr: local, Structure: []uint8{}})
		require.NoError(t, err)
		assert.False(t, subo.TFlag)
	})

	t.Run("InvalidLengthRejected", func(t *testing.T) {
		t.Parallel()

		_, err := NewSRv6EroSubobject(table.SegmentSRv6{Sid: sid, LocalAddr: local, Structure: []uint8{32, 16, 16}})
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

			var o RSVPIPv4PrefixEroSubobject
			assert.Error(t, o.DecodeFromBytes(raw))
		})
	}
}

func TestRSVPIPv4PrefixEroSubobject_Serialize_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string]*RSVPIPv4PrefixEroSubobject{
		"NotIPv4":             {Address: netip.MustParseAddr("2001:db8::1")},
		"InvalidPrefixLength": {Address: netip.MustParseAddr("10.0.0.1"), PrefixLen: 33},
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
		"NotIPv4":             {netip.MustParseAddr("2001:db8::1"), 32},
		"InvalidPrefixLength": {netip.MustParseAddr("10.0.0.1"), 33},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewRSVPIPv4PrefixEroSubobject(tt.address, tt.prefixLen)
			assert.Error(t, err)
		})
	}
}
