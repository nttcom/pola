// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

func TestSREroSubobject_RoundTrip(t *testing.T) {
	t.Parallel()

	mkSRMPLS := func(sid uint32, tc uint8, s bool, ttl uint8) table.SegmentSRMPLS {
		seg := table.NewSegmentSRMPLS(sid)
		seg.TC, seg.S, seg.TTL = tc, s, ttl
		return seg
	}

	cases := map[string]SREroSubobject{
		"NAIAbsent_LabelOnly": {
			SubobjectType: SubObjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			FFlag:         true, MFlag: true,
			Segment: table.NewSegmentSRMPLS(16000),
		},
		"NAIAbsent_LFlag": {
			LFlag:         true,
			SubobjectType: SubObjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			FFlag:         true, MFlag: true,
			Segment: table.NewSegmentSRMPLS(24),
		},
		"NAIAbsent_CFlag_MPLSStackAttrs": {
			SubobjectType: SubObjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			FFlag:         true, CFlag: true, MFlag: true,
			Segment: mkSRMPLS(100500, 5, true, 64),
		},
		"IPv4Node": {
			SubobjectType: SubObjectTypeEROSR,
			NAIType:       NAITypeSRIPv4Node,
			MFlag:         true,
			Segment:       table.NewSegmentSRMPLS(16001),
			NAI:           netip.MustParseAddr("10.0.0.1"),
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

func TestSRv6EroSubobject_RoundTrip(t *testing.T) {
	t.Parallel()

	sid := netip.MustParseAddr("fc00:0:1::")
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")

	cases := map[string]SRv6EroSubobject{
		"IPv6Node_END": {
			SubobjectType: SubObjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6Node,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local},
		},
		"IPv6AdjGlobal_ENDX": {
			SubobjectType: SubObjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6AdjacencyGlobal,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local, RemoteAddr: remote},
		},
		"IPv6Node_USid_WithStructure": {
			SubobjectType: SubObjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6Node,
			TFlag:         true,
			Segment: table.SegmentSRv6{
				Sid: sid, LocalAddr: local, USid: true,
				Structure: []uint8{32, 16, 16, 0},
			},
		},
		"LFlag_IPv6Node": {
			LFlag:         true,
			SubobjectType: SubObjectTypeEROSRv6,
			NAIType:       NAITypeSRv6IPv6Node,
			Segment:       table.SegmentSRv6{Sid: sid, LocalAddr: local},
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

			raw := want.Serialize()
			require.Equal(t, int(want.Len()), len(raw), "Len() must match serialized size")

			// DecodeFromBytes expects the object body (without 4-byte CommonObjectHeader).
			var got SrpObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeSRPSRP, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
		})
	}
}
