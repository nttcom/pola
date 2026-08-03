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
		"ShorterThanHeaderAndSID": {0x24, 0x08, 0x00, 0x08, 0x00, 0x00},
		"TruncatedIPv4NodeNAI":    {0x24, 0x0c, 0x10, 0x01, 0x03, 0xe8, 0x10, 0x00, 0x0a, 0x00},
		"UnsupportedNAIType":      {0x24, 0x08, 0x50, 0x01, 0x03, 0xe8, 0x10, 0x00},
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var subo SREroSubobject
			assert.Error(t, subo.DecodeFromBytes(raw))
		})
	}
}

// The NAI must never be silently dropped: emitting a body that is shorter than
// the advertised Length would corrupt every following ERO subobject.
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

	// An NAI type this implementation cannot encode must not yield a length either.
	_, err := cases["UnsupportedNAIType"].Len()
	assert.Error(t, err)
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

			raw := want.Serialize()
			require.Equal(t, int(want.Len()), len(raw), "Len() must match serialized size")

			var got OpenObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeOpenOpen, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
		})
	}
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

			raw := want.Serialize()
			require.Equal(t, int(want.Len()), len(raw), "Len() must match serialized size")

			var got PCEPErrorObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeErrorError, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
		})
	}
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
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeCloseClose, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
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

			raw := want.Serialize()
			require.Equal(t, int(want.Len()), len(raw), "Len() must match serialized size")

			var got LSPObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeLSPLSP, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
		})
	}
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
					&UndefinedTLV{Typ: SubTLVColorCisco, Length: 4, Value: []uint8{0x00, 0x00, 0x00, 0x64}},
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
					&UndefinedTLV{Typ: TLVVendorInformation, Length: 2, Value: []uint8{0xde, 0xad}},
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
					&UndefinedTLV{Typ: SubTLVColorCisco, Length: 4, Value: Uint32ToByteSlice(100)},
					&UndefinedTLV{Typ: SubTLVPreferenceCisco, Length: 4, Value: Uint32ToByteSlice(200)},
				},
			},
			wantColor: 100, wantPreference: 200,
		},
		// Values too short to hold a uint32 must yield 0 instead of panicking.
		"ShortSubTLVValues": {
			object: &VendorInformationObject{
				EnterpriseNumber: EnterpriseNumberCisco,
				TLVs: []TLVInterface{
					&UndefinedTLV{Typ: SubTLVColorCisco, Length: 0, Value: []uint8{}},
					&UndefinedTLV{Typ: SubTLVPreferenceCisco, Length: 2, Value: []uint8{0x00, 0x01}},
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
				&UndefinedTLV{
					Typ:    SubTLVColorCisco,
					Length: SubTLVColorCiscoValueLength,
					Value:  Uint32ToByteSlice(100),
				},
			},
		},
		"CiscoColorAndPreference": {
			ObjectType:       ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: EnterpriseNumberCisco,
			TLVs: []TLVInterface{
				&UndefinedTLV{
					Typ:    SubTLVColorCisco,
					Length: SubTLVColorCiscoValueLength,
					Value:  Uint32ToByteSlice(100),
				},
				&UndefinedTLV{
					Typ:    SubTLVPreferenceCisco,
					Length: SubTLVPreferenceCiscoValueLength,
					Value:  Uint32ToByteSlice(200),
				},
			},
		},
		"CiscoZeroValues": {
			ObjectType:       ObjectTypeVendorSpecificConstraints,
			EnterpriseNumber: EnterpriseNumberCisco,
			TLVs: []TLVInterface{
				&UndefinedTLV{
					Typ:    SubTLVColorCisco,
					Length: SubTLVColorCiscoValueLength,
					Value:  Uint32ToByteSlice(0),
				},
				&UndefinedTLV{
					Typ:    SubTLVPreferenceCisco,
					Length: SubTLVPreferenceCiscoValueLength,
					Value:  Uint32ToByteSlice(0),
				},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := want.Serialize()
			require.Equal(t, int(want.Len()), len(raw), "Len() must match serialized size")

			var got VendorInformationObject
			require.NoError(t,
				got.DecodeFromBytes(ObjectTypeVendorSpecificConstraints, raw[commonObjectHeaderLength:]),
				"DecodeFromBytes failed",
			)
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
		})
	}
}
