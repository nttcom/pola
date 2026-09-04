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

const (
	testIPv4Addr1  = "10.0.0.1"
	testIPv4Addr2  = "10.0.0.2"
	testIPv6Addr1  = "2001:db8::1"
	testIPv6Addr2  = "2001:db8::2"
	testPolicyName = "policy1"
)

func runTLVLenTests(t *testing.T, cases map[string]struct {
	input    TLVInterface
	expected uint16
},
) {
	t.Helper()

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Helper()
			t.Parallel()

			actual := tt.input.Len()
			assert.Equal(t, int(tt.expected), actual, "length mismatch for '%s'", name)
		})
	}
}

var (
	testPathSetupTypeCapabilityBasic = &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeRSVPTE, PathSetupTypeSRTE},
		SubTLVs:        []TLVInterface{},
	}
	testPathSetupTypeCapabilityWithSubTLV = &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeSRTE},
		SubTLVs:        []TLVInterface{NewSRPCECapability(true, true, 10)},
	}
)

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
			require.Len(t, raw, want.Len(), "Len() must match serialized size")

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
			require.Len(t, raw, want.Len(), "Len() must match serialized size")

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
			require.Len(t, raw, int(want.Len()), "Len() must match serialized size")

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

func TestErrorObject_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]ErrorObject{
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
			require.Len(t, raw, want.Len(), "Len() must match serialized size")

			var got ErrorObject
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
			require.Len(t, raw, int(want.Len()), "Len() must match serialized size")

			var got CloseObject
			require.NoError(t, got.DecodeFromBytes(ObjectTypeCloseClose, raw[commonObjectHeaderLength:]))
			assert.Equal(t, want, got, "round-trip value mismatch")

			assert.Equal(t, raw, got.Serialize(), "re-serialized bytes differ")
		})
	}
}

func TestLSPObject_RoundTrip(t *testing.T) {
	t.Parallel()

	v4Src := netip.MustParseAddr(testIPv4Addr1)
	v4Dst := netip.MustParseAddr(testIPv4Addr2)
	v6Src := netip.MustParseAddr(testIPv6Addr1)
	v6Dst := netip.MustParseAddr(testIPv6Addr2)

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
			require.Len(t, raw, want.Len(), "Len() must match serialized size")

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
				mkSRv6Ero("fc00:0:1::", testIPv6Addr1),
			},
		},
		"SingleRSVPIPv4Prefix": {
			ObjectType: ObjectTypeEROExplicitRoute,
			EroSubobjects: []EroSubobject{
				mkRSVPIPv4PrefixEro(testIPv4Addr1, 32),
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
			require.Len(t, raw, l, "Len() must match serialized size")

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
	v6 := netip.MustParseAddr(testIPv6Addr1)
	v6Endpoint := netip.MustParseAddr(testIPv6Addr2)

	cases := map[string]AssociationObject{
		"IPv4_NoTLVs": {
			ObjectType: ObjectTypeAssociationIPv4,
			AssocType:  AssocTypeSRPolicyAssociation,
			AssocID:    1,
			AssocSrc:   v4,
		},
		"IPv4_RFlag": {
			ObjectType: ObjectTypeAssociationIPv4,
			RFlag:      true,
			AssocType:  AssocTypeSRPolicyAssociation,
			AssocID:    1,
			AssocSrc:   v4,
		},
		"IPv4_WithSRPolicyTLVs": {
			ObjectType: ObjectTypeAssociationIPv4,
			AssocType:  AssocTypeSRPolicyAssociation,
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
			AssocType:  AssocTypeSRPolicyAssociation,
			AssocID:    1,
			AssocSrc:   v6,
		},
		"IPv6_WithExtendedAssociationID": {
			ObjectType: ObjectTypeAssociationIPv6,
			AssocType:  AssocTypeSRPolicyAssociation,
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
			require.Len(t, raw, l, "Len() must match serialized size")

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
		// Enterprise-specific types must not be resolved against the standard TLV type map.
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
		// A body shorter than the mandatory Enterprise Number must return an error.
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
			require.Len(t, raw, want.Len(), "Len() must match serialized size")

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

func TestObjectLength_Boundary(t *testing.T) {
	t.Parallel()

	length, err := objectLength(make([]uint8, 65531))
	require.NoError(t, err, "65535 total bytes must fit the Object-Length field")
	assert.Equal(t, uint16(65535), length)

	_, err = objectLength(make([]uint8, 65532))
	assert.ErrorContains(t, err, "exceeds", "65536 total bytes must be rejected")
}

func TestNewEndpointsObject(t *testing.T) {
	t.Parallel()

	v4a, v4b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	v6a, v6b := netip.MustParseAddr(testIPv6Addr1), netip.MustParseAddr(testIPv6Addr2)

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
	assert.Zero(t, body[3]&0x80, "PLSP-ID/OFlag overflow must not set the C flag")

	var got LSPObject
	require.NoError(t, got.DecodeFromBytes(o.ObjectType, body))
	assert.Equal(t, o.PlspID&0xFFFFF, got.PlspID)
	assert.Equal(t, o.OFlag&0x07, got.OFlag)
	assert.False(t, got.CFlag)
}

func TestTLVType_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		tlvType  TLVType
		expected string
	}{
		"StatefulPCECapability": {TLVStatefulPCECapability, "STATEFUL-PCE-CAPABILITY (0x0010) [RFC8231]"},
		"MultipathCap":          {TLVMultipathCap, "MULTIPATH-CAP (0x003c) [draft-ietf-pce-multipath-07]"},
		"JuniperCPathID":        {TLVSRPolicyCPathIDJuniper, "SRPOLICY-CPATH-ID (Juniper) (0xffe4) [not IANA-assigned]"},
		"UnknownType":           {TLVType(0xdead), "Unknown TLV (0xdead)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.tlvType.StringWithReference(), "unexpected TLVType.StringWithReference() result")
		})
	}
}

func TestTLVType_NameAndReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		tlvType      TLVType
		expectedName string
		expectedRef  Reference
	}{
		"StatefulPCECapability": {TLVStatefulPCECapability, "STATEFUL-PCE-CAPABILITY", rfc(8231)},
		"MultipathCap":          {TLVMultipathCap, "MULTIPATH-CAP", refDraftPCEMultipath},
		"JuniperCPathID":        {TLVSRPolicyCPathIDJuniper, "SRPOLICY-CPATH-ID (Juniper)", refNotIANAAssigned},
		"UnknownType":           {TLVType(0xdead), "", Reference{}},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expectedName, tt.tlvType.Name(), "unexpected TLVType.Name() result")
			assert.Equal(t, tt.expectedRef, tt.tlvType.Reference(), "unexpected TLVType.Reference() result")
		})
	}
}

func TestTLVMap(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		tlvType  TLVType
		expected TLVInterface
	}{
		"VendorInformation":       {TLVVendorInformation, &VendorInformation{}},
		"StatefulPCECapability":   {TLVStatefulPCECapability, &StatefulPCECapability{}},
		"SymbolicPathName":        {TLVSymbolicPathName, &SymbolicPathName{}},
		"IPv4LSPIdentifiers":      {TLVIPv4LSPIdentifiers, &IPv4LSPIdentifiers{}},
		"IPv6LSPIdentifiers":      {TLVIPv6LSPIdentifiers, &IPv6LSPIdentifiers{}},
		"LSPDBVersion":            {TLVLSPDBVersion, &LSPDBVersion{}},
		"SRPCECapability":         {TLVSRPCECapability, &SRPCECapability{}},
		"SRv6PCECapability":       {TLVSRv6PCECapability, &SRv6PCECapability{}},
		"MultipathCapability":     {TLVMultipathCap, &MultipathCapability{}},
		"PathSetupType":           {TLVPathSetupType, &PathSetupType{}},
		"ExtendedAssociationID":   {TLVExtendedAssociationID, &ExtendedAssociationID{}},
		"PathSetupTypeCapability": {TLVPathSetupTypeCapability, &PathSetupTypeCapability{}},
		"AssocTypeList":           {TLVAssocTypeList, &AssocTypeList{}},
		"SRPolicyCPathID":         {TLVSRPolicyCPathID, &SRPolicyCandidatePathIdentifier{}},
		"SRPolicyCPathPreference": {TLVSRPolicyCPathPreference, &SRPolicyCandidatePathPreference{}},
		"Color":                   {TLVColor, &Color{}},

		"ExtendedAssociationIDIPv4Juniper": {TLVExtendedAssociationIDIPv4Juniper, &ExtendedAssociationIDIPv4Juniper{}},
		"SRPolicyCPathIDJuniper":           {TLVSRPolicyCPathIDJuniper, &SRPolicyCandidatePathIdentifierJuniper{}},
		"SRPolicyCPathPreferenceJuniper":   {TLVSRPolicyCPathPreferenceJuniper, &SRPolicyCandidatePathPreferenceJuniper{}},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			constructor, ok := tlvMap[tt.tlvType]
			require.True(t, ok, "constructor not found for TLVType '%s'", name)

			actual := constructor()
			assert.IsType(t, tt.expected, actual, "unexpected type for TLV '%s'", name)
		})
	}
}

func TestPathSetupTypeCapability_pstCount(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		numPST   int
		expected int
	}{
		"BelowMax": {numPST: 10, expected: 10},
		"AtMax":    {numPST: MaxPathSetupTypes, expected: MaxPathSetupTypes},
		"AboveMax": {numPST: MaxPathSetupTypes + 10, expected: MaxPathSetupTypes},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tlv := &PathSetupTypeCapability{
				PathSetupTypes: make(Psts, tt.numPST),
			}
			assert.Equal(t, tt.expected, tlv.pstCount())
		})
	}
}

func TestPathSetupTypeCapability_Len(t *testing.T) {
	t.Parallel()

	var subTLVLen int
	for _, s := range testPathSetupTypeCapabilityWithSubTLV.SubTLVs {
		subTLVLen += s.Len()
	}

	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"Basic":   {input: testPathSetupTypeCapabilityBasic, expected: uint16(TLVValueOffset + PathSetupTypeCapabilityFixedPartLength + testPathSetupTypeCapabilityBasic.paddedPSTLength())},
		"WithSub": {input: testPathSetupTypeCapabilityWithSubTLV, expected: uint16(TLVValueOffset + PathSetupTypeCapabilityFixedPartLength + testPathSetupTypeCapabilityWithSubTLV.paddedPSTLength() + subTLVLen)},
	}
	runTLVLenTests(t, cases)
}

func TestAssocType_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    AssocType
		expected string
	}{
		"PathProtection":   {AssocTypePathProtectionAssociation, nameAssocPathProtection + " (0x0001)"},
		"Disjoint":         {AssocTypeDisjointAssociation, nameAssocDisjoint + " (0x0002)"},
		"Policy":           {AssocTypePolicyAssociation, nameAssocPolicy + " (0x0003)"},
		"SingleSidedBidir": {AssocTypeSingleSidedBidirectionalLSPAssociation, "Single Sided Bidirectional LSP Association (0x0004)"},
		"DoubleSidedBidir": {AssocTypeDoubleSidedBidirectionalLSPAssociation, "Double Sided Bidirectional LSP Association (0x0005)"},
		"SRPolicy":         {AssocTypeSRPolicyAssociation, nameAssocSRPolicy + " (0x0006)"},
		"VnAssociation":    {AssocTypeVnAssociationType, "VN Association Type (0x0007)"},
		"BidirSRLSP":       {AssocTypeBidirectionalSRLSPAssociation, "Bidirectional SR LSP Association (0x0008)"},
		"P2MPSRPolicy":     {AssocTypeP2MPSRPolicyAssociation, "P2MP SR Policy Association (0x0009)"},
		"SRPolicyCisco":    {AssocTypeSRPolicyAssociationCisco, "SR Policy Association (Cisco-specific) (0x0014)"},
		"SRPolicyJuniper":  {AssocTypeSRPolicyAssociationJuniper, "SR Policy Association (Juniper-specific, deprecated) (0xffe1)"},
		"Unknown":          {AssocType(0xffff), "Unknown AssocType (0xffff)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := tt.input.String()
			assert.Equal(t, tt.expected, actual, "unexpected AssocType.String() result for '%s'", name)
		})
	}
}

func TestAssocType_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    AssocType
		expected string
	}{
		"SRPolicy":        {AssocTypeSRPolicyAssociation, nameAssocSRPolicy + " (0x0006) [RFC9862]"},
		"BidirSRLSP":      {AssocTypeBidirectionalSRLSPAssociation, "Bidirectional SR LSP Association (0x0008) [draft-ietf-pce-sr-bidir-path-25]"},
		"SRPolicyCisco":   {AssocTypeSRPolicyAssociationCisco, "SR Policy Association (Cisco-specific) (0x0014) [not IANA-assigned]"},
		"SRPolicyJuniper": {AssocTypeSRPolicyAssociationJuniper, "SR Policy Association (Juniper-specific, deprecated) (0xffe1) [not IANA-assigned]"},
		"Unknown":         {AssocType(0xffff), "Unknown AssocType (0xffff)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.input.StringWithReference(), "unexpected AssocType.StringWithReference() result for '%s'", name)
		})
	}
}

func TestMessageType_Reference(t *testing.T) {
	t.Parallel()

	assert.Equal(t, rfc(8231), MessageTypeReport.Reference())
	assert.Equal(t, RefKindUnknown, MessageType(0x7f).Reference().Kind())
	assert.Empty(t, MessageType(0x7f).Name())
}

func TestPCRptMessage_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	rawBandwidth := func(bw uint32) []uint8 {
		header := NewCommonObjectHeader(ObjectClassBandwidth, ObjectType(1), commonObjectHeaderLength+4)
		return AppendByteSlices(header.Serialize(), Uint32ToByteSlice(bw))
	}

	srp := &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 1}
	lsp := &LSPObject{ObjectType: ObjectTypeLSPLSP, PlspID: 5, OFlag: 1, AFlag: true, DFlag: true}
	ero := &EroObject{ObjectType: ObjectTypeEROExplicitRoute}
	eroRaw, err := ero.Serialize()
	require.NoError(t, err)
	srpRaw, err := srp.Serialize()
	require.NoError(t, err)
	lspRaw, err := lsp.Serialize()
	require.NoError(t, err)

	baseReport := func() []uint8 {
		return AppendByteSlices(srpRaw, lspRaw, eroRaw)
	}

	newBaseStateReport := func() *StateReport {
		sr := NewStateReport()
		sr.SrpObject, sr.LSPObject, sr.EroObject = srp, lsp, ero

		return sr
	}

	t.Run("SingleReport", func(t *testing.T) {
		t.Parallel()

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(baseReport()))
		assert.Equal(t, []*StateReport{newBaseStateReport()}, m.StateReports)
	})

	// An LSP starts a new StateReport without a preceding SRP.
	t.Run("LSPOnlyStartsNewReport", func(t *testing.T) {
		t.Parallel()

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(AppendByteSlices(lspRaw, eroRaw)))

		want := newBaseStateReport()
		want.SrpObject = &SrpObject{}
		assert.Equal(t, []*StateReport{want}, m.StateReports)
	})

	t.Run("MultipleReports", func(t *testing.T) {
		t.Parallel()

		srp2 := &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 2}
		lsp2 := &LSPObject{ObjectType: ObjectTypeLSPLSP, PlspID: 6, OFlag: 1, AFlag: true, DFlag: true}
		srp2Raw, err := srp2.Serialize()
		require.NoError(t, err)
		lsp2Raw, err := lsp2.Serialize()
		require.NoError(t, err)

		raw := AppendByteSlices(baseReport(), srp2Raw, lsp2Raw, eroRaw)

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(raw))

		second := newBaseStateReport()
		second.SrpObject, second.LSPObject = srp2, lsp2

		assert.Equal(t, []*StateReport{newBaseStateReport(), second}, m.StateReports)
	})

	// Unregistered object classes must not break SRP/LSP correlation.
	t.Run("SkipsUnregisteredObjectClass", func(t *testing.T) {
		t.Parallel()

		ep, err := NewEndpointsObject(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
		require.NoError(t, err)
		epRaw, err := ep.Serialize()
		require.NoError(t, err)

		raw := AppendByteSlices(srpRaw, epRaw, lspRaw, eroRaw)

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(raw))
		assert.Equal(t, []*StateReport{newBaseStateReport()}, m.StateReports)
	})

	t.Run("WithMetricsBandwidthLSPAAssociationVendorInfo", func(t *testing.T) {
		t.Parallel()

		metric1 := &MetricObject{ObjectType: ObjectType(1), CFlag: true, MetricType: 2}
		metric2 := &MetricObject{ObjectType: ObjectType(1), BFlag: true, MetricType: 1}
		lspa := &LSPAObject{ObjectType: ObjectType(1), SetupPriority: 7, HoldingPriority: 7, LFlag: true}
		assoc := &AssociationObject{
			ObjectType: ObjectTypeAssociationIPv4, AssocType: AssocTypeSRPolicyAssociation,
			AssocID: 1, AssocSrc: netip.MustParseAddr("192.0.2.1"),
		}
		vendorInfo := &VendorInformationObject{ObjectType: ObjectTypeVendorSpecificConstraints, EnterpriseNumber: EnterpriseNumberCisco}

		assocRaw, err := assoc.Serialize()
		require.NoError(t, err)
		vendorInfoRaw, err := vendorInfo.Serialize()
		require.NoError(t, err)

		raw := AppendByteSlices(
			srpRaw, lspRaw,
			metric1.Serialize(), metric2.Serialize(),
			rawBandwidth(1000),
			lspa.Serialize(),
			assocRaw,
			vendorInfoRaw,
			eroRaw,
		)

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(raw))

		want := newBaseStateReport()
		want.MetricObjects = []*MetricObject{metric1, metric2}
		want.BandwidthObjects = []*BandwidthObject{{ObjectType: ObjectType(1), Bandwidth: 1000}}
		want.LSPAObject = lspa
		want.AssociationObjects = []*AssociationObject{assoc}
		want.VendorInformationObject = vendorInfo

		assert.Equal(t, []*StateReport{want}, m.StateReports)
	})

	t.Run("Errors", func(t *testing.T) {
		t.Parallel()

		ep, err := NewEndpointsObject(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
		require.NoError(t, err)
		epRaw, err := ep.Serialize()
		require.NoError(t, err)

		cases := map[string][]uint8{
			"TruncatedObjectHeader":       {0x01, 0x02},
			"EmptyBody":                   {},
			"OnlyUnregisteredObjectClass": epRaw,
			"MalformedSRPBody": AppendByteSlices(
				NewCommonObjectHeader(ObjectClassSRP, ObjectTypeSRPSRP, commonObjectHeaderLength+4).Serialize(),
				make([]uint8, 4),
			),
			"MalformedBandwidthBody": NewCommonObjectHeader(ObjectClassBandwidth, ObjectType(1), commonObjectHeaderLength).Serialize(),
			"MalformedMetricBody":    NewCommonObjectHeader(ObjectClassMetric, ObjectType(1), commonObjectHeaderLength).Serialize(),
			"SRPWithNoLSP":           srpRaw,
			"TwoSRPsInARowNoLSP":     AppendByteSlices(srpRaw, srpRaw),
		}

		for name, body := range cases {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				var m PCRptMessage
				assert.Error(t, m.DecodeFromBytes(body))
			})
		}
	})
}

func TestPCRptMessage_DecodeFromBytes_MalformedNestedObjectBody(t *testing.T) {
	t.Parallel()

	srp := &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 1}
	lsp := &LSPObject{ObjectType: ObjectTypeLSPLSP, PlspID: 5, OFlag: 1, AFlag: true, DFlag: true}
	srpRaw, err := srp.Serialize()
	require.NoError(t, err)
	lspRaw, err := lsp.Serialize()
	require.NoError(t, err)

	prefix := AppendByteSlices(srpRaw, lspRaw)

	cases := map[string][]uint8{
		"TruncatedBandwidthBody": AppendByteSlices(prefix, NewCommonObjectHeader(ObjectClassBandwidth, ObjectType(1), commonObjectHeaderLength).Serialize()),
		"TruncatedMetricBody":    AppendByteSlices(prefix, NewCommonObjectHeader(ObjectClassMetric, ObjectType(1), commonObjectHeaderLength).Serialize()),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m PCRptMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestNewPCUpdMessage(t *testing.T) {
	t.Parallel()

	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001), table.NewSegmentSRMPLS(16002)}

	m, err := NewPCUpdMessage(1, table.SRPolicy{Name: testPolicyName, PlspID: 5, SegmentList: segmentList})
	require.NoError(t, err)

	raw, err := m.Serialize()
	require.NoError(t, err)

	var commonHeader CommonHeader
	require.NoError(t, commonHeader.DecodeFromBytes(raw[:CommonHeaderLength]))
	assert.Equal(t, MessageTypeUpdate, commonHeader.MessageType)
	assert.Equal(t, len(raw), int(commonHeader.MessageLength))

	body := raw[CommonHeaderLength:]

	var srpHeader CommonObjectHeader
	require.NoError(t, srpHeader.DecodeFromBytes(body))

	var srp SrpObject
	require.NoError(t, srp.DecodeFromBytes(srpHeader.ObjectType, body[commonObjectHeaderLength:srpHeader.ObjectLength]))
	assert.Equal(t, m.SrpObject, &srp)

	body = body[srpHeader.ObjectLength:]

	var lspHeader CommonObjectHeader
	require.NoError(t, lspHeader.DecodeFromBytes(body))

	var lsp LSPObject
	require.NoError(t, lsp.DecodeFromBytes(lspHeader.ObjectType, body[commonObjectHeaderLength:lspHeader.ObjectLength]))
	assert.Equal(t, m.LSPObject, &lsp)

	body = body[lspHeader.ObjectLength:]

	var eroHeader CommonObjectHeader
	require.NoError(t, eroHeader.DecodeFromBytes(body))

	var ero EroObject
	require.NoError(t, ero.DecodeFromBytes(eroHeader.ObjectType, body[commonObjectHeaderLength:eroHeader.ObjectLength]))
	assert.Equal(t, m.EroObject, &ero)
}

func TestCloseMessage_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"TruncatedObjectHeader":   {0x01, 0x02},
		"WrongObjectClass":        NewCommonObjectHeader(ObjectClassOpen, ObjectTypeOpenOpen, 8).Serialize(),
		"WrongObjectType":         NewCommonObjectHeader(ObjectClassClose, ObjectType(2), 8).Serialize(),
		"ObjectLengthHeaderOnly":  NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, commonObjectHeaderLength).Serialize(),
		"ObjectLengthZero":        NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, 0).Serialize(),
		"ObjectLengthExceedsBody": NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, 100).Serialize(),
		"PartialBody": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, commonObjectHeaderLength+2).Serialize(),
			make([]uint8, 2),
		),
		"TrailingBytes": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, commonObjectHeaderLength+4).Serialize(),
			make([]uint8, 4),
			[]uint8{0xff},
		),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m CloseMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestPCErrMessage_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	validSRP, err := (&SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 1}).Serialize()
	require.NoError(t, err)
	validError, err := (&ErrorObject{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1}).Serialize()
	require.NoError(t, err)

	cases := map[string][]uint8{
		"TruncatedObjectHeader":        {0x01, 0x02},
		"InvalidObjectLength":          NewCommonObjectHeader(ObjectClassPCEPError, ObjectTypeErrorError, 5).Serialize(),
		"ObjectBodyExtendsPastMessage": NewCommonObjectHeader(ObjectClassPCEPError, ObjectTypeErrorError, 12).Serialize(),
		"MalformedPCEPErrorTLV": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassPCEPError, ObjectTypeErrorError, 12).Serialize(),
			[]uint8{0x00, 0x00, 0x06, 0x01}, // Error-Type=6, Error-Value=1
			[]uint8{0x00, 0x27, 0x00, 0xff}, // TLV length exceeds available data
		),
		"MalformedSRPBody": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassSRP, ObjectTypeSRPSRP, commonObjectHeaderLength+4).Serialize(),
			make([]uint8, 4),
		),
		// RFC 5440 §6.7 requires at least one PCEP-ERROR object.
		"NoErrorObjectPresent": validSRP,
		"MalformedOpenBody": AppendByteSlices(
			validError,
			NewCommonObjectHeader(ObjectClassOpen, ObjectTypeOpenOpen, commonObjectHeaderLength+4).Serialize(),
			[]uint8{0x40, 0x00, 0x00, 0x00}, // unsupported PCEP version (2) in the OPEN object
		),
		"UnsupportedOpenObjectType": AppendByteSlices(
			validError,
			NewCommonObjectHeader(ObjectClassOpen, ObjectType(2), commonObjectHeaderLength+4).Serialize(),
			[]uint8{0x20, 0x00, 0x00, 0x00},
		),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m PCErrMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}
