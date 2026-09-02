// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pstDescriptionSRTE = "Traffic engineering path is set up using Segment Routing (0x01) [RFC8664]"

func TestTLVType_String(t *testing.T) {
	cases := map[string]struct {
		tlvType  TLVType
		expected string
	}{
		"StatefulPCECapability": {TLVStatefulPCECapability, "STATEFUL-PCE-CAPABILITY (0x0010)"},
		"IPv4LSPIdentifiers":    {TLVIPv4LSPIdentifiers, "IPV4-LSP-IDENTIFIERS (0x0012)"},
		"UnknownType":           {TLVType(0xdead), "Unknown TLV (0xdead)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.tlvType.String()
			assert.Equal(t, tt.expected, actual, "unexpected TLVType.String() result")
		})
	}
}

func TestTLVType_StringWithReference(t *testing.T) {
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
			assert.Equal(t, tt.expected, tt.tlvType.StringWithReference(), "unexpected TLVType.StringWithReference() result")
		})
	}
}

func TestTLVType_NameAndReference(t *testing.T) {
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
			assert.Equal(t, tt.expectedName, tt.tlvType.Name(), "unexpected TLVType.Name() result")
			assert.Equal(t, tt.expectedRef, tt.tlvType.Reference(), "unexpected TLVType.Reference() result")
		})
	}
}

func TestTLVMap(t *testing.T) {
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
			constructor, ok := tlvMap[tt.tlvType]
			require.True(t, ok, "constructor not found for TLVType '%s'", name)
			actual := constructor()
			assert.IsType(t, tt.expected, actual, "unexpected type for TLV '%s'", name)
		})
	}
}

type TLVTestCase struct {
	input    []byte
	expected TLVInterface
	wantErr  bool
}

func runTLVDecodeTests(t *testing.T, cases map[string]TLVTestCase, constructor func() TLVInterface) {
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			tlv := constructor()
			err := tlv.DecodeFromBytes(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "expected error for '%s' but got none", name)
			} else {
				require.NoError(t, err, "unexpected error for '%s'", name)
				assert.Equal(t, tt.expected, tlv, "decoded value mismatch for '%s'", name)
			}
		})
	}
}

func runTLVSerializeTests(t *testing.T, cases map[string]struct {
	input    TLVInterface
	expected []byte
},
) {
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual, err := tt.input.Serialize()
			require.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, actual, "serialized value mismatch for '%s'", name)
		})
	}
}

func runTLVLenTests(t *testing.T, cases map[string]struct {
	input    TLVInterface
	expected uint16
},
) {
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.input.Len()
			assert.Equal(t, int(tt.expected), actual, "length mismatch for '%s'", name)
		})
	}
}

// mustSerializeTLV serializes a TLV for use in test fixtures.
func mustSerializeTLV(tlv TLVInterface) []byte {
	b, err := tlv.Serialize()
	if err != nil {
		panic(err)
	}
	return b
}

func tlvHeader(tlvType TLVType, length uint16) []byte {
	return []byte{byte(tlvType >> 8), byte(tlvType & 0xff), byte(length >> 8), byte(length & 0xff)}
}

// Test data for VendorInformation.
var (
	// Enterprise Number only, no Enterprise-Specific Information (Juniper sends this in Open).
	testVendorInformationJuniper      = NewVendorInformation(EnterpriseNumberJuniper, nil)
	testVendorInformationJuniperBytes = append(tlvHeader(TLVVendorInformation, 4), 0x00, 0x00, 0x0a, 0x4c)
	// Enterprise-Specific Information already 4-byte aligned.
	testVendorInformationWithInfo      = NewVendorInformation(EnterpriseNumberJuniper, []byte{0xde, 0xad, 0xbe, 0xef})
	testVendorInformationWithInfoBytes = append(tlvHeader(TLVVendorInformation, 8), 0x00, 0x00, 0x0a, 0x4c, 0xde, 0xad, 0xbe, 0xef)
	// 2-byte Enterprise-Specific Information (value length 6 → 2 bytes padding).
	testVendorInformationUnaligned      = NewVendorInformation(EnterpriseNumberCisco, []byte{0x01, 0x02})
	testVendorInformationUnalignedBytes = append(tlvHeader(TLVVendorInformation, 6), 0x00, 0x00, 0x00, 0x09, 0x01, 0x02, 0x00, 0x00)
	// Enterprise Number not present in enterpriseNumberNames.
	testVendorInformationUnknownEnterprise = NewVendorInformation(12345, nil)
	// Value shorter than the mandatory Enterprise Number.
	testVendorInformationTooShort        = append(tlvHeader(TLVVendorInformation, 2), 0x00, 0x00)
	testVendorInformationTruncatedValue  = append(tlvHeader(TLVVendorInformation, 8), 0x00, 0x00, 0x0a, 0x4c)
	testVendorInformationTruncatedHeader = []byte{0x00, 0x07, 0x00}
)

func TestVendorInformation_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"EnterpriseNumberOnly": {testVendorInformationJuniperBytes, testVendorInformationJuniper, false},
		"WithEnterpriseSpecificInformation": {
			testVendorInformationWithInfoBytes, testVendorInformationWithInfo, false,
		},
		"UnalignedEnterpriseSpecificInformation": {
			testVendorInformationUnalignedBytes, testVendorInformationUnaligned, false,
		},
		"ValueTooShort":   {testVendorInformationTooShort, nil, true},
		"TruncatedValue":  {testVendorInformationTruncatedValue, nil, true},
		"TruncatedHeader": {testVendorInformationTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &VendorInformation{} })
}

func TestVendorInformation_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"EnterpriseNumberOnly":                   {testVendorInformationJuniper, testVendorInformationJuniperBytes},
		"WithEnterpriseSpecificInformation":      {testVendorInformationWithInfo, testVendorInformationWithInfoBytes},
		"UnalignedEnterpriseSpecificInformation": {testVendorInformationUnaligned, testVendorInformationUnalignedBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestVendorInformation_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"EnterpriseNumberOnly":                   {testVendorInformationJuniper, TLVValueOffset + 4},
		"WithEnterpriseSpecificInformation":      {testVendorInformationWithInfo, TLVValueOffset + 8},
		"UnalignedEnterpriseSpecificInformation": {testVendorInformationUnaligned, TLVValueOffset + 8}, // 6-byte value + 2 pad
	}
	runTLVLenTests(t, cases)
}

func TestVendorInformation_Serialize_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &VendorInformation{EnterpriseSpecificInformation: make([]byte, 65531)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65535), binary.BigEndian.Uint16(raw[TLVLengthOffset:TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &VendorInformation{EnterpriseSpecificInformation: make([]byte, 65532)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

func TestVendorInformation_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*VendorInformation{
		"EnterpriseNumberOnly":                   testVendorInformationJuniper,
		"WithEnterpriseSpecificInformation":      testVendorInformationWithInfo,
		"UnalignedEnterpriseSpecificInformation": testVendorInformationUnaligned,
		"UnknownEnterprise":                      testVendorInformationUnknownEnterprise,
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := original.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, data, original.Len(), "Len() must match serialized size")

			decoded, err := DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*VendorInformation)
			require.Truef(t, ok, "expected *VendorInformation, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			gotData, err := got.Serialize()
			require.NoError(t, err, "Serialize failed")
			assert.Equal(t, data, gotData, "re-serialized bytes differ")
		})
	}
}

// Test data for StatefulPCECapability.
var (
	testStatefulLSPUpdate      = NewStatefulPCECapability(0x00000001) // LSP Update capability only
	testStatefulAll            = NewStatefulPCECapability(0x0000083f) // All capabilities enabled
	testStatefulNone           = NewStatefulPCECapability(0x00000000) // No capabilities enabled
	testStatefulLSPUpdateBytes = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x01)
	testStatefulAllBytes       = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x08, 0x3f)
	testStatefulNoneBytes      = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	testStatefulMissingTLVBody = tlvHeader(TLVStatefulPCECapability, 4)
	testStatefulTooShort       = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x01, 0x02)
	testStatefulInvalidLength  = append(tlvHeader(TLVStatefulPCECapability, 3), 0x00, 0x00, 0x00)
)

func TestStatefulPCECapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"SingleCapability":   {testStatefulLSPUpdateBytes, testStatefulLSPUpdate, false},
		"AllCapabilities":    {testStatefulAllBytes, testStatefulAll, false},
		"MissingTLVBody":     {testStatefulMissingTLVBody, nil, true},
		"ValueTooShort":      {testStatefulTooShort, nil, true},
		"InvalidValueLength": {testStatefulInvalidLength, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &StatefulPCECapability{} })
}

func TestStatefulPCECapability_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"LSPUpdate":       {testStatefulLSPUpdate, testStatefulLSPUpdateBytes},
		"AllCapabilities": {testStatefulAll, testStatefulAllBytes},
		"NoCapabilities":  {testStatefulNone, testStatefulNoneBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestStatefulPCECapability_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"LSPUpdate": {testStatefulLSPUpdate, TLVValueOffset + 4},
	}
	runTLVLenTests(t, cases)
}

// Test data for SymbolicPathName.
var (
	testSymbolicPathName            = NewSymbolicPathName("Test") // Normal case
	testSymbolicPathNameWithPadding = NewSymbolicPathName("ABC")  // 1 padding byte
	testSymbolicPathNameEmptyString = NewSymbolicPathName("")     // Empty string

	testSymbolicPathNameBytes            = []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff), 0x00, 0x04, 'T', 'e', 's', 't'}
	testSymbolicPathNameEmptyBytes       = []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff), 0x00, 0x00}
	testSymbolicPathNameInvalidUTF8Bytes = []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff), 0x00, 0x01, 0xff}
	testSymbolicPathNameTooShort         = []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff), 0x00, 0x02, 'T'}
	testSymbolicPathNameTooLong          = []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff), 0x00, 0x01, 'T', 'e'}
	testSymbolicPathNameTruncatedHeader  = []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff), 0x00}
)

func TestSymbolicPathName_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"Valid":           {testSymbolicPathNameBytes, testSymbolicPathName, false},
		"Empty":           {testSymbolicPathNameEmptyBytes, testSymbolicPathNameEmptyString, false},
		"InvalidUTF8":     {testSymbolicPathNameInvalidUTF8Bytes, nil, true},
		"TruncatedHeader": {testSymbolicPathNameTruncatedHeader, nil, true},
		"TooShort":        {testSymbolicPathNameTooShort, nil, true},
		"TooLong":         {testSymbolicPathNameTooLong, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SymbolicPathName{} })
}

func TestSymbolicPathName_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"Valid": {testSymbolicPathName, testSymbolicPathNameBytes},
		"Empty": {testSymbolicPathNameEmptyString, testSymbolicPathNameEmptyBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSymbolicPathName_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"Valid":  {testSymbolicPathName, TLVValueOffset + 4},
		"Padded": {testSymbolicPathNameWithPadding, TLVValueOffset + 4}, // "ABC" + 1 padding
	}
	runTLVLenTests(t, cases)
}

func TestSymbolicPathName_Serialize_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &SymbolicPathName{Name: strings.Repeat("a", 65535)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65535), binary.BigEndian.Uint16(raw[TLVLengthOffset:TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &SymbolicPathName{Name: strings.Repeat("a", 65536)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

// Test data for IPv4LSPIdentifiers.
var (
	testIPv4LSPIdentifiers      = NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234)
	testIPv4LSPIdentifiersBytes = append(
		tlvHeader(TLVIPv4LSPIdentifiers, TLVIPv4LSPIdentifiersValueLength),
		0xc0, 0x00, 0x02, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, 0x02, // Endpoint Address
	)
	testIPv4LSPIdentifiersTruncated = []byte{
		byte(TLVIPv4LSPIdentifiers >> 8), byte(TLVIPv4LSPIdentifiers & 0xff), 0x00, 0x03,
		0xc0, 0x00, 0x02,
	}
	testIPv4LSPIdentifiersExtra     = append(testIPv4LSPIdentifiersBytes, 0xde, 0xad, 0xbe, 0xef)
	testIPv4LSPIdentifiersBadSender = append(
		tlvHeader(TLVIPv4LSPIdentifiers, TLVIPv4LSPIdentifiersValueLength),
		0xc0, 0x00, 0x02, // 3 bytes only → invalid sender
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, 0x02, // Endpoint Address
	)
	testIPv4LSPIdentifiersBadEndpoint = append(
		tlvHeader(TLVIPv4LSPIdentifiers, TLVIPv4LSPIdentifiersValueLength),
		0xc0, 0x00, 0x02, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, // Endpoint Address (3 bytes only)
	)
)

func TestIPv4LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidIPv4LSPIdentifiers":        {testIPv4LSPIdentifiersBytes, testIPv4LSPIdentifiers, false},
		"TruncatedIPv4LSPIdentifiers":    {testIPv4LSPIdentifiersTruncated, nil, true},
		"ExtraBytesInIPv4LSPIdentifiers": {testIPv4LSPIdentifiersExtra, nil, true},
		"InvalidSenderAddress":           {testIPv4LSPIdentifiersBadSender, nil, true},
		"InvalidEndpointAddress":         {testIPv4LSPIdentifiersBadEndpoint, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &IPv4LSPIdentifiers{} })
}

func TestIPv4LSPIdentifiers_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidIPv4LSPIdentifiers": {testIPv4LSPIdentifiers, testIPv4LSPIdentifiersBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestIPv4LSPIdentifiers_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidIPv4LSPIdentifiersLength": {testIPv4LSPIdentifiers, TLVValueOffset + TLVIPv4LSPIdentifiersValueLength},
	}
	runTLVLenTests(t, cases)
}

// Test data for IPv6LSPIdentifiers.
var (
	// Valid IPv6LSPIdentifiers with typical values.
	testIPv6LSPIdentifiers = NewIPv6LSPIdentifiers(
		netip.MustParseAddr(testIPv6Addr1),
		netip.MustParseAddr(testIPv6Addr2),
		1, 2, [IPv6AddrLen]byte{},
	)

	// Serialized TLV bytes for testIPv6LSPIdentifiers.
	testIPv6LSPIdentifiersBytes = append(
		tlvHeader(TLVIPv6LSPIdentifiers, TLVIPv6LSPIdentifiersValueLength),
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extended Tunnel ID (all zeros)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Endpoint Address
	)

	// TLV bytes with intentionally invalid value length (to cover valueLen != expected case).
	testIPv6LSPIdentifiersInvalidLength = []byte{
		byte(TLVIPv6LSPIdentifiers >> 8),
		byte(TLVIPv6LSPIdentifiers & 0xff),
		0x00, 0x10, // Length = 16 (too short, expected 40)
		// Fill 16 bytes of value (only part of sender address)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // First half of Sender Address
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Second half of Sender Address
	}

	// TLV bytes truncated (cut from the end) to simulate incomplete TLV.
	testIPv6LSPIdentifiersTruncated = testIPv6LSPIdentifiersBytes[:len(testIPv6LSPIdentifiersBytes)-5]

	// TLV bytes with extra bytes appended at the end.
	testIPv6LSPIdentifiersExtra = append(testIPv6LSPIdentifiersBytes, 0xca, 0xfe, 0xba, 0xbe)
)

func TestIPv6LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidIPv6LSPIdentifiers":        {testIPv6LSPIdentifiersBytes, testIPv6LSPIdentifiers, false},
		"InvalidValueLength":             {testIPv6LSPIdentifiersInvalidLength, nil, true},
		"TruncatedIPv6LSPIdentifiers":    {testIPv6LSPIdentifiersTruncated, nil, true},
		"ExtraBytesInIPv6LSPIdentifiers": {testIPv6LSPIdentifiersExtra, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &IPv6LSPIdentifiers{} })
}

func TestIPv6LSPIdentifiers_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidIPv6LSPIdentifiers": {testIPv6LSPIdentifiers, testIPv6LSPIdentifiersBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestIPv6LSPIdentifiers_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidIPv6LSPIdentifiersLength": {testIPv6LSPIdentifiers, TLVValueOffset + TLVIPv6LSPIdentifiersValueLength},
	}
	runTLVLenTests(t, cases)
}

// Test data for LSPDBVersion.
var (
	testLSPDBVersion              = NewLSPDBVersion(12345)
	testLSPDBVersionBytes         = append(tlvHeader(TLVLSPDBVersion, 8), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39)
	testLSPDBVersionTruncated     = append(tlvHeader(TLVLSPDBVersion, 4), 0x00, 0x00, 0x00, 0x00)
	testLSPDBVersionExtra         = append(tlvHeader(TLVLSPDBVersion, 8), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0xde, 0xad, 0xbe, 0xef)
	testLSPDBVersionInvalidLength = append(tlvHeader(TLVLSPDBVersion, 16), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0xde, 0xad, 0xbe, 0xef)
)

func TestLSPDBVersion_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidLSPDBVersion":         {testLSPDBVersionBytes, testLSPDBVersion, false},
		"TruncatedLSPDBVersion":     {testLSPDBVersionTruncated, nil, true},
		"ExtraBytesInLSPDBVersion":  {testLSPDBVersionExtra, nil, true},
		"InvalidLengthLSPDBVersion": {testLSPDBVersionInvalidLength, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &LSPDBVersion{} })
}

func TestLSPDBVersion_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidLSPDBVersion": {testLSPDBVersion, testLSPDBVersionBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestLSPDBVersion_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidLSPDBVersionLength": {testLSPDBVersion, TLVValueOffset + TLVLSPDBVersionValueLength},
	}
	runTLVLenTests(t, cases)
}

// Test data for SRPCECapability.
var (
	testSRPCECapability = NewSRPCECapability(true, true, 10)
	// RFC 8664 §5.1.1: Reserved (2), Flags (1), MSD (1).
	testSRPCECapabilityBytes             = append(tlvHeader(TLVSRPCECapability, 4), 0x00, 0x00, 0x03, 0x0a)
	testSRPCECapabilityTruncated         = append(tlvHeader(TLVSRPCECapability, 4), 0x00, 0x02)
	testSRPCECapabilityExtra             = append(tlvHeader(TLVSRPCECapability, 4), 0x00, 0x00, 0x03, 0x05, 0xde, 0xad, 0xbe, 0xef)
	testSRPCECapabilityInvalidLength     = append(tlvHeader(TLVSRPCECapability, 8), 0x00, 0x00, 0x03, 0x05, 0xde, 0xad, 0xbe, 0xef)
	testSRPCECapabilityZeroMSDBytes      = append(tlvHeader(TLVSRPCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	testSRPCECapabilityMSDZeroAdvertised = &SRPCECapability{MaximumSidDepth: 0}
)

func TestSRPCECapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidSRPCECapability":         {testSRPCECapabilityBytes, testSRPCECapability, false},
		"TruncatedSRPCECapability":     {testSRPCECapabilityTruncated, nil, true},
		"ExtraBytesInSRPCECapability":  {testSRPCECapabilityExtra, nil, true},
		"InvalidLengthSRPCECapability": {testSRPCECapabilityInvalidLength, nil, true},
		"ZeroMSDIsStillAdvertised":     {testSRPCECapabilityZeroMSDBytes, testSRPCECapabilityMSDZeroAdvertised, false},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SRPCECapability{} })
}

func TestSRPCECapability_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidSRPCECapability": {testSRPCECapability, testSRPCECapabilityBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPCECapability_Serialize_WireFormat(t *testing.T) {
	cases := map[string]struct {
		input         *SRPCECapability
		expectedFlags uint8
		expectedMSD   uint8
	}{
		"NoFlagsMSD5":         {&SRPCECapability{MaximumSidDepth: 5}, 0x00, 5},
		"NoFlagsMSD10":        {&SRPCECapability{MaximumSidDepth: 10}, 0x00, 10},
		"UnlimitedMSDOnly":    {&SRPCECapability{HasUnlimitedMaxSIDDepth: true}, 0x01, 0},
		"NAIOnlyWithMSD":      {&SRPCECapability{IsNAISupported: true, MaximumSidDepth: 8}, 0x02, 8},
		"BothFlagsWithMSD255": {NewSRPCECapability(true, true, 255), 0x03, 255},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tt.input.Serialize()
			require.NoError(t, err, "Serialize failed for '%s'", name)
			require.Len(t, got, int(TLVValueOffset+TLVSRPCECapabilityValueLength))

			value := got[TLVValueOffset:]
			assert.Equal(t, []uint8{0x00, 0x00}, value[0:2], "Reserved octets must be zero")
			assert.Equal(t, tt.expectedFlags, value[SRPCECapabilityFlagsOffset], "Flags in wrong byte position")
			assert.Equal(t, tt.expectedMSD, value[SRPCECapabilityMSDOffset], "MSD in wrong byte position")
		})
	}
}

func TestSRPCECapability_DecodeFromBytes_WireFormat(t *testing.T) {
	cases := map[string]struct {
		value    []uint8
		expected *SRPCECapability
	}{
		// Junos: MSD=5; Cisco IOS-XR: MSD=10; no flags.
		"MSD5":  {[]uint8{0x00, 0x00, 0x00, 0x05}, &SRPCECapability{MaximumSidDepth: 5}},
		"MSD10": {[]uint8{0x00, 0x00, 0x00, 0x0a}, &SRPCECapability{MaximumSidDepth: 10}},
		"XFlag": {[]uint8{0x00, 0x00, 0x01, 0x00}, &SRPCECapability{HasUnlimitedMaxSIDDepth: true}},
		"NFlagWithMSD": {
			[]uint8{0x00, 0x00, 0x02, 0x04},
			&SRPCECapability{IsNAISupported: true, MaximumSidDepth: 4},
		},
		"BothFlags": {
			[]uint8{0x00, 0x00, 0x03, 0x0a},
			&SRPCECapability{HasUnlimitedMaxSIDDepth: true, IsNAISupported: true, MaximumSidDepth: 10},
		},
		"NonZeroReservedIsIgnored": {
			[]uint8{0xde, 0xad, 0x00, 0x05},
			&SRPCECapability{MaximumSidDepth: 5},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			var tlv SRPCECapability
			err := tlv.DecodeFromBytes(append(tlvHeader(TLVSRPCECapability, 4), tt.value...))
			require.NoError(t, err, "DecodeFromBytes failed for '%s'", name)
			assert.Equal(t, tt.expected, &tlv, "unexpected decode result for '%s'", name)
		})
	}
}

func TestSRPCECapability_RoundTrip(t *testing.T) {
	cases := map[string]*SRPCECapability{
		"Empty":        {},
		"MSD5":         {MaximumSidDepth: 5},
		"MSD10":        {MaximumSidDepth: 10},
		"UnlimitedMSD": {HasUnlimitedMaxSIDDepth: true},
		"NAIWithMSD":   {IsNAISupported: true, MaximumSidDepth: 8},
		"AllFields":    NewSRPCECapability(true, true, 10),
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed for '%s'", name)

			var got SRPCECapability
			require.NoError(t, got.DecodeFromBytes(raw), "DecodeFromBytes failed for '%s'", name)
			assert.Equal(t, want, &got, "round-trip mismatch for '%s'", name)
		})
	}
}

func TestSRPCECapability_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidSRPCECapabilityLength": {testSRPCECapability, TLVValueOffset + TLVSRPCECapabilityValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestSRPCECapability_DecodeSerializeRoundTrip(t *testing.T) {
	cases := map[string]*SRPCECapability{
		"MSDNonZero":       {MaximumSidDepth: 200},
		"MSDMax":           {MaximumSidDepth: math.MaxUint8},
		"UnlimitedZeroMSD": {HasUnlimitedMaxSIDDepth: true},
		"UnlimitedWithNAIZeroMSD": {
			HasUnlimitedMaxSIDDepth: true,
			IsNAISupported:          true,
		},
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			b, err := original.Serialize()
			require.NoError(t, err)

			var decoded SRPCECapability
			require.NoError(t, decoded.DecodeFromBytes(b))
			assert.Equal(t, original, &decoded, "first decode must match the original")

			b2, err := decoded.Serialize()
			require.NoError(t, err)
			assert.Equal(t, b, b2, "re-serializing a decoded value must produce identical bytes")

			var decodedAgain SRPCECapability
			require.NoError(t, decodedAgain.DecodeFromBytes(b2))
			assert.Equal(t, decoded, decodedAgain, "second decode must match the first")
		})
	}
}

func TestSRPCECapability_HasInvalidZeroMSD(t *testing.T) {
	cases := map[string]struct {
		input    *SRPCECapability
		expected bool
	}{
		"XZeroMSDZero":        {&SRPCECapability{}, true},
		"XZeroMSDNonZero":     {&SRPCECapability{MaximumSidDepth: 10}, false},
		"XOneMSDZero":         {&SRPCECapability{HasUnlimitedMaxSIDDepth: true}, false},
		"XZeroNAIOnlyMSDZero": {&SRPCECapability{IsNAISupported: true}, true},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.HasInvalidZeroMSD())
		})
	}
}

func TestPst_String(t *testing.T) {
	cases := map[string]struct {
		input    Pst
		expected string
	}{
		"Known PathSetupType":   {Pst(0x01), "Traffic engineering path is set up using Segment Routing (0x01)"},
		"Unknown PathSetupType": {Pst(0xff), "Unknown PathSetupType (0xff)"},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.input.String()
			assert.Equal(t, tt.expected, actual, "unexpected Pst.String() result for '%s'", name)
		})
	}
}

func TestPst_StringWithReference(t *testing.T) {
	cases := map[string]struct {
		input    Pst
		expected string
	}{
		"Known PathSetupType":   {PathSetupTypeSRTE, pstDescriptionSRTE},
		"Unknown PathSetupType": {Pst(0xff), "Unknown PathSetupType (0xff)"},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.StringWithReference(), "unexpected Pst.StringWithReference() result for '%s'", name)
		})
	}
}

func TestPsts_MarshalJSON(t *testing.T) {
	cases := map[string]struct {
		input    Psts
		expected string
	}{
		"Nil Psts":      {nil, "null"},
		"Empty Psts":    {Psts{}, "[]"},
		"Single Pst":    {Psts{Pst(1)}, "[1]"},
		"Multiple Psts": {Psts{Pst(1), Pst(2)}, "[1,2]"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual, err := tt.input.MarshalJSON()
			require.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, string(actual), "MarshalJSON output mismatch for '%s'", name)
		})
	}
}

// Test data for PathSetupType.
var (
	testPathSetupTypeSRTE   = NewPathSetupType(PathSetupTypeSRTE)
	testPathSetupTypeRSVPTE = NewPathSetupType(PathSetupTypeRSVPTE)
	testPathSetupTypeSRv6TE = NewPathSetupType(PathSetupTypeSRv6TE)

	// Serialized bytes for PathSetupType SRTE.
	testPathSetupTypeSRTEBytes = []byte{
		byte(TLVPathSetupType >> 8), byte(TLVPathSetupType & 0xff), 0x00, 0x04, 0x00, 0x00, 0x00, byte(PathSetupTypeSRTE),
	}
	// Serialized bytes for PathSetupType RSVPTE.
	testPathSetupTypeRSVPTEBytes = []byte{
		byte(TLVPathSetupType >> 8), byte(TLVPathSetupType & 0xff), 0x00, 0x04, 0x00, 0x00, 0x00, byte(PathSetupTypeRSVPTE),
	}
	// Serialized bytes for PathSetupType SRv6TE.
	testPathSetupTypeSRv6TEBytes = []byte{
		byte(TLVPathSetupType >> 8), byte(TLVPathSetupType & 0xff), 0x00, 0x04, 0x00, 0x00, 0x00, byte(PathSetupTypeSRv6TE),
	}
	// Invalid input for PathSetupType (too short).
	testPathSetupTypeTooShort = []byte{
		0x00, 0x15, 0x00, 0x04,
	}
	// Invalid input for PathSetupType (too long).
	testPathSetupTypeTooLong = append(mustSerializeTLV(NewPathSetupType(PathSetupTypeSRTE)), 0x00, 0x00)
	// Invalid input for PathSetupType (value length mismatch).
	testPathSetupTypeInvalidLength = []byte{
		byte(TLVPathSetupType >> 8), byte(TLVPathSetupType & 0xff),
		0x00, 0x06,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x00,
	}
)

func TestPathSetupType_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"Valid SRv6TE":       {testPathSetupTypeSRv6TEBytes, testPathSetupTypeSRv6TE, false},
		"TooShort":           {testPathSetupTypeTooShort, nil, true},
		"TooLong":            {testPathSetupTypeTooLong, nil, true},
		"InvalidValueLength": {testPathSetupTypeInvalidLength, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &PathSetupType{} })
}

func TestPathSetupType_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"SRTE":   {testPathSetupTypeSRTE, testPathSetupTypeSRTEBytes},
		"RSVPTE": {testPathSetupTypeRSVPTE, testPathSetupTypeRSVPTEBytes},
		"SRv6TE": {testPathSetupTypeSRv6TE, testPathSetupTypeSRv6TEBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestPathSetupType_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"RSVPTELength": {testPathSetupTypeRSVPTE, TLVValueOffset + TLVPathSetupTypeValueLength},
	}
	runTLVLenTests(t, cases)
}

// test data for PathSetupTypeCapability.
var (
	// PathSetupTypeCapability instances.
	testPathSetupTypeCapabilityBasic = &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeRSVPTE, PathSetupTypeSRTE},
		SubTLVs:        []TLVInterface{},
	}
	testPathSetupTypeCapabilityWithSubTLV = &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeSRTE},
		SubTLVs:        []TLVInterface{NewSRPCECapability(true, true, 10)},
	}

	// Serialized TLV bytes.
	testPathSetupTypeCapabilityBasicBytes = []byte{
		0x00, 0x22, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x00, 0x00,
	}
	testPathSetupTypeCapabilityWithSubTLVBytes = []byte{
		0x00, 0x22, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x01,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x1a, 0x00, 0x04, 0x00, 0x00, 0x03, 0x0a,
	}

	// Invalid / error test cases.
	testPathSetupTypeCapabilityTooShort       = []byte{0x00, 0x22, 0x00, 0x02, 0x00, 0x00}
	testPathSetupTypeCapabilityPSTOverflow    = []byte{0x00, 0x22, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05}
	testPathSetupTypeCapabilityInvalidLength  = []byte{0x00, 0x22, 0xFF, 0xFF}
	testPathSetupTypeCapabilityBadSubTLVBytes = []byte{
		0x00, 0x22, 0x00, 0x0C,
		0x00, 0x00, 0x00, 0x01,
		0x01, 0x00,
		0xFF, 0xFF, 0x00, 0x04, 0x01, 0x02,
	}

	testPathSetupTypeCapabilityZeroPSTBytes = []byte{
		0x00, 0x22, 0x00, 0x04, // TLV header
		0x00, 0x00, 0x00, 0x00, // PST count = 0
	}
	testPathSetupTypeCapabilityZeroPST = &PathSetupTypeCapability{
		PathSetupTypes: Psts{},
		SubTLVs:        []TLVInterface{},
	}

	testPathSetupTypeCapabilityNilPST = &PathSetupTypeCapability{
		PathSetupTypes: Psts{},
		SubTLVs:        []TLVInterface{},
	}
	testPathSetupTypeCapabilitySubTLVOffsetOverflowBytes = []byte{
		0x00, 0x22, 0x00, 0x05, // TLV header, length=5
		0x00, 0x00, 0x00, 0x01, // PST count = 1
		0x01, // PST entry
	}
)

func TestPathSetupTypeCapability_pstCount(t *testing.T) {
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
			tlv := &PathSetupTypeCapability{
				PathSetupTypes: make(Psts, tt.numPST),
			}
			assert.Equal(t, tt.expected, tlv.pstCount())
		})
	}
}

func TestPathSetupTypeCapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidBasic":               {testPathSetupTypeCapabilityBasicBytes, testPathSetupTypeCapabilityBasic, false},
		"ValidWithSubTLV":          {testPathSetupTypeCapabilityWithSubTLVBytes, testPathSetupTypeCapabilityWithSubTLV, false},
		"ZeroPST":                  {testPathSetupTypeCapabilityZeroPSTBytes, testPathSetupTypeCapabilityZeroPST, false},
		"NilPST":                   {testPathSetupTypeCapabilityZeroPSTBytes, testPathSetupTypeCapabilityNilPST, false},
		"SubTLVOffsetExceedsValue": {testPathSetupTypeCapabilitySubTLVOffsetOverflowBytes, nil, true},
		"TooShort":                 {testPathSetupTypeCapabilityTooShort, nil, true},
		"PSTCountOverflow":         {testPathSetupTypeCapabilityPSTOverflow, nil, true},
		"InvalidTLVLength":         {testPathSetupTypeCapabilityInvalidLength, nil, true},
		"BadSubTLV":                {testPathSetupTypeCapabilityBadSubTLVBytes, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &PathSetupTypeCapability{} })
}

// TestPathSetupTypeCapability_Serialize tests PathSetupTypeCapability.Serialize.
func TestPathSetupTypeCapability_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"Basic":   {testPathSetupTypeCapabilityBasic, testPathSetupTypeCapabilityBasicBytes},
		"WithSub": {testPathSetupTypeCapabilityWithSubTLV, testPathSetupTypeCapabilityWithSubTLVBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestPathSetupTypeCapability_Len(t *testing.T) {
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

func TestPathSetupTypeCapability_Serialize_SubTLVLengthBoundary(t *testing.T) {
	t.Parallel()

	newSubTLVs := func(n int) []TLVInterface {
		subTLVs := make([]TLVInterface, n)
		for i := range subTLVs {
			subTLVs[i] = &SRPCECapability{}
		}
		return subTLVs
	}

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &PathSetupTypeCapability{SubTLVs: newSubTLVs(8191)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65532), binary.BigEndian.Uint16(raw[TLVLengthOffset:TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &PathSetupTypeCapability{SubTLVs: newSubTLVs(8192)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

func TestPathSetupTypeCapability_Serialize_SubTLVError(t *testing.T) {
	t.Parallel()

	tlv := &PathSetupTypeCapability{SubTLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := tlv.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestPathSetupTypeCapability_SubCapabilities(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    *PathSetupTypeCapability
		expected []CapabilityInterface
	}{
		"NoSubTLVs": {
			&PathSetupTypeCapability{},
			[]CapabilityInterface{},
		},
		"SRAndSRv6": {
			&PathSetupTypeCapability{SubTLVs: []TLVInterface{
				&SRPCECapability{HasUnlimitedMaxSIDDepth: true},
				&SRv6PCECapability{IsNAISupported: true},
			}},
			[]CapabilityInterface{
				&SRPCECapability{HasUnlimitedMaxSIDDepth: true},
				&SRv6PCECapability{IsNAISupported: true},
			},
		},
		"KeepsUnknownTLV": {
			&PathSetupTypeCapability{SubTLVs: []TLVInterface{
				&UnknownTLV{Typ: TLVType(0x1234), Value: []byte{0x01}},
			}},
			[]CapabilityInterface{
				&UnknownTLV{Typ: TLVType(0x1234), Value: []byte{0x01}},
			},
		},
		"DropsNonCapabilityTLV": {
			&PathSetupTypeCapability{SubTLVs: []TLVInterface{
				&PathSetupType{PathSetupType: PathSetupTypeSRTE},
				&SRPCECapability{HasUnlimitedMaxSIDDepth: true},
			}},
			[]CapabilityInterface{
				&SRPCECapability{HasUnlimitedMaxSIDDepth: true},
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.expected, c.input.SubCapabilities())
		})
	}
}

func TestPathSetupTypeCapability_HasPathSetupType(t *testing.T) {
	t.Parallel()

	tlv := &PathSetupTypeCapability{PathSetupTypes: Psts{PathSetupTypeSRTE}}

	assert.True(t, tlv.HasPathSetupType(PathSetupTypeSRTE))
	assert.False(t, tlv.HasPathSetupType(PathSetupTypeSRv6TE))
}

func TestAssocType_String(t *testing.T) {
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
			actual := tt.input.String()
			assert.Equal(t, tt.expected, actual, "unexpected AssocType.String() result for '%s'", name)
		})
	}
}

// Reference determines whether a type is draft-only or unassigned.
func TestAssocType_StringWithReference(t *testing.T) {
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
			assert.Equal(t, tt.expected, tt.input.StringWithReference(), "unexpected AssocType.StringWithReference() result for '%s'", name)
		})
	}
}

// Test data for ExtendedAssociationID.
var (
	testIPv4ExtendedAssociationID = NewExtendedAssociationID(1, netip.MustParseAddr("127.0.0.1"))
	testIPv6ExtendedAssociationID = NewExtendedAssociationID(1, netip.MustParseAddr(testIPv6Addr1))

	testIPv4ExtendedAssociationIDBytes = []byte{
		byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xff), 0x00, 0x08,
		0x00, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
	}
	testIPv6ExtendedAssociationIDBytes = []byte{
		byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xff), 0x00, 0x14,
		0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	testExtendedAssociationIDTooShort = []byte{
		byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xff), 0x00,
	}
	testExtendedAssociationIDInvalidLen = []byte{
		byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xff), 0x00, 0x10,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	testExtendedAssociationIDUnsupportedLen = []byte{
		byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xff), 0x00, 0x0f,
		0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01,
	}
	testExtendedAssociationIDValueTooShort = []byte{
		byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xff), 0x00, 0x03,
		0x00, 0x00, 0x00,
	}
)

func TestExtendedAssociationID_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"IPv4":                  {testIPv4ExtendedAssociationIDBytes, testIPv4ExtendedAssociationID, false},
		"IPv6":                  {testIPv6ExtendedAssociationIDBytes, testIPv6ExtendedAssociationID, false},
		"TooShort":              {testExtendedAssociationIDTooShort, nil, true},
		"ValueTooShortForColor": {testExtendedAssociationIDValueTooShort, nil, true},
		"InvalidLength":         {testExtendedAssociationIDInvalidLen, nil, true},
		"UnsupportedLength":     {testExtendedAssociationIDUnsupportedLen, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &ExtendedAssociationID{} })
}

func TestExtendedAssociationID_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"IPv4":            {testIPv4ExtendedAssociationID, testIPv4ExtendedAssociationIDBytes},
		"IPv6":            {testIPv6ExtendedAssociationID, testIPv6ExtendedAssociationIDBytes},
		"InvalidEndpoint": {&ExtendedAssociationID{Color: 1}, nil}, // Endpoint zero-value
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual, err := tt.input.Serialize()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestExtendedAssociationID_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"IPv4Length":        {testIPv4ExtendedAssociationID, TLVValueOffset + TLVExtendedAssociationIDIPv4ValueLength},
		"IPv6Length":        {testIPv6ExtendedAssociationID, TLVValueOffset + TLVExtendedAssociationIDIPv6ValueLength},
		"UnsupportedLength": {&ExtendedAssociationID{Color: 1}, 0},
	}
	runTLVLenTests(t, cases)
}

func TestExtendedAssociationIDIPv4Juniper_Type(t *testing.T) {
	t.Parallel()

	tlv := &ExtendedAssociationIDIPv4Juniper{}
	assert.Equal(t, TLVExtendedAssociationIDIPv4Juniper, tlv.Type())
}

func TestExtendedAssociationIDIPv4Juniper_Serialize(t *testing.T) {
	expectedIPv4 := append([]byte(nil), testIPv4ExtendedAssociationIDBytes...)
	expectedIPv4[0], expectedIPv4[1] = 0xff, 0xe3 // type=0xffe3, value layout unchanged

	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"IPv4": {
			&ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv4ExtendedAssociationID},
			expectedIPv4,
		},
		"IPv6Rejected": {
			&ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv6ExtendedAssociationID},
			nil,
		},
	}
	runTLVSerializeTests(t, cases)
}

func TestExtendedAssociationIDIPv4Juniper_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"IPv4": {
			&ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv4ExtendedAssociationID},
			uint16(testIPv4ExtendedAssociationID.Len()),
		},
		"IPv6Rejected": {
			&ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv6ExtendedAssociationID},
			0,
		},
	}
	runTLVLenTests(t, cases)
}

// Verifies Juniper vendor TLVs preserve structured logging fields.
var testExtendedAssociationIDIPv4JuniperIPv6Bytes = func() []byte {
	b := append([]byte(nil), testIPv6ExtendedAssociationIDBytes...)
	b[0], b[1] = 0xff, 0xe3 // type=0xffe3, IPv6 value layout (length 20)
	return b
}()

func TestExtendedAssociationIDIPv4Juniper_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	input := append([]byte(nil), testIPv4ExtendedAssociationIDBytes...)
	input[0], input[1] = 0xff, 0xe3 // type=0xffe3, value layout unchanged

	cases := map[string]TLVTestCase{
		"IPv4Juniper": {
			input,
			&ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv4ExtendedAssociationID},
			false,
		},
		"IPv6Rejected": {
			testExtendedAssociationIDIPv4JuniperIPv6Bytes,
			nil,
			true,
		},
		"TooShort": {
			[]byte{0xff, 0xe3, 0x00},
			nil,
			true,
		},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &ExtendedAssociationIDIPv4Juniper{} })
}

// Test data for AssocTypeList.
var (
	// AssocTypeList with two entries.
	testAssocTypeList = &AssocTypeList{
		AssocTypes: []AssocType{AssocTypePathProtectionAssociation, AssocTypeSRPolicyAssociation},
	}
	// AssocTypeList with a single entry (requires padding to 4-byte alignment).
	testAssocTypeListSingle = &AssocTypeList{
		AssocTypes: []AssocType{AssocTypePathProtectionAssociation},
	}
	// AssocTypeList with four entries (already 4-byte aligned).
	testAssocTypeListFour = &AssocTypeList{
		AssocTypes: []AssocType{
			AssocTypePathProtectionAssociation,
			AssocTypeDisjointAssociation,
			AssocTypePolicyAssociation,
			AssocTypeSRPolicyAssociation,
		},
	}
	// Empty AssocTypeList.
	testAssocTypeListEmpty = &AssocTypeList{AssocTypes: []AssocType{}}

	// Bytes for testAssocTypeList (2 entries = 4 bytes value, no padding needed).
	testAssocTypeListBytes = []byte{
		0x00, 0x23, 0x00, 0x04, // Type, Length
		0x00, 0x01, 0x00, 0x06, // Value
	}
	// Bytes for Serialize test: 1 entry + padding to 4-byte alignment.
	testAssocTypeListSingleBytesWithPadding = []byte{
		0x00, 0x23, 0x00, 0x02, // Type, Length
		0x00, 0x01, 0x00, 0x00, // Value + padding
	}
	// Bytes for DecodeFromBytes test: 1 entry without padding.
	testAssocTypeListSingleBytesWithoutPadding = []byte{
		0x00, 0x23, 0x00, 0x02, // Type, Length
		0x00, 0x01, // Value only
	}
	// TLV with odd-length value (should fail decode).
	testAssocTypeListOddLength = []byte{
		0x00, 0x23, 0x00, 0x03,
		0x00, 0x01, 0x00,
	}
	// Truncated header.
	testAssocTypeListTruncatedHeader = []byte{
		0x00, 0x23, 0x00,
	}
)

func TestAssocTypeList_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidTwoEntries":  {testAssocTypeListBytes, testAssocTypeList, false},
		"ValidSingleEntry": {testAssocTypeListSingleBytesWithoutPadding, testAssocTypeListSingle, false},
		"OddLengthValue":   {testAssocTypeListOddLength, nil, true},
		"TruncatedHeader":  {testAssocTypeListTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &AssocTypeList{} })
}

func TestAssocTypeList_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"TwoEntries":  {testAssocTypeList, testAssocTypeListBytes},
		"SingleEntry": {testAssocTypeListSingle, testAssocTypeListSingleBytesWithPadding},
	}
	runTLVSerializeTests(t, cases)
}

func TestAssocTypeList_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"TwoEntriesLen":  {testAssocTypeList, TLVValueOffset + 4},       // 2*2 = 4, already aligned
		"SingleEntryLen": {testAssocTypeListSingle, TLVValueOffset + 4}, // 1*2 + 2 pad = 4
		"FourEntriesLen": {testAssocTypeListFour, TLVValueOffset + 8},   // 4*2 = 8, already aligned
		"EmptyLen":       {testAssocTypeListEmpty, TLVValueOffset + 0},  // 0 entries = 0 bytes
	}
	runTLVLenTests(t, cases)
}

func TestAssocTypeList_Serialize_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &AssocTypeList{AssocTypes: make([]AssocType, 32767)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65534), binary.BigEndian.Uint16(raw[TLVLengthOffset:TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &AssocTypeList{AssocTypes: make([]AssocType, 32768)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

// Test data for SRPolicyCandidatePathIdentifier.
var (
	testSRPolicyCPathIDIPv4 = &SRPolicyCandidatePathIdentifier{
		ProtocolOrigin: ProtocolOriginPCEP,
		OriginatorASN:  65000,
		OriginatorAddr: netip.AddrFrom4([4]byte{192, 0, 2, 1}), // IPv4 originator
		Discriminator:  1,
	}
	testSRPolicyCPathIDIPv6 = &SRPolicyCandidatePathIdentifier{
		ProtocolOrigin: ProtocolOriginPCEP,
		OriginatorASN:  65000,
		OriginatorAddr: netip.MustParseAddr(testIPv6Addr1), // IPv6 originator
		Discriminator:  2,
	}

	testSRPolicyCPathIDIPv4Bytes = []byte{
		0x00, 0x39, 0x00, 0x1c, // type=0x0039, len=28
		0x0a, 0x00, 0x00, 0x00, // protocol=0x0a + mbz
		0x00, 0x00, 0xfd, 0xe8, // ASN=65000
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originator addr padding
		0xc0, 0x00, 0x02, 0x01, // IPv4 addr
		0x00, 0x00, 0x00, 0x01, // discriminator=1
	}

	testSRPolicyCPathIDIPv6Bytes = []byte{
		0x00, 0x39, 0x00, 0x1c, // type=0x0039, len=28
		0x0a, 0x00, 0x00, 0x00, // protocol + mbz
		0x00, 0x00, 0xfd, 0xe8, // ASN=65000
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IPv6 addr
		0x00, 0x00, 0x00, 0x02, // discriminator=2
	}

	testSRPolicyCPathIDTooShort        = []byte{0x00, 0x39, 0x00, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // Less than 16 bytes for OriginatorAddr
	testSRPolicyCPathIDTruncatedHeader = []byte{0x00, 0x39, 0x00}                                                                   // Truncated header (less than 4 bytes)

	testSRPolicyCPathIDInvalid = &SRPolicyCandidatePathIdentifier{
		ProtocolOrigin: ProtocolOriginPCEP,
		OriginatorAddr: netip.Addr{}, // zero value, IsValid() == false
		Discriminator:  1,
	}
	testSRPolicyCPathIDInvalidBytes = []byte{
		0x00, 0x39, 0x00, 0x1c, // type + length
		0x0a, 0x00, 0x00, 0x00, // protocol + mbz
		0x00, 0x00, 0x00, 0x00, // ASN
		0x00, 0x00, 0x00, 0x00, // originator addr (16 bytes)
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, // discriminator
	}

	// Protocol-Origin other than PCEP must survive decode and re-serialize unchanged.
	testSRPolicyCPathIDNonPCEP = &SRPolicyCandidatePathIdentifier{
		ProtocolOrigin: 0x14, // BGP SR Policy origin defined by RFC
		OriginatorASN:  65001,
		OriginatorAddr: netip.AddrFrom4([4]byte{192, 0, 2, 3}),
		Discriminator:  3,
	}
	testSRPolicyCPathIDNonPCEPBytes = []byte{
		0x00, 0x39, 0x00, 0x1c, // type=0x0039, len=28
		0x14, 0x00, 0x00, 0x00, // protocol origin=0x14 + mbz
		0x00, 0x00, 0xfd, 0xe9, // ASN=65001
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originator addr padding
		0xc0, 0x00, 0x02, 0x03, // IPv4 addr
		0x00, 0x00, 0x00, 0x03, // discriminator=3
	}
)

func TestSRPolicyCandidatePathIdentifier_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidIPv4":             {testSRPolicyCPathIDIPv4Bytes, testSRPolicyCPathIDIPv4, false},
		"ValidIPv6":             {testSRPolicyCPathIDIPv6Bytes, testSRPolicyCPathIDIPv6, false},
		"NonPCEPProtocolOrigin": {testSRPolicyCPathIDNonPCEPBytes, testSRPolicyCPathIDNonPCEP, false},
		"TooShort":              {testSRPolicyCPathIDTooShort, nil, true},
		"TruncatedHeader":       {testSRPolicyCPathIDTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SRPolicyCandidatePathIdentifier{} })
}

func TestSRPolicyCandidatePathIdentifier_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"SerializeIPv4":                  {testSRPolicyCPathIDIPv4, testSRPolicyCPathIDIPv4Bytes},
		"SerializeIPv6":                  {testSRPolicyCPathIDIPv6, testSRPolicyCPathIDIPv6Bytes},
		"SerializeNonPCEPProtocolOrigin": {testSRPolicyCPathIDNonPCEP, testSRPolicyCPathIDNonPCEPBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPolicyCandidatePathIdentifier_Serialize_Invalid(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ZeroAddr": {testSRPolicyCPathIDInvalid, testSRPolicyCPathIDInvalidBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPolicyCandidatePathIdentifier_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidLen": {testSRPolicyCPathIDIPv4, TLVValueOffset + TLVSRPolicyCPathIDValueLength},
	}
	runTLVLenTests(t, cases)
}

// Protocol-Origin must survive Decode -> Serialize without being rewritten to PCEP.
func TestSRPolicyCandidatePathIdentifier_ProtocolOriginRoundTrip(t *testing.T) {
	t.Parallel()

	for _, origin := range []uint8{0x00, 0x0a, 0x14, 0x1e, 0xff} {
		t.Run(fmt.Sprintf("Origin_0x%02x", origin), func(t *testing.T) {
			t.Parallel()

			raw := append([]byte(nil), testSRPolicyCPathIDIPv4Bytes...)
			raw[TLVValueOffset+SRPolicyCPathIDProtocolOriginOffset] = origin

			var got SRPolicyCandidatePathIdentifier
			require.NoError(t, got.DecodeFromBytes(raw), "DecodeFromBytes failed")
			assert.Equal(t, origin, got.ProtocolOrigin, "ProtocolOrigin not preserved on decode")

			gotData, err := got.Serialize()
			require.NoError(t, err)
			assert.Equal(t, raw, gotData, "re-serialized bytes differ")
		})
	}
}

func TestSRPolicyCandidatePathIdentifierJuniper_Type(t *testing.T) {
	t.Parallel()

	tlv := &SRPolicyCandidatePathIdentifierJuniper{}
	assert.Equal(t, TLVSRPolicyCPathIDJuniper, tlv.Type())
}

func TestSRPolicyCandidatePathIdentifierJuniper_Serialize(t *testing.T) {
	tlv := &SRPolicyCandidatePathIdentifierJuniper{
		ProtocolOrigin: testSRPolicyCPathIDIPv4.ProtocolOrigin,
		OriginatorASN:  testSRPolicyCPathIDIPv4.OriginatorASN,
		OriginatorAddr: testSRPolicyCPathIDIPv4.OriginatorAddr,
		Discriminator:  testSRPolicyCPathIDIPv4.Discriminator,
	}

	expected := append([]byte(nil), testSRPolicyCPathIDIPv4Bytes...)
	expected[0], expected[1] = 0xff, 0xe4 // type=0xffe4, value layout unchanged

	actual, err := tlv.Serialize()
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestSRPolicyCandidatePathIdentifierJuniper_Len(t *testing.T) {
	tlv := &SRPolicyCandidatePathIdentifierJuniper{
		ProtocolOrigin: testSRPolicyCPathIDIPv4.ProtocolOrigin,
		OriginatorASN:  testSRPolicyCPathIDIPv4.OriginatorASN,
		OriginatorAddr: testSRPolicyCPathIDIPv4.OriginatorAddr,
		Discriminator:  testSRPolicyCPathIDIPv4.Discriminator,
	}
	assert.Equal(t, testSRPolicyCPathIDIPv4.Len(), tlv.Len())
}

// Verifies Juniper vendor TLVs preserve structured logging fields.
var (
	testSRPolicyCPathPreference = &SRPolicyCandidatePathPreference{Preference: 100}

	// Serialized bytes for testSRPolicyCPathPreference.
	testSRPolicyCPathPreferenceBytes = []byte{
		0x00, 0x3b, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x64,
	}
	// Truncated input (invalid length = 3).
	testSRPolicyCPathPreferenceTruncated = []byte{
		0x00, 0x3b, 0x00, 0x03,
		0x00, 0x00, 0x00,
	}
	// Truncated header.
	testSRPolicyCPathPreferenceTruncatedHeader = []byte{
		0x00, 0x3b, 0x00,
	}
)

func TestSRPolicyCandidatePathPreference_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidPreference": {testSRPolicyCPathPreferenceBytes, testSRPolicyCPathPreference, false},
		"InvalidLength":   {testSRPolicyCPathPreferenceTruncated, nil, true},
		"TruncatedHeader": {testSRPolicyCPathPreferenceTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SRPolicyCandidatePathPreference{} })
}

func TestSRPolicyCandidatePathPreference_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidPreference": {testSRPolicyCPathPreference, testSRPolicyCPathPreferenceBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPolicyCandidatePathPreference_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidLen": {testSRPolicyCPathPreference, TLVValueOffset + TLVSRPolicyCPathPreferenceValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestSRPolicyCandidatePathPreferenceJuniper_Type(t *testing.T) {
	t.Parallel()

	tlv := &SRPolicyCandidatePathPreferenceJuniper{}
	assert.Equal(t, TLVSRPolicyCPathPreferenceJuniper, tlv.Type())
}

func TestSRPolicyCandidatePathPreferenceJuniper_Serialize(t *testing.T) {
	tlv := &SRPolicyCandidatePathPreferenceJuniper{
		Preference: testSRPolicyCPathPreference.Preference,
	}

	expected := append([]byte(nil), testSRPolicyCPathPreferenceBytes...)
	expected[0], expected[1] = 0xff, 0xe5 // type=0xffe5, value layout unchanged

	actual, err := tlv.Serialize()
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestSRPolicyCandidatePathPreferenceJuniper_Len(t *testing.T) {
	tlv := &SRPolicyCandidatePathPreferenceJuniper{
		Preference: testSRPolicyCPathPreference.Preference,
	}
	assert.Equal(t, testSRPolicyCPathPreference.Len(), tlv.Len())
}

// Verifies Juniper vendor TLVs preserve structured logging fields.
func TestSRPolicyCandidatePathPreferenceJuniper_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	input := append([]byte(nil), testSRPolicyCPathPreferenceBytes...)
	input[0], input[1] = 0xff, 0xe5 // type=0xffe5, value layout unchanged

	cases := map[string]TLVTestCase{
		"PreferenceJuniper": {
			input,
			&SRPolicyCandidatePathPreferenceJuniper{Preference: testSRPolicyCPathPreference.Preference},
			false,
		},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SRPolicyCandidatePathPreferenceJuniper{} })
}

// Test data for Color.
var (
	testColor = &Color{Color: 255}

	// Serialized bytes for testColor.
	testColorBytes = []byte{
		0x00, 0x43, 0x00, 0x04,
		0x00, 0x00, 0x00, 0xff,
	}
	// Truncated input (invalid length = 3).
	testColorTruncated = []byte{
		0x00, 0x43, 0x00, 0x03,
		0x00, 0x00, 0x00,
	}
	// Truncated header.
	testColorTruncatedHeader = []byte{
		0x00, 0x43, 0x00,
	}
)

func TestColor_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidColor":      {testColorBytes, testColor, false},
		"InvalidLength":   {testColorTruncated, nil, true},
		"TruncatedHeader": {testColorTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &Color{} })
}

func TestColor_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidColor": {testColor, testColorBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestColor_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidLen": {testColor, TLVValueOffset + TLVColorValueLength},
	}
	runTLVLenTests(t, cases)
}

// Test data for UnknownTLV.
var (
	// Standard 4-byte UnknownTLV.
	testUnknownTLV = &UnknownTLV{
		Typ:   TLVType(0xffff),
		Value: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	// 3-byte value (odd → 1 byte padding required).
	testUnknownTLVOddLength = &UnknownTLV{
		Typ:   TLVType(0xffff),
		Value: []byte{0x01, 0x02, 0x03},
	}

	// Serialized TLV bytes.
	testUnknownTLVBytes           = []byte{0xff, 0xff, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef}
	testUnknownTLVOddLengthBytes  = []byte{0xff, 0xff, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00}
	testUnknownTLVTruncatedHeader = []byte{0xff, 0xff, 0x00}
	testUnknownTLVTruncatedValue  = []byte{0xff, 0xff, 0x00, 0x08, 0x01, 0x02}
)

func TestUnknownTLV_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidUnknownTLV": {testUnknownTLVBytes, testUnknownTLV, false},
		"TruncatedHeader": {testUnknownTLVTruncatedHeader, nil, true},
		"TruncatedValue":  {testUnknownTLVTruncatedValue, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &UnknownTLV{} })
}

func TestUnknownTLV_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"AlignedValue":   {testUnknownTLV, testUnknownTLVBytes},
		"UnalignedValue": {testUnknownTLVOddLength, testUnknownTLVOddLengthBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestUnknownTLV_Serialize_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &UnknownTLV{Value: make([]byte, 65535)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Equal(t, uint16(65535), binary.BigEndian.Uint16(raw[TLVLengthOffset:TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &UnknownTLV{Value: make([]byte, 65536)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

func TestUnknownTLV_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"AlignedLen":   {testUnknownTLV, TLVValueOffset + 4},          // 4-byte value
		"UnalignedLen": {testUnknownTLVOddLength, TLVValueOffset + 4}, // 3-byte value + 1 pad = 4
	}
	runTLVLenTests(t, cases)
}

func TestUnknownTLV_Len_DerivedFromValue(t *testing.T) {
	tlv := &UnknownTLV{Value: []byte{0x01, 0x02, 0x03}}
	assert.Equal(t, TLVValueOffset+4, tlv.Len(), "Len() must reflect len(Value) plus padding")
}

// Test data for DecodeTLV / DecodeTLVs.
var (
	testDecodeStatefulLSPUpdateBytes = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x01)
	testDecodeUnknownTLVBytes        = append(tlvHeader(TLVType(0xffff), 4), 0xde, 0xad, 0xbe, 0xef)
	testDecodeTruncatedHeader        = []byte{0x00}
	testDecodeStatefulInvalidBody    = append(tlvHeader(TLVStatefulPCECapability, 3), 0x00, 0x00, 0x00)
	testDecodeUnknownTruncatedValue  = []byte{0xff, 0xff, 0x00, 0x08, 0x01, 0x02}
	testDecodeMultipleTLVs           = append(
		append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x01),
		append(tlvHeader(TLVSymbolicPathName, 4), 'T', 'e', 's', 't')...,
	)
	testDecodeTruncatedValue   = []byte{0x00, 0x10, 0x00, 0x08, 0x00, 0x00}
	testDecodeTruncatedPadding = []byte{0x00, 0xff, 0x00, 0x03, 0x01, 0x02, 0x03}
)

func TestDecodeTLV(t *testing.T) {
	cases := map[string]struct {
		input   []byte
		wantErr bool
		wantTyp TLVType
	}{
		"KnownTLV_StatefulPCECapability": {testDecodeStatefulLSPUpdateBytes, false, TLVStatefulPCECapability},
		"UnknownTLV":                     {testDecodeUnknownTLVBytes, false, TLVType(0xffff)},
		"TooShort":                       {testDecodeTruncatedHeader, true, 0},
		"KnownTLV_InvalidBody":           {testDecodeStatefulInvalidBody, true, 0},
		"UnknownTLV_TruncatedValue":      {testDecodeUnknownTruncatedValue, true, 0},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			tlv, err := DecodeTLV(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "expected error for '%s'", name)
			} else {
				require.NoError(t, err, "unexpected error for '%s'", name)
				assert.Equal(t, tt.wantTyp, tlv.Type(), "TLV type mismatch for '%s'", name)
			}
		})
	}
}

func TestDecodeTLVs(t *testing.T) {
	invalidPaddingBytes := func() []byte {
		valueLen := 5
		header := tlvHeader(0xFFFF, uint16(valueLen))
		body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		tlv := slices.Concat(header, body)
		tlv = append(tlv, 0xFF, 0x00, 0x00) // invalid padding (should be 0x00)
		return tlv
	}()

	cases := map[string]struct {
		input   []byte
		wantErr bool
		wantLen int
		errMsg  string
	}{
		"Empty":               {[]byte{}, false, 0, ""},
		"SingleKnownTLV":      {testDecodeStatefulLSPUpdateBytes, false, 1, ""},
		"MultipleTLVs":        {testDecodeMultipleTLVs, false, 2, ""},
		"TruncatedTLVHeader":  {[]byte{0x00, 0x10, 0x00}, true, 0, "truncated TLV header"},
		"TruncatedTLVValue":   {testDecodeTruncatedValue, true, 0, "truncated TLV value"},
		"TruncatedTLVPadding": {testDecodeTruncatedPadding, true, 0, "truncated TLV padding"},
		"InvalidKnownTLVBody": {append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x00), false, 1, ""},
		"InvalidPadding":      {invalidPaddingBytes, true, 0, "invalid TLV padding"},
		"JuniperExtendedAssociationIDIPv6Rejected": {
			testExtendedAssociationIDIPv4JuniperIPv6Bytes, true, 0, "invalid value length",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			tlvs, err := DecodeTLVs(tt.input)
			if tt.wantErr {
				require.Error(t, err, "expected error for '%s'", name)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "error message mismatch for '%s'", name)
				}
				assert.Nil(t, tlvs)
			} else {
				require.NoError(t, err, "unexpected error for '%s'", name)
				assert.Len(t, tlvs, tt.wantLen, "TLV count mismatch for '%s'", name)
			}
		})
	}
}

func TestDecodeTLVs_SubTLV(t *testing.T) {
	fixedPart := make([]byte, PathSetupTypeCapabilityFixedPartLength)
	fixedPart[PathSetupTypeCapabilityPSTCountOffset] = 0x01 // Set PST count in fixed part
	pathSetupType := []byte{0x00}
	subTLV := append(tlvHeader(TLVStatefulPCECapability, 4), 0x01, 0x02)
	value := slices.Concat(fixedPart, pathSetupType, subTLV)
	header := tlvHeader(TLVPathSetupTypeCapability, uint16(len(value)))
	data := slices.Concat(header, value)

	cases := map[string]struct {
		input   []byte
		wantErr bool
	}{
		"InvalidSubTLV": {data, true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeTLVs(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "expected error for '%s'", name)
			} else {
				assert.NoError(t, err, "unexpected error for '%s'", name)
			}
		})
	}
}

// Test data for SRv6PCECapability.
var (
	testSRv6PCECapability            = NewSRv6PCECapability(true)
	testSRv6PCECapabilityBytes       = append(tlvHeader(TLVSRv6PCECapability, 4), 0x00, 0x00, 0x00, 0x02)
	testSRv6PCECapabilityNoNAIBytes  = append(tlvHeader(TLVSRv6PCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	testSRv6PCECapabilityExtended    = append(tlvHeader(TLVSRv6PCECapability, 8), 0x00, 0x00, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef)
	testSRv6PCECapabilityShortLength = append(tlvHeader(TLVSRv6PCECapability, 3), 0x00, 0x00, 0x00)
	testSRv6PCECapabilityTruncated   = append(tlvHeader(TLVSRv6PCECapability, 4), 0x00, 0x00)
	testSRv6PCECapabilityNoNAI       = &SRv6PCECapability{}
)

func TestSRv6PCECapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidSRv6PCECapability":          {testSRv6PCECapabilityBytes, testSRv6PCECapability, false},
		"ValidSRv6PCECapabilityNoNAI":     {testSRv6PCECapabilityNoNAIBytes, testSRv6PCECapabilityNoNAI, false},
		"ExtendedLengthSRv6PCECapability": {testSRv6PCECapabilityExtended, testSRv6PCECapability, false},
		"ShortLengthSRv6PCECapability":    {testSRv6PCECapabilityShortLength, nil, true},
		"TruncatedSRv6PCECapability":      {testSRv6PCECapabilityTruncated, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SRv6PCECapability{} })
}

func TestSRv6PCECapability_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidSRv6PCECapability":      {testSRv6PCECapability, testSRv6PCECapabilityBytes},
		"ValidSRv6PCECapabilityNoNAI": {testSRv6PCECapabilityNoNAI, testSRv6PCECapabilityNoNAIBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRv6PCECapability_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidSRv6PCECapabilityLength": {testSRv6PCECapability, TLVValueOffset + TLVSRv6PCECapabilityValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestSRv6PCECapability_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*SRv6PCECapability{
		"NAISupported":    NewSRv6PCECapability(true),
		"NAINotSupported": NewSRv6PCECapability(false),
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := original.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, data, original.Len(), "Len() must match serialized size")

			decoded, err := DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*SRv6PCECapability)
			require.Truef(t, ok, "expected *SRv6PCECapability, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			gotData, err := got.Serialize()
			require.NoError(t, err, "Serialize failed")
			assert.Equal(t, data, gotData, "re-serialized bytes differ")
		})
	}
}

// Test data for MultipathCapability.
var (
	testMultipathCapability = NewMultipathCapability(8, true, true, true, true)
	// MaxMultipaths=8 (0x0008), Flags=W|O|F|C = 0x001D.
	testMultipathCapabilityBytes        = append(tlvHeader(TLVMultipathCap, 4), 0x00, 0x08, 0x00, 0x1d)
	testMultipathCapabilityNoFlags      = NewMultipathCapability(1, false, false, false, false)
	testMultipathCapabilityNoFlagsBytes = append(tlvHeader(TLVMultipathCap, 4), 0x00, 0x01, 0x00, 0x00)
	testMultipathCapabilityTruncated    = append(tlvHeader(TLVMultipathCap, 4), 0x00, 0x08)
	testMultipathCapabilityInvalidLen   = append(tlvHeader(TLVMultipathCap, 8), 0x00, 0x08, 0x00, 0x0f, 0xde, 0xad, 0xbe, 0xef)
)

func TestMultipathCapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidMultipathCapabilityAllFlags": {testMultipathCapabilityBytes, testMultipathCapability, false},
		"ValidMultipathCapabilityNoFlags":  {testMultipathCapabilityNoFlagsBytes, testMultipathCapabilityNoFlags, false},
		"TruncatedMultipathCapability":     {testMultipathCapabilityTruncated, nil, true},
		"InvalidLengthMultipathCapability": {testMultipathCapabilityInvalidLen, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &MultipathCapability{} })
}

func TestMultipathCapability_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidMultipathCapabilityAllFlags": {testMultipathCapability, testMultipathCapabilityBytes},
		"ValidMultipathCapabilityNoFlags":  {testMultipathCapabilityNoFlags, testMultipathCapabilityNoFlagsBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestMultipathCapability_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidMultipathCapabilityLength": {testMultipathCapability, TLVValueOffset + TLVMultipathCapValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestMultipathCapability_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*MultipathCapability{
		"AllFlags":         NewMultipathCapability(8, true, true, true, true),
		"NoFlags":          NewMultipathCapability(1, false, false, false, false),
		"OnlyWeighted":     NewMultipathCapability(2, true, false, false, false),
		"OnlyOpposite":     NewMultipathCapability(3, false, true, false, false),
		"OnlyForwardClass": NewMultipathCapability(4, false, false, true, false),
		"OnlyComposite":    NewMultipathCapability(7, false, false, false, true),
		"MaxUint16":        NewMultipathCapability(0xFFFF, true, true, true, true),
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := original.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, data, original.Len(), "Len() must match serialized size")

			decoded, err := DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*MultipathCapability)
			require.Truef(t, ok, "expected *MultipathCapability, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			gotData, err := got.Serialize()
			require.NoError(t, err, "Serialize failed")
			assert.Equal(t, data, gotData, "re-serialized bytes differ")
		})
	}
}
