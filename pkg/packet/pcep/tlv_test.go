// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep_test

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

	"github.com/nttcom/pola/pkg/packet/pcep"
)

const pstDescriptionSRTE = "Traffic engineering path is set up using Segment Routing (0x01) [RFC8664]"

func TestTLVType_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		tlvType  pcep.TLVType
		expected string
	}{
		"StatefulPCECapability": {pcep.TLVStatefulPCECapability, "STATEFUL-PCE-CAPABILITY (0x0010)"},
		"IPv4LSPIdentifiers":    {pcep.TLVIPv4LSPIdentifiers, "IPV4-LSP-IDENTIFIERS (0x0012)"},
		"UnknownType":           {pcep.TLVType(0xdead), "Unknown TLV (0xdead)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := tt.tlvType.String()
			assert.Equal(t, tt.expected, actual, "unexpected TLVType.String() result")
		})
	}
}

type TLVTestCase struct {
	input    []byte
	expected pcep.TLVInterface
	wantErr  bool
}

func runTLVDecodeTests(t *testing.T, cases map[string]TLVTestCase, constructor func() pcep.TLVInterface) {
	t.Helper()

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Helper()
			t.Parallel()

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
	input    pcep.TLVInterface
	expected []byte
},
) {
	t.Helper()

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Helper()
			t.Parallel()

			actual, err := tt.input.Serialize()
			require.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, actual, "serialized value mismatch for '%s'", name)
		})
	}
}

func runTLVLenTests(t *testing.T, cases map[string]struct {
	input    pcep.TLVInterface
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

// mustSerializeTLV serializes a TLV for use in test fixtures.
func mustSerializeTLV(tlv pcep.TLVInterface) []byte {
	b, err := tlv.Serialize()
	if err != nil {
		panic(err)
	}

	return b
}

func tlvHeader(tlvType pcep.TLVType, length uint16) []byte {
	return []byte{byte(tlvType >> 8), byte(tlvType & 0xff), byte(length >> 8), byte(length & 0xff)}
}

var (
	// Enterprise Number only, no Enterprise-Specific Information (Juniper sends this in Open).
	testVendorInformationJuniper      = pcep.NewVendorInformation(pcep.EnterpriseNumberJuniper, nil)
	testVendorInformationJuniperBytes = append(tlvHeader(pcep.TLVVendorInformation, 4), 0x00, 0x00, 0x0a, 0x4c)
	// Enterprise-Specific Information already 4-byte aligned.
	testVendorInformationWithInfo      = pcep.NewVendorInformation(pcep.EnterpriseNumberJuniper, []byte{0xde, 0xad, 0xbe, 0xef})
	testVendorInformationWithInfoBytes = append(tlvHeader(pcep.TLVVendorInformation, 8), 0x00, 0x00, 0x0a, 0x4c, 0xde, 0xad, 0xbe, 0xef)
	// 2-byte Enterprise-Specific Information (value length 6 → 2 bytes padding).
	testVendorInformationUnaligned      = pcep.NewVendorInformation(pcep.EnterpriseNumberCisco, []byte{0x01, 0x02})
	testVendorInformationUnalignedBytes = append(tlvHeader(pcep.TLVVendorInformation, 6), 0x00, 0x00, 0x00, 0x09, 0x01, 0x02, 0x00, 0x00)
	// Enterprise Number not present in enterpriseNumberNames.
	testVendorInformationUnknownEnterprise = pcep.NewVendorInformation(12345, nil)
	// Value shorter than the mandatory Enterprise Number.
	testVendorInformationTooShort        = append(tlvHeader(pcep.TLVVendorInformation, 2), 0x00, 0x00)
	testVendorInformationTruncatedValue  = append(tlvHeader(pcep.TLVVendorInformation, 8), 0x00, 0x00, 0x0a, 0x4c)
	testVendorInformationTruncatedHeader = []byte{0x00, 0x07, 0x00}
)

func TestVendorInformation_DecodeFromBytes(t *testing.T) {
	t.Parallel()

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
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.VendorInformation{} })
}

func TestVendorInformation_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"EnterpriseNumberOnly":                   {testVendorInformationJuniper, testVendorInformationJuniperBytes},
		"WithEnterpriseSpecificInformation":      {testVendorInformationWithInfo, testVendorInformationWithInfoBytes},
		"UnalignedEnterpriseSpecificInformation": {testVendorInformationUnaligned, testVendorInformationUnalignedBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestVendorInformation_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"EnterpriseNumberOnly":                   {testVendorInformationJuniper, pcep.TLVValueOffset + 4},
		"WithEnterpriseSpecificInformation":      {testVendorInformationWithInfo, pcep.TLVValueOffset + 8},
		"UnalignedEnterpriseSpecificInformation": {testVendorInformationUnaligned, pcep.TLVValueOffset + 8}, // 6-byte value + 2 pad
	}
	runTLVLenTests(t, cases)
}

func TestVendorInformation_Serialize_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.VendorInformation{EnterpriseSpecificInformation: make([]byte, 65531)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65535), binary.BigEndian.Uint16(raw[pcep.TLVLengthOffset:pcep.TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.VendorInformation{EnterpriseSpecificInformation: make([]byte, 65532)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "is outside the range")
	})
}

func TestVendorInformation_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.VendorInformation{
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

			decoded, err := pcep.DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*pcep.VendorInformation)
			require.Truef(t, ok, "expected *VendorInformation, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			gotData, err := got.Serialize()
			require.NoError(t, err, "Serialize failed")
			assert.Equal(t, data, gotData, "re-serialized bytes differ")
		})
	}
}

var (
	testStatefulLSPUpdate      = pcep.NewStatefulPCECapability(0x00000001) // LSP Update capability only
	testStatefulAll            = pcep.NewStatefulPCECapability(0x0000083f) // All capabilities enabled
	testStatefulNone           = pcep.NewStatefulPCECapability(0x00000000) // No capabilities enabled
	testStatefulLSPUpdateBytes = append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x01)
	testStatefulAllBytes       = append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x00, 0x00, 0x08, 0x3f)
	testStatefulNoneBytes      = append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	testStatefulMissingTLVBody = tlvHeader(pcep.TLVStatefulPCECapability, 4)
	testStatefulTooShort       = append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x00, 0x01, 0x02)
	testStatefulInvalidLength  = append(tlvHeader(pcep.TLVStatefulPCECapability, 3), 0x00, 0x00, 0x00)
)

func TestStatefulPCECapability_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"SingleCapability":   {testStatefulLSPUpdateBytes, testStatefulLSPUpdate, false},
		"AllCapabilities":    {testStatefulAllBytes, testStatefulAll, false},
		"MissingTLVBody":     {testStatefulMissingTLVBody, nil, true},
		"ValueTooShort":      {testStatefulTooShort, nil, true},
		"InvalidValueLength": {testStatefulInvalidLength, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.StatefulPCECapability{} })
}

func TestStatefulPCECapability_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"LSPUpdate":       {testStatefulLSPUpdate, testStatefulLSPUpdateBytes},
		"AllCapabilities": {testStatefulAll, testStatefulAllBytes},
		"NoCapabilities":  {testStatefulNone, testStatefulNoneBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestStatefulPCECapability_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"LSPUpdate": {testStatefulLSPUpdate, pcep.TLVValueOffset + 4},
	}
	runTLVLenTests(t, cases)
}

var (
	testSymbolicPathName            = pcep.NewSymbolicPathName("Test") // Normal case
	testSymbolicPathNameWithPadding = pcep.NewSymbolicPathName("ABC")  // 1 padding byte
	testSymbolicPathNameEmptyString = pcep.NewSymbolicPathName("")     // Empty string

	testSymbolicPathNameBytes            = []byte{byte(pcep.TLVSymbolicPathName >> 8), byte(pcep.TLVSymbolicPathName & 0xff), 0x00, 0x04, 'T', 'e', 's', 't'}
	testSymbolicPathNameEmptyBytes       = []byte{byte(pcep.TLVSymbolicPathName >> 8), byte(pcep.TLVSymbolicPathName & 0xff), 0x00, 0x00}
	testSymbolicPathNameInvalidUTF8Bytes = []byte{byte(pcep.TLVSymbolicPathName >> 8), byte(pcep.TLVSymbolicPathName & 0xff), 0x00, 0x01, 0xff}
	testSymbolicPathNameTooShort         = []byte{byte(pcep.TLVSymbolicPathName >> 8), byte(pcep.TLVSymbolicPathName & 0xff), 0x00, 0x02, 'T'}
	testSymbolicPathNameTooLong          = []byte{byte(pcep.TLVSymbolicPathName >> 8), byte(pcep.TLVSymbolicPathName & 0xff), 0x00, 0x01, 'T', 'e'}
	testSymbolicPathNameTruncatedHeader  = []byte{byte(pcep.TLVSymbolicPathName >> 8), byte(pcep.TLVSymbolicPathName & 0xff), 0x00}
)

func TestSymbolicPathName_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"Valid":           {testSymbolicPathNameBytes, testSymbolicPathName, false},
		"Empty":           {testSymbolicPathNameEmptyBytes, testSymbolicPathNameEmptyString, false},
		"InvalidUTF8":     {testSymbolicPathNameInvalidUTF8Bytes, nil, true},
		"TruncatedHeader": {testSymbolicPathNameTruncatedHeader, nil, true},
		"TooShort":        {testSymbolicPathNameTooShort, nil, true},
		"TooLong":         {testSymbolicPathNameTooLong, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.SymbolicPathName{} })
}

func TestSymbolicPathName_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"Valid": {testSymbolicPathName, testSymbolicPathNameBytes},
		"Empty": {testSymbolicPathNameEmptyString, testSymbolicPathNameEmptyBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSymbolicPathName_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"Valid":  {testSymbolicPathName, pcep.TLVValueOffset + 4},
		"Padded": {testSymbolicPathNameWithPadding, pcep.TLVValueOffset + 4}, // "ABC" + 1 padding
	}
	runTLVLenTests(t, cases)
}

func TestSymbolicPathName_Serialize_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.SymbolicPathName{Name: strings.Repeat("a", 65535)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65535), binary.BigEndian.Uint16(raw[pcep.TLVLengthOffset:pcep.TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.SymbolicPathName{Name: strings.Repeat("a", 65536)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "is outside the range")
	})
}

var (
	testIPv4LSPIdentifiers      = pcep.NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234)
	testIPv4LSPIdentifiersBytes = append(
		tlvHeader(pcep.TLVIPv4LSPIdentifiers, pcep.TLVIPv4LSPIdentifiersValueLength),
		0xc0, 0x00, 0x02, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, 0x02, // Endpoint Address
	)
	testIPv4LSPIdentifiersTruncated = []byte{
		byte(pcep.TLVIPv4LSPIdentifiers >> 8), byte(pcep.TLVIPv4LSPIdentifiers & 0xff), 0x00, 0x03,
		0xc0, 0x00, 0x02,
	}
	testIPv4LSPIdentifiersExtra     = append(testIPv4LSPIdentifiersBytes, 0xde, 0xad, 0xbe, 0xef)
	testIPv4LSPIdentifiersBadSender = append(
		tlvHeader(pcep.TLVIPv4LSPIdentifiers, pcep.TLVIPv4LSPIdentifiersValueLength),
		0xc0, 0x00, 0x02, // 3 bytes only → invalid sender
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, 0x02, // Endpoint Address
	)
	testIPv4LSPIdentifiersBadEndpoint = append(
		tlvHeader(pcep.TLVIPv4LSPIdentifiers, pcep.TLVIPv4LSPIdentifiersValueLength),
		0xc0, 0x00, 0x02, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, // Endpoint Address (3 bytes only)
	)
)

func TestIPv4LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidIPv4LSPIdentifiers":        {testIPv4LSPIdentifiersBytes, testIPv4LSPIdentifiers, false},
		"TruncatedIPv4LSPIdentifiers":    {testIPv4LSPIdentifiersTruncated, nil, true},
		"ExtraBytesInIPv4LSPIdentifiers": {testIPv4LSPIdentifiersExtra, nil, true},
		"InvalidSenderAddress":           {testIPv4LSPIdentifiersBadSender, nil, true},
		"InvalidEndpointAddress":         {testIPv4LSPIdentifiersBadEndpoint, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.IPv4LSPIdentifiers{} })
}

func TestIPv4LSPIdentifiers_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidIPv4LSPIdentifiers": {testIPv4LSPIdentifiers, testIPv4LSPIdentifiersBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestIPv4LSPIdentifiers_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidIPv4LSPIdentifiersLength": {testIPv4LSPIdentifiers, pcep.TLVValueOffset + pcep.TLVIPv4LSPIdentifiersValueLength},
	}
	runTLVLenTests(t, cases)
}

var (
	// Valid pcep.IPv6LSPIdentifiers with typical values.
	testIPv6LSPIdentifiers = pcep.NewIPv6LSPIdentifiers(
		netip.MustParseAddr(testIPv6Addr1),
		netip.MustParseAddr(testIPv6Addr2),
		1, 2, [pcep.IPv6AddrLen]byte{},
	)

	// Serialized TLV bytes for testIPv6LSPIdentifiers.
	testIPv6LSPIdentifiersBytes = append(
		tlvHeader(pcep.TLVIPv6LSPIdentifiers, pcep.TLVIPv6LSPIdentifiersValueLength),
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extended Tunnel ID (all zeros)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Endpoint Address
	)

	// TLV bytes with intentionally invalid value length (to cover valueLen != expected case).
	testIPv6LSPIdentifiersInvalidLength = []byte{
		byte(pcep.TLVIPv6LSPIdentifiers >> 8),
		byte(pcep.TLVIPv6LSPIdentifiers & 0xff),
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
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidIPv6LSPIdentifiers":        {testIPv6LSPIdentifiersBytes, testIPv6LSPIdentifiers, false},
		"InvalidValueLength":             {testIPv6LSPIdentifiersInvalidLength, nil, true},
		"TruncatedIPv6LSPIdentifiers":    {testIPv6LSPIdentifiersTruncated, nil, true},
		"ExtraBytesInIPv6LSPIdentifiers": {testIPv6LSPIdentifiersExtra, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.IPv6LSPIdentifiers{} })
}

func TestIPv6LSPIdentifiers_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidIPv6LSPIdentifiers": {testIPv6LSPIdentifiers, testIPv6LSPIdentifiersBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestIPv6LSPIdentifiers_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidIPv6LSPIdentifiersLength": {testIPv6LSPIdentifiers, pcep.TLVValueOffset + pcep.TLVIPv6LSPIdentifiersValueLength},
	}
	runTLVLenTests(t, cases)
}

var (
	testLSPDBVersion              = pcep.NewLSPDBVersion(12345)
	testLSPDBVersionBytes         = append(tlvHeader(pcep.TLVLSPDBVersion, 8), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39)
	testLSPDBVersionTruncated     = append(tlvHeader(pcep.TLVLSPDBVersion, 4), 0x00, 0x00, 0x00, 0x00)
	testLSPDBVersionExtra         = append(tlvHeader(pcep.TLVLSPDBVersion, 8), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0xde, 0xad, 0xbe, 0xef)
	testLSPDBVersionInvalidLength = append(tlvHeader(pcep.TLVLSPDBVersion, 16), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0xde, 0xad, 0xbe, 0xef)
)

func TestLSPDBVersion_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidLSPDBVersion":         {testLSPDBVersionBytes, testLSPDBVersion, false},
		"TruncatedLSPDBVersion":     {testLSPDBVersionTruncated, nil, true},
		"ExtraBytesInLSPDBVersion":  {testLSPDBVersionExtra, nil, true},
		"InvalidLengthLSPDBVersion": {testLSPDBVersionInvalidLength, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.LSPDBVersion{} })
}

func TestLSPDBVersion_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidLSPDBVersion": {testLSPDBVersion, testLSPDBVersionBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestLSPDBVersion_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidLSPDBVersionLength": {testLSPDBVersion, pcep.TLVValueOffset + pcep.TLVLSPDBVersionValueLength},
	}
	runTLVLenTests(t, cases)
}

var (
	testSRPCECapability = pcep.NewSRPCECapability(true, true, 10)
	// RFC 8664 §5.1.1: Reserved (2), Flags (1), MSD (1).
	testSRPCECapabilityBytes             = append(tlvHeader(pcep.TLVSRPCECapability, 4), 0x00, 0x00, 0x03, 0x0a)
	testSRPCECapabilityTruncated         = append(tlvHeader(pcep.TLVSRPCECapability, 4), 0x00, 0x02)
	testSRPCECapabilityExtra             = append(tlvHeader(pcep.TLVSRPCECapability, 4), 0x00, 0x00, 0x03, 0x05, 0xde, 0xad, 0xbe, 0xef)
	testSRPCECapabilityInvalidLength     = append(tlvHeader(pcep.TLVSRPCECapability, 8), 0x00, 0x00, 0x03, 0x05, 0xde, 0xad, 0xbe, 0xef)
	testSRPCECapabilityZeroMSDBytes      = append(tlvHeader(pcep.TLVSRPCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	testSRPCECapabilityMSDZeroAdvertised = &pcep.SRPCECapability{MaximumSidDepth: 0}
)

func TestSRPCECapability_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidSRPCECapability":         {testSRPCECapabilityBytes, testSRPCECapability, false},
		"TruncatedSRPCECapability":     {testSRPCECapabilityTruncated, nil, true},
		"ExtraBytesInSRPCECapability":  {testSRPCECapabilityExtra, nil, true},
		"InvalidLengthSRPCECapability": {testSRPCECapabilityInvalidLength, nil, true},
		"ZeroMSDIsStillAdvertised":     {testSRPCECapabilityZeroMSDBytes, testSRPCECapabilityMSDZeroAdvertised, false},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.SRPCECapability{} })
}

func TestSRPCECapability_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidSRPCECapability": {testSRPCECapability, testSRPCECapabilityBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPCECapability_Serialize_WireFormat(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input         *pcep.SRPCECapability
		expectedFlags uint8
		expectedMSD   uint8
	}{
		"NoFlagsMSD5":         {&pcep.SRPCECapability{MaximumSidDepth: 5}, 0x00, 5},
		"NoFlagsMSD10":        {&pcep.SRPCECapability{MaximumSidDepth: 10}, 0x00, 10},
		"UnlimitedMSDOnly":    {&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true}, 0x01, 0},
		"NAIOnlyWithMSD":      {&pcep.SRPCECapability{IsNAISupported: true, MaximumSidDepth: 8}, 0x02, 8},
		"BothFlagsWithMSD255": {pcep.NewSRPCECapability(true, true, 255), 0x03, 255},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.input.Serialize()
			require.NoError(t, err, "Serialize failed for '%s'", name)
			require.Len(t, got, int(pcep.TLVValueOffset+pcep.TLVSRPCECapabilityValueLength))

			value := got[pcep.TLVValueOffset:]
			assert.Equal(t, []uint8{0x00, 0x00}, value[0:2], "Reserved octets must be zero")
			assert.Equal(t, tt.expectedFlags, value[pcep.SRPCECapabilityFlagsOffset], "Flags in wrong byte position")
			assert.Equal(t, tt.expectedMSD, value[pcep.SRPCECapabilityMSDOffset], "MSD in wrong byte position")
		})
	}
}

func TestSRPCECapability_DecodeFromBytes_WireFormat(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		value    []uint8
		expected *pcep.SRPCECapability
	}{
		// Junos: MSD=5; Cisco IOS-XR: MSD=10; no flags.
		"MSD5":  {[]uint8{0x00, 0x00, 0x00, 0x05}, &pcep.SRPCECapability{MaximumSidDepth: 5}},
		"MSD10": {[]uint8{0x00, 0x00, 0x00, 0x0a}, &pcep.SRPCECapability{MaximumSidDepth: 10}},
		"XFlag": {[]uint8{0x00, 0x00, 0x01, 0x00}, &pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true}},
		"NFlagWithMSD": {
			[]uint8{0x00, 0x00, 0x02, 0x04},
			&pcep.SRPCECapability{IsNAISupported: true, MaximumSidDepth: 4},
		},
		"BothFlags": {
			[]uint8{0x00, 0x00, 0x03, 0x0a},
			&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true, IsNAISupported: true, MaximumSidDepth: 10},
		},
		"NonZeroReservedIsIgnored": {
			[]uint8{0xde, 0xad, 0x00, 0x05},
			&pcep.SRPCECapability{MaximumSidDepth: 5},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var tlv pcep.SRPCECapability

			err := tlv.DecodeFromBytes(append(tlvHeader(pcep.TLVSRPCECapability, 4), tt.value...))
			require.NoError(t, err, "DecodeFromBytes failed for '%s'", name)
			assert.Equal(t, tt.expected, &tlv, "unexpected decode result for '%s'", name)
		})
	}
}

func TestSRPCECapability_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.SRPCECapability{
		"Empty":        {},
		"MSD5":         {MaximumSidDepth: 5},
		"MSD10":        {MaximumSidDepth: 10},
		"UnlimitedMSD": {HasUnlimitedMaxSIDDepth: true},
		"NAIWithMSD":   {IsNAISupported: true, MaximumSidDepth: 8},
		"AllFields":    pcep.NewSRPCECapability(true, true, 10),
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed for '%s'", name)

			var got pcep.SRPCECapability
			require.NoError(t, got.DecodeFromBytes(raw), "DecodeFromBytes failed for '%s'", name)
			assert.Equal(t, want, &got, "round-trip mismatch for '%s'", name)
		})
	}
}

func TestSRPCECapability_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidSRPCECapabilityLength": {testSRPCECapability, pcep.TLVValueOffset + pcep.TLVSRPCECapabilityValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestSRPCECapability_DecodeSerializeRoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.SRPCECapability{
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
			t.Parallel()

			b, err := original.Serialize()
			require.NoError(t, err)

			var decoded pcep.SRPCECapability
			require.NoError(t, decoded.DecodeFromBytes(b))
			assert.Equal(t, original, &decoded, "first decode must match the original")

			b2, err := decoded.Serialize()
			require.NoError(t, err)
			assert.Equal(t, b, b2, "re-serializing a decoded value must produce identical bytes")

			var decodedAgain pcep.SRPCECapability
			require.NoError(t, decodedAgain.DecodeFromBytes(b2))
			assert.Equal(t, decoded, decodedAgain, "second decode must match the first")
		})
	}
}

func TestSRPCECapability_HasInvalidZeroMSD(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    *pcep.SRPCECapability
		expected bool
	}{
		"XZeroMSDZero":        {&pcep.SRPCECapability{}, true},
		"XZeroMSDNonZero":     {&pcep.SRPCECapability{MaximumSidDepth: 10}, false},
		"XOneMSDZero":         {&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true}, false},
		"XZeroNAIOnlyMSDZero": {&pcep.SRPCECapability{IsNAISupported: true}, true},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.input.HasInvalidZeroMSD())
		})
	}
}

func TestPst_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.Pst
		expected string
	}{
		"Known PathSetupType":   {pcep.Pst(0x01), "Traffic engineering path is set up using Segment Routing (0x01)"},
		"Unknown PathSetupType": {pcep.Pst(0xff), "Unknown PathSetupType (0xff)"},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := tt.input.String()
			assert.Equal(t, tt.expected, actual, "unexpected Pst.String() result for '%s'", name)
		})
	}
}

func TestPst_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.Pst
		expected string
	}{
		"Known PathSetupType":   {pcep.PathSetupTypeSRTE, pstDescriptionSRTE},
		"Unknown PathSetupType": {pcep.Pst(0xff), "Unknown PathSetupType (0xff)"},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.input.StringWithReference(), "unexpected Pst.StringWithReference() result for '%s'", name)
		})
	}
}

func TestPsts_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.Psts
		expected string
	}{
		"Nil Psts":      {nil, "null"},
		"Empty Psts":    {pcep.Psts{}, "[]"},
		"Single Pst":    {pcep.Psts{pcep.Pst(1)}, "[1]"},
		"Multiple Psts": {pcep.Psts{pcep.Pst(1), pcep.Pst(2)}, "[1,2]"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual, err := tt.input.MarshalJSON()
			require.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, string(actual), "MarshalJSON output mismatch for '%s'", name)
		})
	}
}

var (
	testPathSetupTypeSRTE   = pcep.NewPathSetupType(pcep.PathSetupTypeSRTE)
	testPathSetupTypeRSVPTE = pcep.NewPathSetupType(pcep.PathSetupTypeRSVPTE)
	testPathSetupTypeSRv6TE = pcep.NewPathSetupType(pcep.PathSetupTypeSRv6TE)

	// Serialized bytes for pcep.PathSetupType SRTE.
	testPathSetupTypeSRTEBytes = []byte{
		byte(pcep.TLVPathSetupType >> 8), byte(pcep.TLVPathSetupType & 0xff), 0x00, 0x04, 0x00, 0x00, 0x00, byte(pcep.PathSetupTypeSRTE),
	}
	// Serialized bytes for pcep.PathSetupType RSVPTE.
	testPathSetupTypeRSVPTEBytes = []byte{
		byte(pcep.TLVPathSetupType >> 8), byte(pcep.TLVPathSetupType & 0xff), 0x00, 0x04, 0x00, 0x00, 0x00, byte(pcep.PathSetupTypeRSVPTE),
	}
	// Serialized bytes for pcep.PathSetupType SRv6TE.
	testPathSetupTypeSRv6TEBytes = []byte{
		byte(pcep.TLVPathSetupType >> 8), byte(pcep.TLVPathSetupType & 0xff), 0x00, 0x04, 0x00, 0x00, 0x00, byte(pcep.PathSetupTypeSRv6TE),
	}
	// Invalid input for pcep.PathSetupType (too short).
	testPathSetupTypeTooShort = []byte{
		0x00, 0x15, 0x00, 0x04,
	}
	// Invalid input for pcep.PathSetupType (too long).
	testPathSetupTypeTooLong = append(mustSerializeTLV(pcep.NewPathSetupType(pcep.PathSetupTypeSRTE)), 0x00, 0x00)
	// Invalid input for pcep.PathSetupType (value length mismatch).
	testPathSetupTypeInvalidLength = []byte{
		byte(pcep.TLVPathSetupType >> 8), byte(pcep.TLVPathSetupType & 0xff),
		0x00, 0x06,
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x00,
	}
)

func TestPathSetupType_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"Valid SRv6TE":       {testPathSetupTypeSRv6TEBytes, testPathSetupTypeSRv6TE, false},
		"TooShort":           {testPathSetupTypeTooShort, nil, true},
		"TooLong":            {testPathSetupTypeTooLong, nil, true},
		"InvalidValueLength": {testPathSetupTypeInvalidLength, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.PathSetupType{} })
}

func TestPathSetupType_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"SRTE":   {testPathSetupTypeSRTE, testPathSetupTypeSRTEBytes},
		"RSVPTE": {testPathSetupTypeRSVPTE, testPathSetupTypeRSVPTEBytes},
		"SRv6TE": {testPathSetupTypeSRv6TE, testPathSetupTypeSRv6TEBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestPathSetupType_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"RSVPTELength": {testPathSetupTypeRSVPTE, pcep.TLVValueOffset + pcep.TLVPathSetupTypeValueLength},
	}
	runTLVLenTests(t, cases)
}

var (
	// pcep.PathSetupTypeCapability instances.
	testPathSetupTypeCapabilityBasic = &pcep.PathSetupTypeCapability{
		PathSetupTypes: pcep.Psts{pcep.PathSetupTypeRSVPTE, pcep.PathSetupTypeSRTE},
		SubTLVs:        []pcep.TLVInterface{},
	}
	testPathSetupTypeCapabilityWithSubTLV = &pcep.PathSetupTypeCapability{
		PathSetupTypes: pcep.Psts{pcep.PathSetupTypeSRTE},
		SubTLVs:        []pcep.TLVInterface{pcep.NewSRPCECapability(true, true, 10)},
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
	testPathSetupTypeCapabilityZeroPST = &pcep.PathSetupTypeCapability{
		PathSetupTypes: pcep.Psts{},
		SubTLVs:        []pcep.TLVInterface{},
	}

	testPathSetupTypeCapabilityNilPST = &pcep.PathSetupTypeCapability{
		PathSetupTypes: pcep.Psts{},
		SubTLVs:        []pcep.TLVInterface{},
	}
	testPathSetupTypeCapabilitySubTLVOffsetOverflowBytes = []byte{
		0x00, 0x22, 0x00, 0x05, // TLV header, length=5
		0x00, 0x00, 0x00, 0x01, // PST count = 1
		0x01, // PST entry
	}
)

func TestPathSetupTypeCapability_DecodeFromBytes(t *testing.T) {
	t.Parallel()

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
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.PathSetupTypeCapability{} })
}

// TestPathSetupTypeCapability_Serialize tests pcep.PathSetupTypeCapability.Serialize.
func TestPathSetupTypeCapability_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"Basic":   {testPathSetupTypeCapabilityBasic, testPathSetupTypeCapabilityBasicBytes},
		"WithSub": {testPathSetupTypeCapabilityWithSubTLV, testPathSetupTypeCapabilityWithSubTLVBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestPathSetupTypeCapability_Serialize_SubTLVLengthBoundary(t *testing.T) {
	t.Parallel()

	newSubTLVs := func(n int) []pcep.TLVInterface {
		subTLVs := make([]pcep.TLVInterface, n)
		for i := range subTLVs {
			subTLVs[i] = &pcep.SRPCECapability{}
		}

		return subTLVs
	}

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.PathSetupTypeCapability{SubTLVs: newSubTLVs(8191)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65532), binary.BigEndian.Uint16(raw[pcep.TLVLengthOffset:pcep.TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.PathSetupTypeCapability{SubTLVs: newSubTLVs(8192)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "is outside the range")
	})
}

func TestPathSetupTypeCapability_Serialize_SubTLVError(t *testing.T) {
	t.Parallel()

	tlv := &pcep.PathSetupTypeCapability{SubTLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}
	_, err := tlv.Serialize()
	assert.ErrorContains(t, err, "is outside the range")
}

func TestPathSetupTypeCapability_SubCapabilities(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    *pcep.PathSetupTypeCapability
		expected []pcep.CapabilityInterface
	}{
		"NoSubTLVs": {
			&pcep.PathSetupTypeCapability{},
			[]pcep.CapabilityInterface{},
		},
		"SRAndSRv6": {
			&pcep.PathSetupTypeCapability{SubTLVs: []pcep.TLVInterface{
				&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true},
				&pcep.SRv6PCECapability{IsNAISupported: true},
			}},
			[]pcep.CapabilityInterface{
				&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true},
				&pcep.SRv6PCECapability{IsNAISupported: true},
			},
		},
		"KeepsUnknownTLV": {
			&pcep.PathSetupTypeCapability{SubTLVs: []pcep.TLVInterface{
				&pcep.UnknownTLV{Typ: pcep.TLVType(0x1234), Value: []byte{0x01}},
			}},
			[]pcep.CapabilityInterface{
				&pcep.UnknownTLV{Typ: pcep.TLVType(0x1234), Value: []byte{0x01}},
			},
		},
		"DropsNonCapabilityTLV": {
			&pcep.PathSetupTypeCapability{SubTLVs: []pcep.TLVInterface{
				&pcep.PathSetupType{PathSetupType: pcep.PathSetupTypeSRTE},
				&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true},
			}},
			[]pcep.CapabilityInterface{
				&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true},
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

	tlv := &pcep.PathSetupTypeCapability{PathSetupTypes: pcep.Psts{pcep.PathSetupTypeSRTE}}

	assert.True(t, tlv.HasPathSetupType(pcep.PathSetupTypeSRTE))
	assert.False(t, tlv.HasPathSetupType(pcep.PathSetupTypeSRv6TE))
}

// pcep.Reference determines whether a type is draft-only or unassigned.
var (
	testIPv4ExtendedAssociationID = pcep.NewExtendedAssociationID(1, netip.MustParseAddr("127.0.0.1"))
	testIPv6ExtendedAssociationID = pcep.NewExtendedAssociationID(1, netip.MustParseAddr(testIPv6Addr1))

	testIPv4ExtendedAssociationIDBytes = []byte{
		byte(pcep.TLVExtendedAssociationID >> 8), byte(pcep.TLVExtendedAssociationID & 0xff), 0x00, 0x08,
		0x00, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
	}
	testIPv6ExtendedAssociationIDBytes = []byte{
		byte(pcep.TLVExtendedAssociationID >> 8), byte(pcep.TLVExtendedAssociationID & 0xff), 0x00, 0x14,
		0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	testExtendedAssociationIDTooShort = []byte{
		byte(pcep.TLVExtendedAssociationID >> 8), byte(pcep.TLVExtendedAssociationID & 0xff), 0x00,
	}
	testExtendedAssociationIDInvalidLen = []byte{
		byte(pcep.TLVExtendedAssociationID >> 8), byte(pcep.TLVExtendedAssociationID & 0xff), 0x00, 0x10,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	testExtendedAssociationIDUnsupportedLen = []byte{
		byte(pcep.TLVExtendedAssociationID >> 8), byte(pcep.TLVExtendedAssociationID & 0xff), 0x00, 0x0f,
		0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01,
	}
	testExtendedAssociationIDValueTooShort = []byte{
		byte(pcep.TLVExtendedAssociationID >> 8), byte(pcep.TLVExtendedAssociationID & 0xff), 0x00, 0x03,
		0x00, 0x00, 0x00,
	}
)

func TestExtendedAssociationID_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"IPv4":                  {testIPv4ExtendedAssociationIDBytes, testIPv4ExtendedAssociationID, false},
		"IPv6":                  {testIPv6ExtendedAssociationIDBytes, testIPv6ExtendedAssociationID, false},
		"TooShort":              {testExtendedAssociationIDTooShort, nil, true},
		"ValueTooShortForColor": {testExtendedAssociationIDValueTooShort, nil, true},
		"InvalidLength":         {testExtendedAssociationIDInvalidLen, nil, true},
		"UnsupportedLength":     {testExtendedAssociationIDUnsupportedLen, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.ExtendedAssociationID{} })
}

func TestExtendedAssociationID_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"IPv4":            {testIPv4ExtendedAssociationID, testIPv4ExtendedAssociationIDBytes},
		"IPv6":            {testIPv6ExtendedAssociationID, testIPv6ExtendedAssociationIDBytes},
		"InvalidEndpoint": {&pcep.ExtendedAssociationID{Color: 1}, nil}, // Endpoint zero-value
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual, err := tt.input.Serialize()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestExtendedAssociationID_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"IPv4Length":        {testIPv4ExtendedAssociationID, pcep.TLVValueOffset + pcep.TLVExtendedAssociationIDIPv4ValueLength},
		"IPv6Length":        {testIPv6ExtendedAssociationID, pcep.TLVValueOffset + pcep.TLVExtendedAssociationIDIPv6ValueLength},
		"UnsupportedLength": {&pcep.ExtendedAssociationID{Color: 1}, 0},
	}
	runTLVLenTests(t, cases)
}

func TestExtendedAssociationIDIPv4Juniper_Type(t *testing.T) {
	t.Parallel()

	tlv := &pcep.ExtendedAssociationIDIPv4Juniper{}
	assert.Equal(t, pcep.TLVExtendedAssociationIDIPv4Juniper, tlv.Type())
}

func TestExtendedAssociationIDIPv4Juniper_Serialize(t *testing.T) {
	t.Parallel()

	expectedIPv4 := append([]byte(nil), testIPv4ExtendedAssociationIDBytes...)
	expectedIPv4[0], expectedIPv4[1] = 0xff, 0xe3 // type=0xffe3, value layout unchanged

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"IPv4": {
			&pcep.ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv4ExtendedAssociationID},
			expectedIPv4,
		},
		"IPv6Rejected": {
			&pcep.ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv6ExtendedAssociationID},
			nil,
		},
	}
	runTLVSerializeTests(t, cases)
}

func TestExtendedAssociationIDIPv4Juniper_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"IPv4": {
			&pcep.ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv4ExtendedAssociationID},
			uint16(testIPv4ExtendedAssociationID.Len()),
		},
		"IPv6Rejected": {
			&pcep.ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv6ExtendedAssociationID},
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
			&pcep.ExtendedAssociationIDIPv4Juniper{ExtendedAssociationID: *testIPv4ExtendedAssociationID},
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
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.ExtendedAssociationIDIPv4Juniper{} })
}

var (
	// pcep.AssocTypeList with two entries.
	testAssocTypeList = &pcep.AssocTypeList{
		AssocTypes: []pcep.AssocType{pcep.AssocTypePathProtectionAssociation, pcep.AssocTypeSRPolicyAssociation},
	}
	// pcep.AssocTypeList with a single entry (requires padding to 4-byte alignment).
	testAssocTypeListSingle = &pcep.AssocTypeList{
		AssocTypes: []pcep.AssocType{pcep.AssocTypePathProtectionAssociation},
	}
	// pcep.AssocTypeList with four entries (already 4-byte aligned).
	testAssocTypeListFour = &pcep.AssocTypeList{
		AssocTypes: []pcep.AssocType{
			pcep.AssocTypePathProtectionAssociation,
			pcep.AssocTypeDisjointAssociation,
			pcep.AssocTypePolicyAssociation,
			pcep.AssocTypeSRPolicyAssociation,
		},
	}
	// Empty pcep.AssocTypeList.
	testAssocTypeListEmpty = &pcep.AssocTypeList{AssocTypes: []pcep.AssocType{}}

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
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidTwoEntries":  {testAssocTypeListBytes, testAssocTypeList, false},
		"ValidSingleEntry": {testAssocTypeListSingleBytesWithoutPadding, testAssocTypeListSingle, false},
		"OddLengthValue":   {testAssocTypeListOddLength, nil, true},
		"TruncatedHeader":  {testAssocTypeListTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.AssocTypeList{} })
}

func TestAssocTypeList_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"TwoEntries":  {testAssocTypeList, testAssocTypeListBytes},
		"SingleEntry": {testAssocTypeListSingle, testAssocTypeListSingleBytesWithPadding},
	}
	runTLVSerializeTests(t, cases)
}

func TestAssocTypeList_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"TwoEntriesLen":  {testAssocTypeList, pcep.TLVValueOffset + 4},       // 2*2 = 4, already aligned
		"SingleEntryLen": {testAssocTypeListSingle, pcep.TLVValueOffset + 4}, // 1*2 + 2 pad = 4
		"FourEntriesLen": {testAssocTypeListFour, pcep.TLVValueOffset + 8},   // 4*2 = 8, already aligned
		"EmptyLen":       {testAssocTypeListEmpty, pcep.TLVValueOffset + 0},  // 0 entries = 0 bytes
	}
	runTLVLenTests(t, cases)
}

func TestAssocTypeList_Serialize_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("AtLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.AssocTypeList{AssocTypes: make([]pcep.AssocType, 32767)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Len(t, raw, tlv.Len(), "Len() must match serialized size")
		assert.Equal(t, uint16(65534), binary.BigEndian.Uint16(raw[pcep.TLVLengthOffset:pcep.TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.AssocTypeList{AssocTypes: make([]pcep.AssocType, 32768)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "is outside the range")
	})
}

var (
	testSRPolicyCPathIDIPv4 = &pcep.SRPolicyCandidatePathIdentifier{
		ProtocolOrigin: pcep.ProtocolOriginPCEP,
		OriginatorASN:  65000,
		OriginatorAddr: netip.AddrFrom4([4]byte{192, 0, 2, 1}), // IPv4 originator
		Discriminator:  1,
	}
	testSRPolicyCPathIDIPv6 = &pcep.SRPolicyCandidatePathIdentifier{
		ProtocolOrigin: pcep.ProtocolOriginPCEP,
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

	testSRPolicyCPathIDInvalid = &pcep.SRPolicyCandidatePathIdentifier{
		ProtocolOrigin: pcep.ProtocolOriginPCEP,
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
	testSRPolicyCPathIDNonPCEP = &pcep.SRPolicyCandidatePathIdentifier{
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
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidIPv4":             {testSRPolicyCPathIDIPv4Bytes, testSRPolicyCPathIDIPv4, false},
		"ValidIPv6":             {testSRPolicyCPathIDIPv6Bytes, testSRPolicyCPathIDIPv6, false},
		"NonPCEPProtocolOrigin": {testSRPolicyCPathIDNonPCEPBytes, testSRPolicyCPathIDNonPCEP, false},
		"TooShort":              {testSRPolicyCPathIDTooShort, nil, true},
		"TruncatedHeader":       {testSRPolicyCPathIDTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.SRPolicyCandidatePathIdentifier{} })
}

func TestSRPolicyCandidatePathIdentifier_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"SerializeIPv4":                  {testSRPolicyCPathIDIPv4, testSRPolicyCPathIDIPv4Bytes},
		"SerializeIPv6":                  {testSRPolicyCPathIDIPv6, testSRPolicyCPathIDIPv6Bytes},
		"SerializeNonPCEPProtocolOrigin": {testSRPolicyCPathIDNonPCEP, testSRPolicyCPathIDNonPCEPBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPolicyCandidatePathIdentifier_Serialize_Invalid(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ZeroAddr": {testSRPolicyCPathIDInvalid, testSRPolicyCPathIDInvalidBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPolicyCandidatePathIdentifier_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidLen": {testSRPolicyCPathIDIPv4, pcep.TLVValueOffset + pcep.TLVSRPolicyCPathIDValueLength},
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
			raw[pcep.TLVValueOffset+pcep.SRPolicyCPathIDProtocolOriginOffset] = origin

			var got pcep.SRPolicyCandidatePathIdentifier
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

	tlv := &pcep.SRPolicyCandidatePathIdentifierJuniper{}
	assert.Equal(t, pcep.TLVSRPolicyCPathIDJuniper, tlv.Type())
}

func TestSRPolicyCandidatePathIdentifierJuniper_Serialize(t *testing.T) {
	t.Parallel()

	tlv := &pcep.SRPolicyCandidatePathIdentifierJuniper{
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
	t.Parallel()

	tlv := &pcep.SRPolicyCandidatePathIdentifierJuniper{
		ProtocolOrigin: testSRPolicyCPathIDIPv4.ProtocolOrigin,
		OriginatorASN:  testSRPolicyCPathIDIPv4.OriginatorASN,
		OriginatorAddr: testSRPolicyCPathIDIPv4.OriginatorAddr,
		Discriminator:  testSRPolicyCPathIDIPv4.Discriminator,
	}
	assert.Equal(t, testSRPolicyCPathIDIPv4.Len(), tlv.Len())
}

// Verifies Juniper vendor TLVs preserve structured logging fields.
var (
	testSRPolicyCPathPreference = &pcep.SRPolicyCandidatePathPreference{Preference: 100}

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
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidPreference": {testSRPolicyCPathPreferenceBytes, testSRPolicyCPathPreference, false},
		"InvalidLength":   {testSRPolicyCPathPreferenceTruncated, nil, true},
		"TruncatedHeader": {testSRPolicyCPathPreferenceTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.SRPolicyCandidatePathPreference{} })
}

func TestSRPolicyCandidatePathPreference_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidPreference": {testSRPolicyCPathPreference, testSRPolicyCPathPreferenceBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRPolicyCandidatePathPreference_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidLen": {testSRPolicyCPathPreference, pcep.TLVValueOffset + pcep.TLVSRPolicyCPathPreferenceValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestSRPolicyCandidatePathPreferenceJuniper_Type(t *testing.T) {
	t.Parallel()

	tlv := &pcep.SRPolicyCandidatePathPreferenceJuniper{}
	assert.Equal(t, pcep.TLVSRPolicyCPathPreferenceJuniper, tlv.Type())
}

func TestSRPolicyCandidatePathPreferenceJuniper_Serialize(t *testing.T) {
	t.Parallel()

	tlv := &pcep.SRPolicyCandidatePathPreferenceJuniper{
		Preference: testSRPolicyCPathPreference.Preference,
	}

	expected := append([]byte(nil), testSRPolicyCPathPreferenceBytes...)
	expected[0], expected[1] = 0xff, 0xe5 // type=0xffe5, value layout unchanged

	actual, err := tlv.Serialize()
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestSRPolicyCandidatePathPreferenceJuniper_Len(t *testing.T) {
	t.Parallel()

	tlv := &pcep.SRPolicyCandidatePathPreferenceJuniper{
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
			&pcep.SRPolicyCandidatePathPreferenceJuniper{Preference: testSRPolicyCPathPreference.Preference},
			false,
		},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.SRPolicyCandidatePathPreferenceJuniper{} })
}

var (
	testColor = &pcep.Color{Color: 255}

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
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidColor":      {testColorBytes, testColor, false},
		"InvalidLength":   {testColorTruncated, nil, true},
		"TruncatedHeader": {testColorTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.Color{} })
}

func TestColor_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidColor": {testColor, testColorBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestColor_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidLen": {testColor, pcep.TLVValueOffset + pcep.TLVColorValueLength},
	}
	runTLVLenTests(t, cases)
}

var (
	// Standard 4-byte pcep.UnknownTLV.
	testUnknownTLV = &pcep.UnknownTLV{
		Typ:   pcep.TLVType(0xffff),
		Value: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	// 3-byte value (odd → 1 byte padding required).
	testUnknownTLVOddLength = &pcep.UnknownTLV{
		Typ:   pcep.TLVType(0xffff),
		Value: []byte{0x01, 0x02, 0x03},
	}

	// Serialized TLV bytes.
	testUnknownTLVBytes           = []byte{0xff, 0xff, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef}
	testUnknownTLVOddLengthBytes  = []byte{0xff, 0xff, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00}
	testUnknownTLVTruncatedHeader = []byte{0xff, 0xff, 0x00}
	testUnknownTLVTruncatedValue  = []byte{0xff, 0xff, 0x00, 0x08, 0x01, 0x02}
)

func TestUnknownTLV_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidUnknownTLV": {testUnknownTLVBytes, testUnknownTLV, false},
		"TruncatedHeader": {testUnknownTLVTruncatedHeader, nil, true},
		"TruncatedValue":  {testUnknownTLVTruncatedValue, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.UnknownTLV{} })
}

func TestUnknownTLV_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
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

		tlv := &pcep.UnknownTLV{Value: make([]byte, 65535)}
		raw, err := tlv.Serialize()
		require.NoError(t, err)
		assert.Equal(t, uint16(65535), binary.BigEndian.Uint16(raw[pcep.TLVLengthOffset:pcep.TLVValueOffset]))
	})

	t.Run("ExceedsLimit", func(t *testing.T) {
		t.Parallel()

		tlv := &pcep.UnknownTLV{Value: make([]byte, 65536)}
		_, err := tlv.Serialize()
		assert.ErrorContains(t, err, "is outside the range")
	})
}

func TestUnknownTLV_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"AlignedLen":   {testUnknownTLV, pcep.TLVValueOffset + 4},          // 4-byte value
		"UnalignedLen": {testUnknownTLVOddLength, pcep.TLVValueOffset + 4}, // 3-byte value + 1 pad = 4
	}
	runTLVLenTests(t, cases)
}

func TestUnknownTLV_Len_DerivedFromValue(t *testing.T) {
	t.Parallel()

	tlv := &pcep.UnknownTLV{Value: []byte{0x01, 0x02, 0x03}}
	assert.Equal(t, pcep.TLVValueOffset+4, tlv.Len(), "Len() must reflect len(Value) plus padding")
}

var (
	testDecodeStatefulLSPUpdateBytes = append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x01)
	testDecodeUnknownTLVBytes        = append(tlvHeader(pcep.TLVType(0xffff), 4), 0xde, 0xad, 0xbe, 0xef)
	testDecodeTruncatedHeader        = []byte{0x00}
	testDecodeStatefulInvalidBody    = append(tlvHeader(pcep.TLVStatefulPCECapability, 3), 0x00, 0x00, 0x00)
	testDecodeUnknownTruncatedValue  = []byte{0xff, 0xff, 0x00, 0x08, 0x01, 0x02}
	testDecodeMultipleTLVs           = append(
		append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x01),
		append(tlvHeader(pcep.TLVSymbolicPathName, 4), 'T', 'e', 's', 't')...,
	)
	testDecodeTruncatedValue   = []byte{0x00, 0x10, 0x00, 0x08, 0x00, 0x00}
	testDecodeTruncatedPadding = []byte{0x00, 0xff, 0x00, 0x03, 0x01, 0x02, 0x03}
)

func TestDecodeTLV(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input   []byte
		wantErr bool
		wantTyp pcep.TLVType
	}{
		"KnownTLV_StatefulPCECapability": {testDecodeStatefulLSPUpdateBytes, false, pcep.TLVStatefulPCECapability},
		"UnknownTLV":                     {testDecodeUnknownTLVBytes, false, pcep.TLVType(0xffff)},
		"TooShort":                       {testDecodeTruncatedHeader, true, 0},
		"KnownTLV_InvalidBody":           {testDecodeStatefulInvalidBody, true, 0},
		"UnknownTLV_TruncatedValue":      {testDecodeUnknownTruncatedValue, true, 0},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tlv, err := pcep.DecodeTLV(tt.input)
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
	t.Parallel()

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
		"InvalidKnownTLVBody": {append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x00), false, 1, ""},
		"InvalidPadding":      {invalidPaddingBytes, true, 0, "invalid TLV padding"},
		"JuniperExtendedAssociationIDIPv6Rejected": {
			testExtendedAssociationIDIPv4JuniperIPv6Bytes, true, 0, "invalid value length",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tlvs, err := pcep.DecodeTLVs(tt.input)
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
	t.Parallel()

	fixedPart := make([]byte, pcep.PathSetupTypeCapabilityFixedPartLength)
	fixedPart[pcep.PathSetupTypeCapabilityPSTCountOffset] = 0x01 // Set PST count in fixed part
	pathSetupType := []byte{0x00}

	subTLV := append(tlvHeader(pcep.TLVStatefulPCECapability, 4), 0x01, 0x02)
	value := slices.Concat(fixedPart, pathSetupType, subTLV)
	header := tlvHeader(pcep.TLVPathSetupTypeCapability, uint16(len(value)))
	data := slices.Concat(header, value)

	cases := map[string]struct {
		input   []byte
		wantErr bool
	}{
		"InvalidSubTLV": {data, true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := pcep.DecodeTLVs(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "expected error for '%s'", name)
			} else {
				assert.NoError(t, err, "unexpected error for '%s'", name)
			}
		})
	}
}

var (
	testSRv6PCECapability            = pcep.NewSRv6PCECapability(true)
	testSRv6PCECapabilityBytes       = append(tlvHeader(pcep.TLVSRv6PCECapability, 4), 0x00, 0x00, 0x00, 0x02)
	testSRv6PCECapabilityNoNAIBytes  = append(tlvHeader(pcep.TLVSRv6PCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	testSRv6PCECapabilityExtended    = append(tlvHeader(pcep.TLVSRv6PCECapability, 8), 0x00, 0x00, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef)
	testSRv6PCECapabilityShortLength = append(tlvHeader(pcep.TLVSRv6PCECapability, 3), 0x00, 0x00, 0x00)
	testSRv6PCECapabilityTruncated   = append(tlvHeader(pcep.TLVSRv6PCECapability, 4), 0x00, 0x00)
	testSRv6PCECapabilityNoNAI       = &pcep.SRv6PCECapability{}
)

func TestSRv6PCECapability_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidSRv6PCECapability":          {testSRv6PCECapabilityBytes, testSRv6PCECapability, false},
		"ValidSRv6PCECapabilityNoNAI":     {testSRv6PCECapabilityNoNAIBytes, testSRv6PCECapabilityNoNAI, false},
		"ExtendedLengthSRv6PCECapability": {testSRv6PCECapabilityExtended, testSRv6PCECapability, false},
		"ShortLengthSRv6PCECapability":    {testSRv6PCECapabilityShortLength, nil, true},
		"TruncatedSRv6PCECapability":      {testSRv6PCECapabilityTruncated, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.SRv6PCECapability{} })
}

func TestSRv6PCECapability_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidSRv6PCECapability":      {testSRv6PCECapability, testSRv6PCECapabilityBytes},
		"ValidSRv6PCECapabilityNoNAI": {testSRv6PCECapabilityNoNAI, testSRv6PCECapabilityNoNAIBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestSRv6PCECapability_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidSRv6PCECapabilityLength": {testSRv6PCECapability, pcep.TLVValueOffset + pcep.TLVSRv6PCECapabilityValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestSRv6PCECapability_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.SRv6PCECapability{
		"NAISupported":    pcep.NewSRv6PCECapability(true),
		"NAINotSupported": pcep.NewSRv6PCECapability(false),
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := original.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, data, original.Len(), "Len() must match serialized size")

			decoded, err := pcep.DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*pcep.SRv6PCECapability)
			require.Truef(t, ok, "expected *SRv6PCECapability, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			gotData, err := got.Serialize()
			require.NoError(t, err, "Serialize failed")
			assert.Equal(t, data, gotData, "re-serialized bytes differ")
		})
	}
}

var (
	testMultipathCapability = pcep.NewMultipathCapability(8, true, true, true, true)
	// MaxMultipaths=8 (0x0008), Flags=W|O|F|C = 0x001D.
	testMultipathCapabilityBytes        = append(tlvHeader(pcep.TLVMultipathCap, 4), 0x00, 0x08, 0x00, 0x1d)
	testMultipathCapabilityNoFlags      = pcep.NewMultipathCapability(1, false, false, false, false)
	testMultipathCapabilityNoFlagsBytes = append(tlvHeader(pcep.TLVMultipathCap, 4), 0x00, 0x01, 0x00, 0x00)
	testMultipathCapabilityTruncated    = append(tlvHeader(pcep.TLVMultipathCap, 4), 0x00, 0x08)
	testMultipathCapabilityInvalidLen   = append(tlvHeader(pcep.TLVMultipathCap, 8), 0x00, 0x08, 0x00, 0x0f, 0xde, 0xad, 0xbe, 0xef)
)

func TestMultipathCapability_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	cases := map[string]TLVTestCase{
		"ValidMultipathCapabilityAllFlags": {testMultipathCapabilityBytes, testMultipathCapability, false},
		"ValidMultipathCapabilityNoFlags":  {testMultipathCapabilityNoFlagsBytes, testMultipathCapabilityNoFlags, false},
		"TruncatedMultipathCapability":     {testMultipathCapabilityTruncated, nil, true},
		"InvalidLengthMultipathCapability": {testMultipathCapabilityInvalidLen, nil, true},
	}
	runTLVDecodeTests(t, cases, func() pcep.TLVInterface { return &pcep.MultipathCapability{} })
}

func TestMultipathCapability_Serialize(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected []byte
	}{
		"ValidMultipathCapabilityAllFlags": {testMultipathCapability, testMultipathCapabilityBytes},
		"ValidMultipathCapabilityNoFlags":  {testMultipathCapabilityNoFlags, testMultipathCapabilityNoFlagsBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestMultipathCapability_Len(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		input    pcep.TLVInterface
		expected uint16
	}{
		"ValidMultipathCapabilityLength": {testMultipathCapability, pcep.TLVValueOffset + pcep.TLVMultipathCapValueLength},
	}
	runTLVLenTests(t, cases)
}

func TestMultipathCapability_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.MultipathCapability{
		"AllFlags":         pcep.NewMultipathCapability(8, true, true, true, true),
		"NoFlags":          pcep.NewMultipathCapability(1, false, false, false, false),
		"OnlyWeighted":     pcep.NewMultipathCapability(2, true, false, false, false),
		"OnlyOpposite":     pcep.NewMultipathCapability(3, false, true, false, false),
		"OnlyForwardClass": pcep.NewMultipathCapability(4, false, false, true, false),
		"OnlyComposite":    pcep.NewMultipathCapability(7, false, false, false, true),
		"MaxUint16":        pcep.NewMultipathCapability(0xFFFF, true, true, true, true),
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := original.Serialize()
			require.NoError(t, err, "Serialize failed")
			require.Len(t, data, original.Len(), "Len() must match serialized size")

			decoded, err := pcep.DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*pcep.MultipathCapability)
			require.Truef(t, ok, "expected *MultipathCapability, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			gotData, err := got.Serialize()
			require.NoError(t, err, "Serialize failed")
			assert.Equal(t, data, gotData, "re-serialized bytes differ")
		})
	}
}
