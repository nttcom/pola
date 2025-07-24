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
	"go.uber.org/zap/zapcore"
)

// TestTLVType_String tests the String method for TLVType.
func TestTLVType_String(t *testing.T) {
	cases := map[string]struct {
		tlvType  TLVType
		expected string
	}{
		"StatefulPCECapability": {TLVStatefulPCECapability, "STATEFUL-PCE-CAPABILITY (RFC8231)"},
		"IPv4LSPIdentifiers":    {TLVIPv4LSPIdentifiers, "IPV4-LSP-IDENTIFIERS (RFC8231)"},
		"UnknownType":           {TLVType(0xdead), "Unknown TLV (0xdead)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.tlvType.String()
			assert.Equal(t, tt.expected, actual, "unexpected TLVType.String() result")
		})
	}
}

// TestTLVMap tests the mapping of TLVType to TLVInterface.
func TestTLVMap(t *testing.T) {
	cases := map[string]struct {
		tlvType  TLVType
		expected TLVInterface
	}{
		"StatefulPCECapability":   {TLVStatefulPCECapability, &StatefulPCECapability{}},
		"SymbolicPathName":        {TLVSymbolicPathName, &SymbolicPathName{}},
		"IPv4LSPIdentifiers":      {TLVIPv4LSPIdentifiers, &IPv4LSPIdentifiers{}},
		"IPv6LSPIdentifiers":      {TLVIPv6LSPIdentifiers, &IPv6LSPIdentifiers{}},
		"LSPDBVersion":            {TLVLSPDBVersion, &LSPDBVersion{}},
		"SRPCECapability":         {TLVSRPCECapability, &SRPCECapability{}},
		"PathSetupType":           {TLVPathSetupType, &PathSetupType{}},
		"ExtendedAssociationID":   {TLVExtendedAssociationID, &ExtendedAssociationID{}},
		"PathSetupTypeCapability": {TLVPathSetupTypeCapability, &PathSetupTypeCapability{}},
		"AssocTypeList":           {TLVAssocTypeList, &AssocTypeList{}},
		"SRPolicyCPathID":         {TLVSRPolicyCPathID, &SRPolicyCandidatePathIdentifier{}},
		"SRPolicyCPathPreference": {TLVSRPolicyCPathPreference, &SRPolicyCandidatePathPreference{}},
		"Color":                   {TLVColor, &Color{}},
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

// TLVTestCase defines a common structure for TLV test cases.
type TLVTestCase struct {
	input    []byte
	expected TLVInterface
	wantErr  bool
}

// runTLVDecodeTests is a helper function to run DecodeFromBytes tests for TLVs.
func runTLVDecodeTests(t *testing.T, cases map[string]TLVTestCase, constructor func() TLVInterface) {
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			tlv := constructor()
			err := tlv.DecodeFromBytes(tt.input)

			if tt.wantErr {
				assert.Error(t, err, "expected error for '%s' but got none", name)
			} else {
				assert.NoError(t, err, "unexpected error for '%s'", name)
				assert.Equal(t, tt.expected, tlv, "decoded value mismatch for '%s'", name)
			}
		})
	}
}

// runTLVSerializeTests is a helper function to run Serialize tests for TLVs.
func runTLVSerializeTests(t *testing.T, cases map[string]struct {
	input    TLVInterface
	expected []byte
}) {
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "serialized value mismatch for '%s'", name)
		})
	}
}

type CapStringsInterface interface {
	CapStrings() []string
}

// runCapStringsTests is a helper function to run CapStrings tests for capabilities.
func runCapStringsTests(t *testing.T, cases map[string]struct {
	input    CapStringsInterface
	expected []string
}) {
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.input.CapStrings()
			assert.Equal(t, tt.expected, actual, "capabilities mismatch for '%s'", name)
		})
	}
}

// runTLVLenTests is a helper function to run Len tests for TLVs.
func runTLVLenTests(t *testing.T, cases map[string]struct {
	input    TLVInterface
	expected uint16
}) {
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.input.Len()
			assert.Equal(t, tt.expected, actual, "length mismatch for '%s'", name)
		})
	}
}

// tlvHeader generates a 4-byte TLV header with the given type and length in big-endian format.
func tlvHeader(tlvType TLVType, length uint16) []byte {
	return []byte{byte(tlvType >> 8), byte(tlvType & 0xff), byte(length >> 8), byte(length & 0xff)}
}

// Test data for StatefulPCECapability tests.
var (
	// StatefulPCECapability instance with only the LSP Update capability enabled.
	testStatefulLSPUpdate = NewStatefulPCECapability(0x00000001)
	// StatefulPCECapability instance with all capabilities enabled.
	testStatefulAll = NewStatefulPCECapability(0x0000083f)
	// StatefulPCECapability instance with no capabilities enabled.
	testStatefulNone = NewStatefulPCECapability(0x00000000)

	// Serialized TLV bytes for a StatefulPCECapability with only the LSP Update capability enabled.
	testStatefulLSPUpdateBytes = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x01)
	// Serialized TLV bytes for a StatefulPCECapability with all capabilities enabled.
	testStatefulAllBytes = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x08, 0x3f)
	// Serialized TLV bytes for a StatefulPCECapability with no capabilities enabled.
	testStatefulNoneBytes = append(tlvHeader(TLVStatefulPCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	// Serialized TLV header only to simulate missing TLV body.
	testStatefulMissingTLVBody = tlvHeader(TLVStatefulPCECapability, 4)

	// Expected capability strings when all capabilities are enabled.
	testCapsAllStrings = []string{
		"Stateful", "Update", "Include-DB-Ver", "Instantiation",
		"Triggered-Resync", "Delta-LSP-Sync", "Triggered-Initial-Sync", "Color",
	}
	// Expected capability strings when no additional capabilities are enabled.
	testCapsNoneStrings = []string{"Stateful"}
)

// TestStatefulPCECapability_DecodeFromBytes tests the DecodeFromBytes method for StatefulPCECapability.
func TestStatefulPCECapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"SingleCapability": {testStatefulLSPUpdateBytes, testStatefulLSPUpdate, false},
		"AllCapabilities":  {testStatefulAllBytes, testStatefulAll, false},
		"MissingTLVBody":   {testStatefulMissingTLVBody, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &StatefulPCECapability{} })
}

// TestStatefulPCECapability_Serialize tests the Serialize method for StatefulPCECapability.
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

// TestStatefulPCECapability_MarshalLogObject tests the MarshalLogObject method for StatefulPCECapability.
func TestStatefulPCECapability_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *StatefulPCECapability
		expected bool
	}{
		"LSPUpdateEnabled":  {testStatefulLSPUpdate, true},
		"LSPUpdateDisabled": {testStatefulNone, false},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)

			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields["lspUpdateCapability"], "unexpected value for '%s'", name)
		})
	}
}

// TestStatefulPCECapability_Len tests the Len method for StatefulPCECapability.
func TestStatefulPCECapability_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"LSPUpdate": {testStatefulLSPUpdate, TLVHeaderLength + 4},
	}
	runTLVLenTests(t, cases)
}

// TestStatefulPCECapability_CapStrings tests the CapStrings method for StatefulPCECapability.
func TestStatefulPCECapability_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"AllCapabilities": {testStatefulAll, testCapsAllStrings},
		"NoCapabilities":  {testStatefulNone, testCapsNoneStrings},
	}
	runCapStringsTests(t, cases)
}

// Test data for SymbolicPathName tests.
var (
	testSymbolicPathName            = NewSymbolicPathName("Test")
	testSymbolicPathNameWithPadding = NewSymbolicPathName("ABC") // with 1 padding byte
	testSymbolicPathNameEmptyString = NewSymbolicPathName("")

	// Serialized TLV bytes for SymbolicPathName "Test".
	testSymbolicPathNameBytes = []byte{
		byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff),
		0x00, 0x04, 'T', 'e', 's', 't',
	}
	// Serialized TLV bytes for an empty SymbolicPathName.
	testSymbolicPathNameEmptyBytes = []byte{
		byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff),
		0x00, 0x00,
	}
	// Serialized TLV bytes with an invalid UTF-8 sequence.
	testSymbolicPathNameInvalidUTF8Bytes = []byte{
		byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff),
		0x00, 0x01, 0xff,
	}
	// Declared TLV length is 2, but only 1 byte is provided.
	testSymbolicPathNameTooShort = []byte{
		byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff),
		0x00, 0x02, 'T',
	}
	// Declared TLV length is 1, but 2 bytes are provided.
	testSymbolicPathNameTooLong = []byte{
		byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff),
		0x00, 0x01, 'T', 'e',
	}
	// Incomplete TLV header (only 3 bytes).
	testSymbolicPathNameTruncatedHeader = []byte{
		byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xff), 0x00,
	}
)

// TestSymbolicPathName_DecodeFromBytes tests the DecodeFromBytes method for SymbolicPathName.
func TestSymbolicPathName_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidSymbolicPathName":  {testSymbolicPathNameBytes, testSymbolicPathName, false},
		"EmptySymbolicPathName":  {testSymbolicPathNameEmptyBytes, testSymbolicPathNameEmptyString, false},
		"InvalidUTF8Sequence":    {testSymbolicPathNameInvalidUTF8Bytes, nil, true},
		"InputTooShort":          {testSymbolicPathNameTruncatedHeader, nil, true},
		"DeclaredLengthTooShort": {testSymbolicPathNameTooShort, nil, true},
		"DeclaredLengthTooLong":  {testSymbolicPathNameTooLong, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SymbolicPathName{} })
}

// TestSymbolicPathName_Serialize tests the Serialize method for SymbolicPathName.
func TestSymbolicPathName_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidSymbolicPathName": {testSymbolicPathName, testSymbolicPathNameBytes},
		"EmptySymbolicPathName": {testSymbolicPathNameEmptyString, testSymbolicPathNameEmptyBytes},
	}
	runTLVSerializeTests(t, cases)
}

// TestSymbolicPathName_MarshalLogObject tests the MarshalLogObject method for SymbolicPathName.
func TestSymbolicPathName_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *SymbolicPathName
		expected string
	}{
		"ValidSymbolicPathName": {testSymbolicPathName, "Test"},
		"EmptySymbolicPathName": {testSymbolicPathNameEmptyString, ""},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)

			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields["symbolicPathName"], "unexpected value for '%s'", name)
		})
	}
}

// TestSymbolicPathName_Len tests the Len method for SymbolicPathName.
func TestSymbolicPathName_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidSymbolicPathNameLength":       {testSymbolicPathName, TLVHeaderLength + 4},
		"SymbolicPathNameWithPaddingLength": {testSymbolicPathNameWithPadding, TLVHeaderLength + 4}, // "ABC" + 1 padding
	}
	runTLVLenTests(t, cases)
}

// Test data for IPv4LSPIdentifiers tests.
var (
	// IPv4LSPIdentifiers with valid values.
	testIPv4LSPIdentifiers = NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234)
	// Serialized TLV bytes for testIPv4LSPIdentifiers.
	testIPv4LSPIdentifiersBytes = []byte{
		byte(TLVIPv4LSPIdentifiers >> 8), byte(TLVIPv4LSPIdentifiers & 0xff), 0x00, 0x10,
		0xc0, 0x00, 0x02, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, 0x02, // Endpoint Address
	}
	// Serialized TLV bytes for a truncated IPv4LSPIdentifiers (length mismatch).
	testIPv4LSPIdentifiersTruncated = []byte{
		byte(TLVIPv4LSPIdentifiers >> 8), byte(TLVIPv4LSPIdentifiers & 0xff), 0x00, 0x03,
		0xc0, 0x00, 0x02, // Missing one byte
	}
	// Serialized TLV bytes for IPv4LSPIdentifiers with extra bytes.
	testIPv4LSPIdentifiersExtra = []byte{
		byte(TLVIPv4LSPIdentifiers >> 8), byte(TLVIPv4LSPIdentifiers & 0xff), 0x00, 0x14,
		0xc0, 0x00, 0x02, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x04, 0xd2, // Extended Tunnel ID
		0xc0, 0x00, 0x02, 0x02, // Endpoint Address
		0xde, 0xad, 0xbe, 0xef, // Extra bytes
	}
)

// TestIPv4LSPIdentifiers_DecodeFromBytes tests the DecodeFromBytes method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidIPv4LSPIdentifiers":        {testIPv4LSPIdentifiersBytes, testIPv4LSPIdentifiers, false},
		"TruncatedIPv4LSPIdentifiers":    {testIPv4LSPIdentifiersTruncated, nil, true},
		"ExtraBytesInIPv4LSPIdentifiers": {testIPv4LSPIdentifiersExtra, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &IPv4LSPIdentifiers{} })
}

// TestIPv4LSPIdentifiers_Serialize tests the Serialize method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidIPv4LSPIdentifiers": {testIPv4LSPIdentifiers, testIPv4LSPIdentifiersBytes},
	}
	runTLVSerializeTests(t, cases)
}

// TestIPv4LSPIdentifiers_MarshalLogObject tests the MarshalLogObject method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_MarshalLogObject(t *testing.T) {
	tlv := &IPv4LSPIdentifiers{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)
	assert.NoError(t, err, "unexpected error during MarshalLogObject")
}

// TestIPv4LSPIdentifiers_Len tests the Len method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidIPv4LSPIdentifiersLength": {testIPv4LSPIdentifiers, TLVHeaderLength + TLVIPv4LSPIdentifiersValueLength},
	}
	runTLVLenTests(t, cases)
}

// Test data for IPv6LSPIdentifiers tests
var (
	// IPv6LSPIdentifiers with valid values.
	testIPv6LSPIdentifiers = NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{})
	// Serialized TLV bytes for testIPv6LSPIdentifiers.
	testIPv6LSPIdentifiersBytes = []byte{
		byte(TLVIPv6LSPIdentifiers >> 8), byte(TLVIPv6LSPIdentifiers & 0xff), 0x00, 0x34,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extended Tunnel ID
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Endpoint Address
	}
	// Serialized TLV bytes for a truncated IPv6LSPIdentifiers (length mismatch).
	testIPv6LSPIdentifiersTruncated = []byte{
		byte(TLVIPv6LSPIdentifiers >> 8), byte(TLVIPv6LSPIdentifiers & 0xff), 0x00, 0x1f, // Truncated length
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Incomplete
	}
	// Serialized TLV bytes for IPv6LSPIdentifiers with extra bytes.
	testIPv6LSPIdentifiersExtra = []byte{
		byte(TLVIPv6LSPIdentifiers >> 8), byte(TLVIPv6LSPIdentifiers & 0xff), 0x00, 0x38, // Extra length
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Sender Address
		0x00, 0x01, // LSP ID
		0x00, 0x02, // Tunnel ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extended Tunnel ID
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Endpoint Address
		0xca, 0xfe, 0xba, 0xbe, // Extra bytes
	}
)

// TestIPv6LSPIdentifiers_DecodeFromBytes tests the DecodeFromBytes method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidIPv6LSPIdentifiers":        {testIPv6LSPIdentifiersBytes, testIPv6LSPIdentifiers, false},
		"TruncatedIPv6LSPIdentifiers":    {testIPv6LSPIdentifiersTruncated, nil, true},
		"ExtraBytesInIPv6LSPIdentifiers": {testIPv6LSPIdentifiersExtra, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &IPv6LSPIdentifiers{} })
}

// TestIPv6LSPIdentifiers_Serialize tests the Serialize method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidIPv6LSPIdentifiers": {testIPv6LSPIdentifiers, testIPv6LSPIdentifiersBytes},
	}
	runTLVSerializeTests(t, cases)
}

// TestIPv6LSPIdentifiers_MarshalLogObject tests the MarshalLogObject method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_MarshalLogObject(t *testing.T) {
	tlv := &IPv6LSPIdentifiers{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)
	assert.NoError(t, err, "unexpected error during MarshalLogObject")
}

// TestIPv6LSPIdentifiers_Len tests the Len method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidIPv6LSPIdentifiersLength": {testIPv6LSPIdentifiers, TLVHeaderLength + TLVIPv6LSPIdentifiersValueLength},
	}
	runTLVLenTests(t, cases)
}

// Test data for LSPDBVersion tests
var (
	// LSPDBVersion with a valid version number.
	testLSPDBVersion = NewLSPDBVersion(12345)
	// Serialized TLV bytes for testLSPDBVersion.
	testLSPDBVersionBytes = append(tlvHeader(TLVLSPDBVersion, 8), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39)
	// Serialized TLV bytes for a truncated LSPDBVersion.
	testLSPDBVersionTruncated = append(tlvHeader(TLVLSPDBVersion, 4), 0x00, 0x00, 0x00, 0x00)
	// Serialized TLV bytes for LSPDBVersion with extra bytes.
	testLSPDBVersionExtra = append(tlvHeader(TLVLSPDBVersion, 16), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0xde, 0xad, 0xbe, 0xef)
)

// TestLSPDBVersion_DecodeFromBytes tests the DecodeFromBytes method for LSPDBVersion.
func TestLSPDBVersion_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidLSPDBVersion":        {testLSPDBVersionBytes, testLSPDBVersion, false},
		"TruncatedLSPDBVersion":    {testLSPDBVersionTruncated, nil, true},
		"ExtraBytesInLSPDBVersion": {testLSPDBVersionExtra, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &LSPDBVersion{} })
}

// TestLSPDBVersion_Serialize tests the Serialize method for LSPDBVersion.
func TestLSPDBVersion_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidLSPDBVersion": {testLSPDBVersion, testLSPDBVersionBytes},
	}
	runTLVSerializeTests(t, cases)
}

// TestLSPDBVersion_MarshalLogObject tests the MarshalLogObject method for LSPDBVersion.
func TestLSPDBVersion_MarshalLogObject(t *testing.T) {
	tlv := &LSPDBVersion{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)
	assert.NoError(t, err, "unexpected error during MarshalLogObject")
}

// TestLSPDBVersion_Len tests the Len method for LSPDBVersion.
func TestLSPDBVersion_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidLSPDBVersionLength": {testLSPDBVersion, TLVHeaderLength + TLVLSPDBVersionValueLength},
	}
	runTLVLenTests(t, cases)
}

// TestLSPDBVersion_CapStrings tests the CapStrings method for LSPDBVersion.
func TestLSPDBVersion_CapStrings(t *testing.T) {
	tlv := &LSPDBVersion{}
	expected := []string{"LSP-DB-VERSION"}
	actual := tlv.CapStrings()

	assert.Equal(t, expected, actual, "CapStrings() did not return expected value")
}

// Test data for SRPCECapability tests
var (
	// testSRPCECapability represents a valid SRPCECapability with true values and a maximum SID depth of 10.
	testSRPCECapability = NewSRPCECapability(true, true, 10)
	// testSRPCECapabilityBytes represents the serialized form of testSRPCECapability.
	testSRPCECapabilityBytes = append(tlvHeader(TLVSRPCECapability, 4), 0x03, 0x0a, 0x00, 0x00)
	// testSRPCECapabilityTruncated represents a truncated version of SRPCECapability data.
	testSRPCECapabilityTruncated = append(tlvHeader(TLVSRPCECapability, 4), 0x00, 0x02)
	// testSRPCECapabilityExtra represents an SRPCECapability with extra bytes.
	testSRPCECapabilityExtra = append(tlvHeader(TLVSRPCECapability, 8), 0x03, 0x05, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef)

	// testSRPCECapabilityValid is a valid SRPCECapability instance with proper values.
	testSRPCECapabilityValid = &SRPCECapability{
		HasUnlimitedMaxSIDDepth: true,
		IsNAISupported:          true,
		MaximumSidDepth:         10,
	}
	// testSRPCECapabilityDefault is an SRPCECapability instance with default values (false, false, 0).
	testSRPCECapabilityDefault = &SRPCECapability{
		HasUnlimitedMaxSIDDepth: false,
		IsNAISupported:          false,
		MaximumSidDepth:         0,
	}

	// validSRPCECapabilityValues represents the expected values for a valid SRPCECapability.
	validSRPCECapabilityValues = map[string]interface{}{
		"unlimited_max_sid_depth": true,
		"nai_is_supported":        true,
		"maximum_sid_depth":       uint8(10),
	}
	// defaultSRPCECapabilityValues represents the default values for SRPCECapability.
	defaultSRPCECapabilityValues = map[string]interface{}{
		"unlimited_max_sid_depth": false,
		"nai_is_supported":        false,
		"maximum_sid_depth":       uint8(0),
	}

	testSRPCECapabilityAllEnabledInput       = &SRPCECapability{HasUnlimitedMaxSIDDepth: true, IsNAISupported: true}
	testSRPCECapabilityUnlimitedOnlyInput    = &SRPCECapability{HasUnlimitedMaxSIDDepth: true}
	testSRPCECapabilityNAIOnlyInput          = &SRPCECapability{IsNAISupported: true}
	testSRPCECapabilityNoneEnabledInput      = &SRPCECapability{}
	testSRPCECapabilityAllEnabledExpected    = []string{"Unlimited-SID-Depth", "NAI-Supported"}
	testSRPCECapabilityUnlimitedOnlyExpected = []string{"Unlimited-SID-Depth"}
	testSRPCECapabilityNAIOnlyExpected       = []string{"NAI-Supported"}
	testSRPCECapabilityNoneEnabledExpected   = []string(nil)
)

// TestSRPCECapability_DecodeFromBytes tests the DecodeFromBytes method for SRPCECapability.
func TestSRPCECapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidSRPCECapability":        {testSRPCECapabilityBytes, testSRPCECapability, false},
		"TruncatedSRPCECapability":    {testSRPCECapabilityTruncated, nil, true},
		"ExtraBytesInSRPCECapability": {testSRPCECapabilityExtra, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SRPCECapability{} })
}

// TestSRPCECapability_Serialize tests the Serialize method for SRPCECapability.
func TestSRPCECapability_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"ValidSRPCECapability": {testSRPCECapability, testSRPCECapabilityBytes},
	}
	runTLVSerializeTests(t, cases)
}

// TestSRPCECapability_MarshalLogObject tests the MarshalLogObject method for SRPCECapability.
func TestSRPCECapability_MarshalLogObject(t *testing.T) {
	tlv := &SRPCECapability{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)
	assert.NoError(t, err, "unexpected error during MarshalLogObject")
}

// TestSRPCECapability_Len tests the Len method for SRPCECapability.
func TestSRPCECapability_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"ValidSRPCECapabilityLength": {testSRPCECapability, TLVHeaderLength + TLVSRPCECapabilityValueLength},
	}
	runTLVLenTests(t, cases)
}

// TestSRPCECapability_CapStrings tests the CapStrings method for SRPCECapability.
func TestSRPCECapability_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"AllCapabilitiesEnabled":          {testSRPCECapabilityAllEnabledInput, testSRPCECapabilityAllEnabledExpected},
		"OnlyUnlimitedMaxSIDDepthEnabled": {testSRPCECapabilityUnlimitedOnlyInput, testSRPCECapabilityUnlimitedOnlyExpected},
		"OnlyNAISupportedEnabled":         {testSRPCECapabilityNAIOnlyInput, testSRPCECapabilityNAIOnlyExpected},
		"NoCapabilitiesEnabled":           {testSRPCECapabilityNoneEnabledInput, testSRPCECapabilityNoneEnabledExpected},
	}
	runCapStringsTests(t, cases)
}

// TestPst_String tests the String method for Pst.
func TestPst_String(t *testing.T) {
	cases := map[string]struct {
		input    Pst
		expected string
	}{
		"Known PathSetupType":   {Pst(0x01), "Traffic engineering path is set up using Segment Routing (RFC8664)"},
		"Unknown PathSetupType": {Pst(0xff), "Unknown PathSetupType (0xff)"},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.input.String()
			assert.Equal(t, tt.expected, actual, "unexpected Pst.String() result for %s", name)
		})
	}
}

// TestPsts_MarshalJSON tests the MarshalJSON method for Psts.
func TestPsts_MarshalJSON(t *testing.T) {
	cases := map[string]struct {
		input    Psts
		expected string
	}{
		"Nil Psts":      {nil, "null"},
		"Empty Psts":    {Psts{}, ""},
		"Single Pst":    {Psts{Pst(0x01)}, "1"},
		"Multiple Psts": {Psts{Pst(0x01), Pst(0x02)}, "1,2"},
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual, err := tt.input.MarshalJSON()
			assert.NoError(t, err, "MarshalJSON returned unexpected error for %s", name)
			assert.Equal(t, tt.expected, string(actual), "MarshalJSON output mismatch for %s", name)
		})
	}
}

// Test data for PathSetupType tests
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
	testPathSetupTypeTooLong = append(NewPathSetupType(PathSetupTypeSRTE).Serialize(), 0x00, 0x00)
)

// TestPathSetupType_DecodeFromBytes tests the DecodeFromBytes method for PathSetupType.
func TestPathSetupType_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"Valid PathSetupType SRv6TE": {testPathSetupTypeSRv6TEBytes, testPathSetupTypeSRv6TE, false},
		"Invalid input (too short)":  {testPathSetupTypeTooShort, nil, true},
		"Invalid input (too long)":   {testPathSetupTypeTooLong, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &PathSetupType{} })
}

// TestPathSetupType_Serialize tests the Serialize method for PathSetupType.
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

// TestPathSetupType_MarshalLogObject tests the MarshalLogObject method for PathSetupType.
func TestPathSetupType_MarshalLogObject(t *testing.T) {
	tlv := &PathSetupType{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)
	assert.NoError(t, err, "unexpected error during MarshalLogObject")
}

// TestPathSetupType_Len tests the Len method for PathSetupType.
func TestPathSetupType_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"Valid PathSetupType Length": {testPathSetupTypeRSVPTE, TLVHeaderLength + TLVPathSetupTypeValueLength},
	}
	runTLVLenTests(t, cases)
}

// Test data for ExtendedAssociationID tests
var (
	testIPv4ExtendedAssociationID = NewExtendedAssociationID(1, netip.MustParseAddr("127.0.0.1"))
	testIPv6ExtendedAssociationID = NewExtendedAssociationID(1, netip.MustParseAddr("2001:db8::1"))

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
)

// TestExtendedAssociationID_DecodeFromBytes tests the DecodeFromBytes method for ExtendedAssociationID.
func TestExtendedAssociationID_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidIPv4":         {testIPv4ExtendedAssociationIDBytes, testIPv4ExtendedAssociationID, false},
		"ValidIPv6":         {testIPv6ExtendedAssociationIDBytes, testIPv6ExtendedAssociationID, false},
		"TooShort":          {testExtendedAssociationIDTooShort, nil, true},
		"InvalidLength":     {testExtendedAssociationIDInvalidLen, nil, true},
		"UnsupportedLength": {testExtendedAssociationIDUnsupportedLen, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &ExtendedAssociationID{} })
}

// TestExtendedAssociationID_Serialize tests the Serialize method for ExtendedAssociationID.
func TestExtendedAssociationID_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"SerializeIPv4": {testIPv4ExtendedAssociationID, testIPv4ExtendedAssociationIDBytes},
		"SerializeIPv6": {testIPv6ExtendedAssociationID, testIPv6ExtendedAssociationIDBytes},
	}
	runTLVSerializeTests(t, cases)
}

// TestExtendedAssociationID_MarshalLogObject tests the MarshalLogObject method for ExtendedAssociationID.
func TestExtendedAssociationID_MarshalLogObject(t *testing.T) {
	tlv := &ExtendedAssociationID{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)
	assert.NoError(t, err, "unexpected error during MarshalLogObject")
}

// TestExtendedAssociationID_Len tests the Len method for ExtendedAssociationID.
func TestExtendedAssociationID_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"IPv4Length":        {testIPv4ExtendedAssociationID, TLVHeaderLength + TLVExtendedAssociationIDIPv4ValueLength},
		"IPv6Length":        {testIPv6ExtendedAssociationID, TLVHeaderLength + TLVExtendedAssociationIDIPv6ValueLength},
		"UnsupportedLength": {&ExtendedAssociationID{Color: 1}, 0},
	}
	runTLVLenTests(t, cases)
}
