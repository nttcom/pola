// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

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
		"SRv6PCECapability":       {TLVSRv6PCECapability, &SRv6PCECapability{}},
		"MultipathCapability":     {TLVMultipathCap, &MultipathCapability{}},
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
				assert.NoError(t, err, "unexpected error for '%s'", name)
				assert.Equal(t, tt.expected, tlv, "decoded value mismatch for '%s'", name)
			}
		})
	}
}

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

func tlvHeader(tlvType TLVType, length uint16) []byte {
	return []byte{byte(tlvType >> 8), byte(tlvType & 0xff), byte(length >> 8), byte(length & 0xff)}
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
	testCapsAllStrings         = []string{"Stateful", "Update", "Include-DB-Ver", "Instantiation", "Triggered-Resync", "Delta-LSP-Sync", "Triggered-Initial-Sync", "Color"}
	testCapsNoneStrings        = []string{"Stateful"}
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

func TestStatefulPCECapability_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *StatefulPCECapability
		expected bool
	}{
		"LSPUpdateEnabled":  {testStatefulLSPUpdate, true},
		"LSPUpdateDisabled": {testStatefulNone, false},
		"NilTLV":            {nil, false},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)

			got, ok := enc.Fields["lspUpdateCapability"]
			if tt.input == nil {
				assert.False(t, ok, "expected no lspUpdateCapability field for nil TLV")
			} else {
				assert.Equal(t, tt.expected, got, "unexpected value for '%s'", name)
			}
		})
	}
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

func TestSymbolicPathName_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *SymbolicPathName
		expected string
	}{
		"Valid":  {testSymbolicPathName, "Test"},
		"Empty":  {testSymbolicPathNameEmptyString, ""},
		"NilTLV": {nil, ""},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)

			if tt.input == nil {
				_, ok := enc.Fields["symbolicPathName"]
				assert.False(t, ok, "expected no symbolicPathName field for nil TLV")
			} else {
				assert.Equal(t, tt.expected, enc.Fields["symbolicPathName"], "unexpected value for '%s'", name)
			}
		})
	}
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

// Test data for IPv4LSPIdentifiers.
var (
	testIPv4LSPIdentifiers      = NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234)
	testIPv4LSPIdentifiersBytes = append(tlvHeader(TLVIPv4LSPIdentifiers, TLVIPv4LSPIdentifiersValueLength),
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

func TestIPv4LSPIdentifiers_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *IPv4LSPIdentifiers
		expected map[string]any
	}{
		"NilTLV": {nil, map[string]any{}},
		"EmptyTLV": {
			&IPv4LSPIdentifiers{
				LSPID:            1,
				TunnelID:         2,
				ExtendedTunnelID: 1234,
			},
			map[string]any{
				"lspID":            uint16(1),
				"tunnelID":         uint16(2),
				"extendedTunnelID": uint32(1234),
			},
		},
		"FullTLV": {
			testIPv4LSPIdentifiers,
			map[string]any{
				"ipv4TunnelSenderAddress":   "192.0.2.1",
				"ipv4TunnelEndpointAddress": "192.0.2.2",
				"lspID":                     uint16(1),
				"tunnelID":                  uint16(2),
				"extendedTunnelID":          uint32(1234),
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
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

	// TLV bytes with intentionally invalid value length (to cover valueLen != expected case)
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

func TestIPv6LSPIdentifiers_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *IPv6LSPIdentifiers
		expected map[string]any
	}{
		"NilTLV": {nil, map[string]any{}},
		"EmptyTLV": {
			&IPv6LSPIdentifiers{
				LSPID:            1,
				TunnelID:         2,
				ExtendedTunnelID: [IPv6AddrLen]byte{},
			},
			map[string]any{
				"lspID":            uint16(1),
				"tunnelID":         uint16(2),
				"extendedTunnelID": "00000000000000000000000000000000",
			},
		},
		"FullTLV": {
			testIPv6LSPIdentifiers,
			map[string]any{
				"ipv6TunnelSenderAddress":   "2001:db8::1",
				"ipv6TunnelEndpointAddress": "2001:db8::2",
				"lspID":                     uint16(1),
				"tunnelID":                  uint16(2),
				"extendedTunnelID":          "00000000000000000000000000000000",
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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
	testLSPDBVersionCapStrings    = []string{"LSP-DB-VERSION"}
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

func TestLSPDBVersion_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *LSPDBVersion
		expected map[string]any
	}{
		"NilTLV": {nil, map[string]any{}},
		"EmptyTLV": {
			&LSPDBVersion{},
			map[string]any{
				"versionNumber": uint64(0),
			},
		},
		"FullTLV": {
			testLSPDBVersion,
			map[string]any{
				"versionNumber": uint64(12345),
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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

func TestLSPDBVersion_CapStrings(t *testing.T) {
	tlv := &LSPDBVersion{}
	actual := tlv.CapStrings()
	assert.Equal(t, testLSPDBVersionCapStrings, actual, "CapStrings() did not return expected value")
}

// Test data for SRPCECapability.
var (
	testSRPCECapability               = NewSRPCECapability(true, true, 10)
	testSRPCECapabilityBytes          = append(tlvHeader(TLVSRPCECapability, 4), 0x03, 0x0a, 0x00, 0x00)
	testSRPCECapabilityTruncated      = append(tlvHeader(TLVSRPCECapability, 4), 0x00, 0x02)
	testSRPCECapabilityExtra          = append(tlvHeader(TLVSRPCECapability, 4), 0x03, 0x05, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef)
	testSRPCECapabilityInvalidLength  = append(tlvHeader(TLVSRPCECapability, 8), 0x03, 0x05, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef)
	testSRPCECapabilityAllEnabled     = &SRPCECapability{HasUnlimitedMaxSIDDepth: true, IsNAISupported: true}
	testSRPCECapabilityUnlimitedOnly  = &SRPCECapability{HasUnlimitedMaxSIDDepth: true}
	testSRPCECapabilityNAIOnly        = &SRPCECapability{IsNAISupported: true}
	testSRPCECapabilityNoneEnabled    = &SRPCECapability{}
	testSRPCECapabilityAllEnabledStrs = []string{"Unlimited-SID-Depth", "NAI-Supported"}
	testSRPCECapabilityUnlimitedStrs  = []string{"Unlimited-SID-Depth"}
	testSRPCECapabilityNAIStrs        = []string{"NAI-Supported"}
	testSRPCECapabilityNoneStrs       = []string(nil)
)

func TestSRPCECapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidSRPCECapability":         {testSRPCECapabilityBytes, testSRPCECapability, false},
		"TruncatedSRPCECapability":     {testSRPCECapabilityTruncated, nil, true},
		"ExtraBytesInSRPCECapability":  {testSRPCECapabilityExtra, nil, true},
		"InvalidLengthSRPCECapability": {testSRPCECapabilityInvalidLength, nil, true},
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

func TestSRPCECapability_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *SRPCECapability
		expected map[string]any
	}{
		"NilTLV": {nil, map[string]any{}},
		"EmptyTLV": {
			&SRPCECapability{},
			map[string]any{
				"unlimited_max_sid_depth": false,
				"nai_is_supported":        false,
				"maximum_sid_depth":       uint8(0),
			},
		},
		"FullTLV": {
			testSRPCECapability,
			map[string]any{
				"unlimited_max_sid_depth": true,
				"nai_is_supported":        true,
				"maximum_sid_depth":       uint8(10),
			},
		},
		"OnlyUnlimited": {
			testSRPCECapabilityUnlimitedOnly,
			map[string]any{
				"unlimited_max_sid_depth": true,
				"nai_is_supported":        false,
				"maximum_sid_depth":       uint8(0),
			},
		},
		"OnlyNAI": {
			testSRPCECapabilityNAIOnly,
			map[string]any{
				"unlimited_max_sid_depth": false,
				"nai_is_supported":        true,
				"maximum_sid_depth":       uint8(0),
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
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

func TestSRPCECapability_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"AllCapabilitiesEnabled":          {testSRPCECapabilityAllEnabled, testSRPCECapabilityAllEnabledStrs},
		"OnlyUnlimitedMaxSIDDepthEnabled": {testSRPCECapabilityUnlimitedOnly, testSRPCECapabilityUnlimitedStrs},
		"OnlyNAISupportedEnabled":         {testSRPCECapabilityNAIOnly, testSRPCECapabilityNAIStrs},
		"NoCapabilitiesEnabled":           {testSRPCECapabilityNoneEnabled, testSRPCECapabilityNoneStrs},
	}
	runCapStringsTests(t, cases)
}

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
			assert.Equal(t, tt.expected, actual, "unexpected Pst.String() result for '%s'", name)
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
			assert.NoError(t, err, "unexpected error for '%s'", name)
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
	testPathSetupTypeTooLong = append(NewPathSetupType(PathSetupTypeSRTE).Serialize(), 0x00, 0x00)
	// Invalid input for PathSetupType (value length mismatch)
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

func TestPathSetupType_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *PathSetupType
		expected map[string]any
	}{
		"NilTLV": {nil, map[string]any{}},
		"SRTE": {
			testPathSetupTypeSRTE,
			map[string]any{
				"pathSetupType": "Traffic engineering path is set up using Segment Routing (RFC8664)",
			},
		},
		"RSVPTE": {
			testPathSetupTypeRSVPTE,
			map[string]any{
				"pathSetupType": "Path is set up using the RSVP-TE signaling protocol (RFC8408)",
			},
		},
		"SRv6TE": {
			testPathSetupTypeSRv6TE,
			map[string]any{
				"pathSetupType": "Traffic engineering path is set up using SRv6 (RFC9603)",
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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
	// PathSetupTypeCapability instances
	testPathSetupTypeCapabilityBasic = &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeRSVPTE, PathSetupTypeSRTE},
		SubTLVs:        []TLVInterface{},
	}
	testPathSetupTypeCapabilityWithSubTLV = &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeSRTE},
		SubTLVs:        []TLVInterface{NewSRPCECapability(true, true, 10)},
	}

	// Serialized TLV bytes
	testPathSetupTypeCapabilityBasicBytes = []byte{
		0x00, 0x22, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x00, 0x00,
	}
	testPathSetupTypeCapabilityWithSubTLVBytes = []byte{
		0x00, 0x22, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x01,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x1a, 0x00, 0x04, 0x03, 0x0a, 0x00, 0x00,
	}

	// Invalid / error test cases
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

func TestPathSetupTypeCapability_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *PathSetupTypeCapability
		expected map[string]any
	}{
		"Basic": {
			testPathSetupTypeCapabilityBasic,
			map[string]any{
				"pathSetupTypes": []any{
					"Path is set up using the RSVP-TE signaling protocol (RFC8408)",
					"Traffic engineering path is set up using Segment Routing (RFC8664)",
				},
				"subTLVs": []any{},
			},
		},
		"WithSub": {
			testPathSetupTypeCapabilityWithSubTLV,
			map[string]any{
				"pathSetupTypes": []any{
					"Traffic engineering path is set up using Segment Routing (RFC8664)",
				},
				"subTLVs": []any{"0x53522d5043452d4341504142494c49545920285246433836363429 (SR-PCE-CAPABILITY (RFC8664))"},
			},
		},
		"NilTLV": {
			nil,
			map[string]any{},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, enc.Fields)
		})
	}
}

func TestPathSetupTypeCapability_Len(t *testing.T) {
	var subTLVLen uint16
	for _, s := range testPathSetupTypeCapabilityWithSubTLV.SubTLVs {
		subTLVLen += s.Len()
	}

	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"Basic":   {input: testPathSetupTypeCapabilityBasic, expected: TLVValueOffset + PathSetupTypeCapabilityFixedPartLength + testPathSetupTypeCapabilityBasic.paddedPSTLength()},
		"WithSub": {input: testPathSetupTypeCapabilityWithSubTLV, expected: TLVValueOffset + PathSetupTypeCapabilityFixedPartLength + testPathSetupTypeCapabilityWithSubTLV.paddedPSTLength() + subTLVLen},
	}
	runTLVLenTests(t, cases)
}

func TestPathSetupTypeCapability_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"SRTEAndSRv6TE":        {&PathSetupTypeCapability{PathSetupTypes: Psts{PathSetupTypeSRTE, PathSetupTypeSRv6TE}}, []string{"SR-TE", "SRv6-TE"}},
		"SRTEOnly":             {&PathSetupTypeCapability{PathSetupTypes: Psts{PathSetupTypeSRTE}}, []string{"SR-TE"}},
		"SRv6TEOnly":           {&PathSetupTypeCapability{PathSetupTypes: Psts{PathSetupTypeSRv6TE}}, []string{"SRv6-TE"}},
		"NeitherSRTENorSRv6TE": {&PathSetupTypeCapability{PathSetupTypes: Psts{PathSetupTypeRSVPTE}}, []string{}},
	}
	runCapStringsTests(t, cases)
}

func TestAssocType_String(t *testing.T) {
	cases := map[string]struct {
		input    AssocType
		expected string
	}{
		"PathProtection":   {AssocTypePathProtectionAssociation, "Path Protection Association"},
		"Disjoint":         {AssocTypeDisjointAssociation, "Disjoint Association"},
		"Policy":           {AssocTypePolicyAssociation, "Policy Association"},
		"SingleSidedBidir": {AssocTypeSingleSidedBidirectionalLSPAssociation, "Single Sided Bidirectional LSP Association"},
		"DoubleSidedBidir": {AssocTypeDoubleSidedBidirectionalLSPAssociation, "Double Sided Bidirectional LSP Association"},
		"SRPolicy":         {AssocTypeSRPolicyAssociation, "SR Policy Association"},
		"VnAssociation":    {AssocTypeVnAssociationType, "VN Association Type"},
		"Unknown":          {AssocType(0xffff), "Unknown AssocType (0xffff)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.input.String()
			assert.Equal(t, tt.expected, actual, "unexpected AssocType.String() result for '%s'", name)
		})
	}
}

// Test data for ExtendedAssociationID.
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
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestExtendedAssociationID_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *ExtendedAssociationID
		expected map[string]any
	}{
		"IPv4": {
			NewExtendedAssociationID(123, netip.MustParseAddr("192.0.2.1")),
			map[string]any{
				"color":    uint32(123),
				"ipv4Addr": "192.0.2.1",
			},
		},
		"IPv6": {
			NewExtendedAssociationID(456, netip.MustParseAddr("2001:db8::1")),
			map[string]any{
				"color":    uint32(456),
				"ipv6Addr": "2001:db8::1",
			},
		},
		"NilTLV": {
			nil,
			map[string]any{},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error during MarshalLogObject for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
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

func TestAssocTypeList_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *AssocTypeList
		expected map[string]any
	}{
		"TwoEntries": {
			testAssocTypeList,
			map[string]any{
				"assocTypes": []any{
					"Path Protection Association",
					"SR Policy Association",
				},
			},
		},
		"SingleEntry": {
			testAssocTypeListSingle,
			map[string]any{
				"assocTypes": []any{"Path Protection Association"},
			},
		},
		"FourEntries": {
			testAssocTypeListFour,
			map[string]any{
				"assocTypes": []any{
					"Path Protection Association",
					"Disjoint Association",
					"Policy Association",
					"SR Policy Association",
				},
			},
		},
		"EmptyList": {
			testAssocTypeListEmpty,
			map[string]any{
				"assocTypes": []any{},
			},
		},
		"NilTLV": {
			nil,
			map[string]any{},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, enc.Fields)
		})
	}
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

func TestAssocTypeList_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"EmptyList": {&AssocTypeList{}, []string{}},
	}
	runCapStringsTests(t, cases)
}

// Test data for SRPolicyCandidatePathIdentifier.
var (
	testSRPolicyCPathIDIPv4 = &SRPolicyCandidatePathIdentifier{OriginatorAddr: netip.AddrFrom4([4]byte{192, 0, 2, 1})} // IPv4 originator
	testSRPolicyCPathIDIPv6 = &SRPolicyCandidatePathIdentifier{OriginatorAddr: netip.MustParseAddr("2001:db8::1")}     // IPv6 originator

	testSRPolicyCPathIDIPv4Bytes = []byte{
		0x00, 0x39, 0x00, 0x1c, // type=0x0039, len=28
		0x0a, 0x00, 0x00, 0x00, // protocol=0x0a + mbz
		0x00, 0x00, 0x00, 0x00, // ASN=0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originator addr padding
		0xc0, 0x00, 0x02, 0x01, // IPv4 addr
		0x00, 0x00, 0x00, 0x01, // discriminator
	}

	testSRPolicyCPathIDIPv6Bytes = []byte{
		0x00, 0x39, 0x00, 0x1c, // type=0x0039, len=28
		0x0a, 0x00, 0x00, 0x00, // protocol + mbz
		0x00, 0x00, 0x00, 0x00, // ASN
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IPv6 addr
		0x00, 0x00, 0x00, 0x01, // discriminator
	}

	testSRPolicyCPathIDTooShort        = []byte{0x00, 0x39, 0x00, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // Less than 16 bytes for OriginatorAddr
	testSRPolicyCPathIDTruncatedHeader = []byte{0x00, 0x39, 0x00}                                                                   // Truncated header (less than 4 bytes)

	testSRPolicyCPathIDInvalid = &SRPolicyCandidatePathIdentifier{
		OriginatorAddr: netip.Addr{}, // zero value, IsValid() == false
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
)

func TestSRPolicyCandidatePathIdentifier_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidIPv4":       {testSRPolicyCPathIDIPv4Bytes, testSRPolicyCPathIDIPv4, false},
		"ValidIPv6":       {testSRPolicyCPathIDIPv6Bytes, testSRPolicyCPathIDIPv6, false},
		"TooShort":        {testSRPolicyCPathIDTooShort, nil, true},
		"TruncatedHeader": {testSRPolicyCPathIDTruncatedHeader, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &SRPolicyCandidatePathIdentifier{} })
}

func TestSRPolicyCandidatePathIdentifier_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"SerializeIPv4": {testSRPolicyCPathIDIPv4, testSRPolicyCPathIDIPv4Bytes},
		"SerializeIPv6": {testSRPolicyCPathIDIPv6, testSRPolicyCPathIDIPv6Bytes},
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

func TestSRPolicyCandidatePathIdentifier_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *SRPolicyCandidatePathIdentifier
		expected map[string]any
	}{
		"IPv4": {
			testSRPolicyCPathIDIPv4,
			map[string]any{
				"originatorAddr": testSRPolicyCPathIDIPv4.OriginatorAddr.String(),
			},
		},
		"IPv6": {
			testSRPolicyCPathIDIPv6,
			map[string]any{
				"originatorAddr": testSRPolicyCPathIDIPv6.OriginatorAddr.String(),
			},
		},
		"NilTLV": {
			nil,
			map[string]any{},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error during MarshalLogObject for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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

// Test data for SRPolicyCandidatePathPreference.
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

func TestSRPolicyCandidatePathPreference_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *SRPolicyCandidatePathPreference
		expected map[string]any
	}{
		"Preference": {
			testSRPolicyCPathPreference,
			map[string]any{
				"preference": testSRPolicyCPathPreference.Preference,
			},
		},
		"NilTLV": {
			nil,
			map[string]any{},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error during MarshalLogObject for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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

func TestColor_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *Color
		expected map[string]any
	}{
		"ValidColor": {
			testColor,
			map[string]any{
				"color": testColor.Color,
			},
		},
		"ZeroColor": {
			&Color{Color: 0},
			map[string]any{
				"color": uint32(0),
			},
		},
		"NilTLV": {
			nil,
			map[string]any{},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error during MarshalLogObject for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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

// Test data for UndefinedTLV.
var (
	// Standard 4-byte UndefinedTLV
	testUndefinedTLV = &UndefinedTLV{
		Typ:    TLVType(0xffff),
		Length: 4,
		Value:  []byte{0xde, 0xad, 0xbe, 0xef},
	}
	// 3-byte value (odd → 1 byte padding required)
	testUndefinedTLVOddLength = &UndefinedTLV{
		Typ:    TLVType(0xffff),
		Length: 3,
		Value:  []byte{0x01, 0x02, 0x03},
	}

	// Serialized TLV bytes
	testUndefinedTLVBytes           = []byte{0xff, 0xff, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef}
	testUndefinedTLVOddLengthBytes  = []byte{0xff, 0xff, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00}
	testUndefinedTLVTruncatedHeader = []byte{0xff, 0xff, 0x00}
	testUndefinedTLVTruncatedValue  = []byte{0xff, 0xff, 0x00, 0x08, 0x01, 0x02}
)

func TestUndefinedTLV_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidUndefinedTLV": {testUndefinedTLVBytes, testUndefinedTLV, false},
		"TruncatedHeader":   {testUndefinedTLVTruncatedHeader, nil, true},
		"TruncatedValue":    {testUndefinedTLVTruncatedValue, nil, true},
	}
	runTLVDecodeTests(t, cases, func() TLVInterface { return &UndefinedTLV{} })
}

func TestUndefinedTLV_Serialize(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected []byte
	}{
		"AlignedValue":   {testUndefinedTLV, testUndefinedTLVBytes},
		"UnalignedValue": {testUndefinedTLVOddLength, testUndefinedTLVOddLengthBytes},
	}
	runTLVSerializeTests(t, cases)
}

func TestUndefinedTLV_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *UndefinedTLV
		expected map[string]any
	}{
		"StandardTLV": {
			testUndefinedTLV,
			map[string]any{
				"type":   fmt.Sprintf("0x%04x", testUndefinedTLV.Typ),
				"length": testUndefinedTLV.Length,
			},
		},
		"OddLength": {
			testUndefinedTLVOddLength,
			map[string]any{
				"type":   fmt.Sprintf("0x%04x", testUndefinedTLVOddLength.Typ),
				"length": testUndefinedTLVOddLength.Length,
			},
		},
		"NilTLV": {
			nil,
			map[string]any{},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error during MarshalLogObject for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
}

func TestUndefinedTLV_Len(t *testing.T) {
	cases := map[string]struct {
		input    TLVInterface
		expected uint16
	}{
		"AlignedLen":   {testUndefinedTLV, TLVValueOffset + 4},          // 4-byte value
		"UnalignedLen": {testUndefinedTLVOddLength, TLVValueOffset + 4}, // 3-byte value + 1 pad = 4
	}
	runTLVLenTests(t, cases)
}

func TestUndefinedTLV_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"UnknownType42": {
			input:    &UndefinedTLV{Typ: TLVType(42)},
			expected: []string{"unknown_type_42"},
		},
	}

	runCapStringsTests(t, cases)
}

func TestUndefinedTLV_SetLength(t *testing.T) {
	tlv := &UndefinedTLV{Value: []byte{0x01, 0x02, 0x03}}
	tlv.SetLength()
	assert.Equal(t, uint16(3), tlv.Length, "SetLength() should set Length to len(Value)")
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
		tlv := append(header, body...)
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
	value := append(fixedPart, pathSetupType...)
	value = append(value, subTLV...)
	header := tlvHeader(TLVPathSetupTypeCapability, uint16(len(value)))
	data := append(header, value...)

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
	testSRv6PCECapability           = NewSRv6PCECapability(true)
	testSRv6PCECapabilityBytes      = append(tlvHeader(TLVSRv6PCECapability, 4), 0x00, 0x00, 0x00, 0x02)
	testSRv6PCECapabilityNoNAIBytes = append(tlvHeader(TLVSRv6PCECapability, 4), 0x00, 0x00, 0x00, 0x00)
	testSRv6PCECapabilityExtended   = append(tlvHeader(TLVSRv6PCECapability, 8), 0x00, 0x00, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef)
	testSRv6PCECapabilityTruncated  = append(tlvHeader(TLVSRv6PCECapability, 4), 0x00, 0x00)
	testSRv6PCECapabilityNoNAI      = &SRv6PCECapability{}
	testSRv6PCECapabilityNAIStrs    = []string{"SRv6", "NAI-Supported"}
	testSRv6PCECapabilityNoNAIStrs  = []string{"SRv6"}
)

func TestSRv6PCECapability_DecodeFromBytes(t *testing.T) {
	cases := map[string]TLVTestCase{
		"ValidSRv6PCECapability":          {testSRv6PCECapabilityBytes, testSRv6PCECapability, false},
		"ValidSRv6PCECapabilityNoNAI":     {testSRv6PCECapabilityNoNAIBytes, testSRv6PCECapabilityNoNAI, false},
		"ExtendedLengthSRv6PCECapability": {testSRv6PCECapabilityExtended, testSRv6PCECapability, false},
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

func TestSRv6PCECapability_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *SRv6PCECapability
		expected map[string]any
	}{
		"NilTLV": {nil, map[string]any{}},
		"EmptyTLV": {
			&SRv6PCECapability{},
			map[string]any{
				"nai_is_supported": false,
			},
		},
		"FullTLV": {
			testSRv6PCECapability,
			map[string]any{
				"nai_is_supported": true,
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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

func TestSRv6PCECapability_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"NAISupported":    {testSRv6PCECapability, testSRv6PCECapabilityNAIStrs},
		"NAINotSupported": {testSRv6PCECapabilityNoNAI, testSRv6PCECapabilityNoNAIStrs},
	}
	runCapStringsTests(t, cases)
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

			data := original.Serialize()
			require.Equal(t, int(original.Len()), len(data), "Len() must match serialized size")

			decoded, err := DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*SRv6PCECapability)
			require.Truef(t, ok, "expected *SRv6PCECapability, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			assert.Equal(t, data, got.Serialize(), "re-serialized bytes differ")
		})
	}
}

// Test data for MultipathCapability.
var (
	testMultipathCapability = NewMultipathCapability(8, true, true, true, true)
	// MaxMultipaths=8 (0x0008), Flags=W|O|F|C = 0x001D
	testMultipathCapabilityBytes        = append(tlvHeader(TLVMultipathCap, 4), 0x00, 0x08, 0x00, 0x1d)
	testMultipathCapabilityNoFlags      = NewMultipathCapability(1, false, false, false, false)
	testMultipathCapabilityNoFlagsBytes = append(tlvHeader(TLVMultipathCap, 4), 0x00, 0x01, 0x00, 0x00)
	testMultipathCapabilityTruncated    = append(tlvHeader(TLVMultipathCap, 4), 0x00, 0x08)
	testMultipathCapabilityInvalidLen   = append(tlvHeader(TLVMultipathCap, 8), 0x00, 0x08, 0x00, 0x0f, 0xde, 0xad, 0xbe, 0xef)
	testMultipathCapabilityCapStrs      = []string{"Multipath"}
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

func TestMultipathCapability_MarshalLogObject(t *testing.T) {
	cases := map[string]struct {
		input    *MultipathCapability
		expected map[string]any
	}{
		"NilTLV": {nil, map[string]any{}},
		"EmptyTLV": {
			&MultipathCapability{},
			map[string]any{
				"max_multipaths":              uint16(0),
				"weighted_is_supported":       false,
				"opposite_dir_is_supported":   false,
				"forward_class_is_supported":  false,
				"composite_path_is_supported": false,
			},
		},
		"FullTLV": {
			testMultipathCapability,
			map[string]any{
				"max_multipaths":              uint16(8),
				"weighted_is_supported":       true,
				"opposite_dir_is_supported":   true,
				"forward_class_is_supported":  true,
				"composite_path_is_supported": true,
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.input.MarshalLogObject(enc)
			assert.NoError(t, err, "unexpected error for '%s'", name)
			assert.Equal(t, tt.expected, enc.Fields, "unexpected fields for '%s'", name)
		})
	}
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

func TestMultipathCapability_CapStrings(t *testing.T) {
	cases := map[string]struct {
		input    CapStringsInterface
		expected []string
	}{
		"AllFlagsEnabled": {testMultipathCapability, testMultipathCapabilityCapStrs},
		"NoFlagsEnabled":  {testMultipathCapabilityNoFlags, testMultipathCapabilityCapStrs},
	}
	runCapStringsTests(t, cases)
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

			data := original.Serialize()
			require.Equal(t, int(original.Len()), len(data), "Len() must match serialized size")

			decoded, err := DecodeTLV(data)
			require.NoError(t, err, "DecodeTLV failed")

			got, ok := decoded.(*MultipathCapability)
			require.Truef(t, ok, "expected *MultipathCapability, got %T", decoded)
			assert.Equal(t, original, got, "round-trip value mismatch")

			// Serialize again and verify bytes are identical (stability check).
			assert.Equal(t, data, got.Serialize(), "re-serialized bytes differ")
		})
	}
}
