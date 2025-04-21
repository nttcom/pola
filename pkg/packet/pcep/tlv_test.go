// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

// TestTLVType_String tests the String method for TLVType.
func TestTLVType_String(t *testing.T) {
	tests := map[string]struct {
		tlvType  TLVType
		expected string
	}{
		"String: Valid TLVType (StatefulPCECapability)": {
			tlvType:  TLVStatefulPCECapability,
			expected: "STATEFUL-PCE-CAPABILITY (RFC8231)",
		},
		"String: Valid TLVType (IPv4LSPIdentifiers)": {
			tlvType:  TLVIPv4LSPIdentifiers,
			expected: "IPV4-LSP-IDENTIFIERS (RFC8231)",
		},
		"String: Unknown TLVType": {
			tlvType:  TLVType(0x9999), // Unknown type
			expected: "Unknown TLV (0x9999)",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			actual := tt.tlvType.String()
			assert.Equal(t, tt.expected, actual, "String() returned unexpected value")
		})
	}
}

// TestTLVMap tests the mapping of TLVType to TLVInterface.
func TestTLVMap(t *testing.T) {
	tests := []struct {
		name     string
		tlvType  TLVType
		expected TLVInterface
	}{
		{
			name:     "Map: StatefulPCECapability",
			tlvType:  TLVStatefulPCECapability,
			expected: &StatefulPCECapability{},
		},
		{
			name:     "Map: SymbolicPathName",
			tlvType:  TLVSymbolicPathName,
			expected: &SymbolicPathName{},
		},
		{
			name:     "Map: IPv4LSPIdentifiers",
			tlvType:  TLVIPv4LSPIdentifiers,
			expected: &IPv4LSPIdentifiers{},
		},
		{
			name:     "Map: IPv6LSPIdentifiers",
			tlvType:  TLVIPv6LSPIdentifiers,
			expected: &IPv6LSPIdentifiers{},
		},
		{
			name:     "Map: LSPDBVersion",
			tlvType:  TLVLSPDBVersion,
			expected: &LSPDBVersion{},
		},
		{
			name:     "Map: SRPCECapability",
			tlvType:  TLVSRPCECapability,
			expected: &SRPCECapability{},
		},
		{
			name:     "Map: PathSetupType",
			tlvType:  TLVPathSetupType,
			expected: &PathSetupType{},
		},
		{
			name:     "Map: ExtendedAssociationID",
			tlvType:  TLVExtendedAssociationID,
			expected: &ExtendedAssociationID{},
		},
		{
			name:     "Map: PathSetupTypeCapability",
			tlvType:  TLVPathSetupTypeCapability,
			expected: &PathSetupTypeCapability{},
		},
		{
			name:     "Map: AssocTypeList",
			tlvType:  TLVAssocTypeList,
			expected: &AssocTypeList{},
		},
		{
			name:     "Map: SRPolicyCPathID",
			tlvType:  TLVSRPolicyCPathID,
			expected: &SRPolicyCandidatePathIdentifier{},
		},
		{
			name:     "Map: SRPolicyCPathPreference",
			tlvType:  TLVSRPolicyCPathPreference,
			expected: &SRPolicyCandidatePathPreference{},
		},
		{
			name:     "Map: Color",
			tlvType:  TLVColor,
			expected: &Color{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tlvMap[tt.tlvType]()
			assert.Equal(t, reflect.TypeOf(tt.expected), reflect.TypeOf(actual), "Map returned unexpected type")
		})
	}
}

// TestStatefulPCECapability_DecodeFromBytes tests the DecodeFromBytes method for StatefulPCECapability.
func TestStatefulPCECapability_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *StatefulPCECapability
		err      bool
	}{
		{
			name:     "DecodeFromBytes: Single capability (LSP Update enabled)",
			input:    NewStatefulPCECapability(0x01).Serialize(),
			expected: NewStatefulPCECapability(0x01),
			err:      false,
		},
		{
			name:     "DecodeFromBytes: All capabilities enabled",
			input:    NewStatefulPCECapability(0x3F).Serialize(),
			expected: NewStatefulPCECapability(0x3F),
			err:      false,
		},
		{
			name:     "DecodeFromBytes: Input too short (missing TLV body)",
			input:    []byte{byte(TLVStatefulPCECapability >> 8), byte(TLVStatefulPCECapability & 0xFF), 0x00, 0x04},
			expected: nil,
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actual StatefulPCECapability
			err := actual.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for input: %v", tt.input)
				assert.Equal(t, *tt.expected, actual, "Decoded capability mismatch")
			}
		})
	}
}

// TestStatefulPCECapability_Serialize tests the Serialize method for StatefulPCECapability.
func TestStatefulPCECapability_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *StatefulPCECapability
		expected []byte
	}{
		{
			name:     "Serialize: LSP Update Capability enabled",
			input:    NewStatefulPCECapability(0x01),
			expected: []byte{byte(TLVStatefulPCECapability >> 8), byte(TLVStatefulPCECapability & 0xFF), 0x00, 0x04, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name:     "Serialize: All capabilities enabled",
			input:    NewStatefulPCECapability(0x3F),
			expected: []byte{byte(TLVStatefulPCECapability >> 8), byte(TLVStatefulPCECapability & 0xFF), 0x00, 0x04, 0x00, 0x00, 0x00, 0x3F},
		},
		{
			name:     "Serialize: No capabilities enabled",
			input:    NewStatefulPCECapability(0x00),
			expected: []byte{byte(TLVStatefulPCECapability >> 8), byte(TLVStatefulPCECapability & 0xFF), 0x00, 0x04, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestStatefulPCECapability_MarshalLogObject tests the MarshalLogObject method for StatefulPCECapability.
func TestStatefulPCECapability_MarshalLogObject(t *testing.T) {
	tests := []struct {
		name     string
		tlv      *StatefulPCECapability
		expected bool
	}{
		{
			name: "LSP Update Capability enabled",
			tlv: &StatefulPCECapability{
				LSPUpdateCapability: true,
			},
			expected: true,
		},
		{
			name: "LSP Update Capability disabled",
			tlv: &StatefulPCECapability{
				LSPUpdateCapability: false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.tlv.MarshalLogObject(enc)

			assert.NoError(t, err, "Expected no error while marshaling log object")
			assert.Equal(t, tt.expected, enc.Fields["lspUpdateCapability"], "Field 'lspUpdateCapability' mismatch")
		})
	}
}

// TestStatefulPCECapability_CapStrings tests the CapStrings method for StatefulPCECapability.
func TestStatefulPCECapability_CapStrings(t *testing.T) {
	tests := []struct {
		name     string
		bits     uint32
		expected []string
	}{
		{
			name:     "All capabilities enabled",
			bits:     uint32(0x0000083F),
			expected: []string{"Stateful", "Update", "Include-DB-Ver", "Instantiation", "Triggered-Resync", "Delta-LSP-Sync", "Triggered-Initial-Sync", "Color"},
		},
		{
			name:     "No capabilities enabled",
			bits:     0x00,
			expected: []string{"Stateful"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := NewStatefulPCECapability(tt.bits)
			assert.ElementsMatch(t, tt.expected, input.CapStrings(), "Capabilities mismatch")
		})
	}
}

// TestSymbolicPathName_DecodeFromBytes tests the DecodeFromBytes method for SymbolicPathName.
func TestSymbolicPathName_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *SymbolicPathName
		err      bool
	}{
		{
			name:     "DecodeFromBytes: Valid Symbolic Path Name",
			input:    NewSymbolicPathName("Test").Serialize(),
			expected: NewSymbolicPathName("Test"),
			err:      false,
		},
		{
			name:     "DecodeFromBytes: Input too short to contain TLV header",
			input:    []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xFF), 0x00}, // Less than TLVHeaderLength (4 bytes)
			expected: NewSymbolicPathName(""),
			err:      true,
		},
		{
			name:     "DecodeFromBytes: Declared name length longer than actual data",
			input:    []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xFF), 0x00, 0x02, 'T'}, // Declared 2 bytes, only 1 provided
			expected: NewSymbolicPathName(""),
			err:      true,
		},
		{
			name:     "DecodeFromBytes: Declared name length shorter than actual data",
			input:    []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xFF), 0x00, 0x01, 'T', 'e'}, // Declared 1 byte, but extra provided
			expected: NewSymbolicPathName(""),
			err:      true,
		},
		{
			name: "DecodeFromBytes: Invalid UTF-8 sequence in name",
			input: func() []byte {
				invalidName := []byte{0xff} // 0xff is invalid as standalone UTF-8
				length := Uint16ToByteSlice(uint16(len(invalidName)))
				return AppendByteSlices(
					Uint16ToByteSlice(uint16(TLVSymbolicPathName)),
					length,
					invalidName,
				)
			}(),
			expected: NewSymbolicPathName(""),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv SymbolicPathName
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv, "Decoded value mismatch")
			}
		})
	}
}

// TestSymbolicPathName_Serialize tests the Serialize method for SymbolicPathName.
func TestSymbolicPathName_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *SymbolicPathName
		expected []byte
	}{
		{
			name:     "Serialize: Valid Symbolic Path Name",
			input:    NewSymbolicPathName("Test"),
			expected: []byte{byte(TLVSymbolicPathName >> 8), byte(TLVSymbolicPathName & 0xFF), 0x00, 0x04, 'T', 'e', 's', 't'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestSymbolicPathName_Len tests the Len method for SymbolicPathName.
func TestSymbolicPathName_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *SymbolicPathName
		expected uint16
	}{
		{
			name:     "Len: Symbolic Path Name length",
			input:    NewSymbolicPathName("Test"),
			expected: TLVHeaderLength + 4,
		},
		{
			name:     "Len: Symbolic Path Name with padding",
			input:    NewSymbolicPathName("ABC"), // 3 bytes + 1 byte padding
			expected: TLVHeaderLength + 3 + 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len(), "Length mismatch")
		})
	}
}

// TestSymbolicPathName_MarshalLogObject tests the MarshalLogObject method for SymbolicPathName.
func TestSymbolicPathName_MarshalLogObject(t *testing.T) {
	tests := []struct {
		name     string
		tlv      *SymbolicPathName
		expected string
	}{
		{
			name:     "MarshalLogObject: Valid symbolic path name",
			tlv:      &SymbolicPathName{Name: "pathA"},
			expected: "pathA",
		},
		{
			name:     "MarshalLogObject: Empty symbolic path name",
			tlv:      &SymbolicPathName{Name: ""},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.tlv.MarshalLogObject(enc)

			assert.NoError(t, err, "MarshalLogObject returned unexpected error")
			assert.Equal(t, tt.expected, enc.Fields["symbolicPathName"], "Field 'symbolicPathName' mismatch")
		})
	}
}

// TestIPv4LSPIdentifiers_DecodeFromBytes tests the DecodeFromBytes method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *IPv4LSPIdentifiers
		err      bool
	}{
		{
			name:     "DecodeFromBytes: Valid IPv4 LSP Identifiers",
			input:    NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234).Serialize(),
			expected: NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234),
			err:      false,
		},
		{
			name: "DecodeFromBytes: Invalid IPv4 LSP Identifiers (truncated '192.0.2.1')",
			input: []byte{
				byte(TLVIPv4LSPIdentifiers >> 8), byte(TLVIPv4LSPIdentifiers & 0xFF), 0x00, 0x03, // Type (0x12), truncated length (0x03)
				0xC0, 0x00, 0x02, // Incomplete address: missing last byte (0x01)
			},
			expected: NewIPv4LSPIdentifiers(netip.Addr{}, netip.Addr{}, 0, 0, 0),
			err:      true,
		},
		{
			name: "DecodeFromBytes: Invalid IPv4 LSP Identifiers (extra bytes after '192.0.2.1')",
			input: []byte{
				byte(TLVIPv4LSPIdentifiers >> 8), byte(TLVIPv4LSPIdentifiers & 0xFF), 0x00, 0x14, // Type IPV4-LSP-IDENTIFIERS (0x12), extra length (0x14)
				0xC0, 0x00, 0x02, 0x01, // IPv4 Tunnel Sender Address (192.0.2.1)
				0x00, 0x01, // LSP ID (0x0001)
				0x00, 0x02, // Tunnel ID (0x0002)
				0x00, 0x00, 0x04, 0xD2, // Extended Tunnel ID (1234)
				0xC0, 0x00, 0x02, 0x02, // IPv4 Tunnel Endpoint Address (192.0.2.2)
				0xDE, 0xAD, 0xBE, 0xEF, // Extra unexpected bytes
			},
			expected: NewIPv4LSPIdentifiers(netip.Addr{}, netip.Addr{}, 0, 0, 0),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv IPv4LSPIdentifiers
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv, "Decoded value mismatch")
			}
		})
	}
}

// TestIPv4LSPIdentifiers_Serialize tests the Serialize method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *IPv4LSPIdentifiers
		expected []byte
	}{
		{
			name:  "Serialize: Valid IPv4 LSP Identifiers",
			input: NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234),
			expected: []byte{
				byte(TLVIPv4LSPIdentifiers >> 8), byte(TLVIPv4LSPIdentifiers & 0xFF), 0x00, 0x10, // Type IPV4-LSP-IDENTIFIERS (0x12), Length 16 (0x10)
				0xC0, 0x00, 0x02, 0x01, // IPv4 Tunnel Sender Address (192.0.2.1)
				0x00, 0x01, // LSP ID (0x0001)
				0x00, 0x02, // Tunnel ID (0x0002)
				0x00, 0x00, 0x04, 0xD2, // Extended Tunnel ID (1234)
				0xC0, 0x00, 0x02, 0x02, // IPv4 Tunnel Endpoint Address (192.0.2.2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestIPv4LSPIdentifiers_MarshalLogObject tests the MarshalLogObject method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_MarshalLogObject(t *testing.T) {
	tlv := &IPv4LSPIdentifiers{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)

	assert.NoError(t, err, "expected no error while marshaling IPv4LSPIdentifiers")
}

// TestIPv4LSPIdentifiers_Len tests the Len method for IPv4LSPIdentifiers.
func TestIPv4LSPIdentifiers_Len(t *testing.T) {
	tests := []struct {
		name     string
		tlv      *IPv4LSPIdentifiers
		expected uint16
	}{
		{
			name:     "Len: IPv4LSPIdentifiers length",
			tlv:      &IPv4LSPIdentifiers{},
			expected: TLVHeaderLength + TLVIPv4LSPIdentifiersValueLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tlv.Len(), "Length mismatch")
		})
	}
}

// TestIPv6LSPIdentifiers_DecodeFromBytes tests the DecodeFromBytes method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *IPv6LSPIdentifiers
		err      bool
	}{
		{
			name:     "DecodeFromBytes: Valid IPv6 LSP Identifiers",
			input:    NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{}).Serialize(),
			expected: NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{}),
			err:      false,
		},
		{
			name: "DecodeFromBytes: Invalid IPv6 LSP Identifiers (truncated '2001:db8::1')",
			input: []byte{
				byte(TLVIPv6LSPIdentifiers >> 8), byte(TLVIPv6LSPIdentifiers & 0xFF), 0x00, 0x07, // Type IPV6-LSP-IDENTIFIERS (0x13), truncated length (0x07)
				0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, // Incomplete
			},
			expected: NewIPv6LSPIdentifiers(netip.Addr{}, netip.Addr{}, 0, 0, [16]byte{}),
			err:      true,
		},
		{
			name: "DecodeFromBytes: Invalid IPv6 LSP Identifiers (extra bytes)",
			input: []byte{
				byte(TLVIPv6LSPIdentifiers >> 8), byte(TLVIPv6LSPIdentifiers & 0xFF), 0x00, 0x38, // Type IPV6-LSP-IDENTIFIERS (0x13), extra length (0x38)
				0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IPv6 Tunnel Sender Address (2001:db8::1)
				0x00, 0x01, // LSP ID (0x0001)
				0x00, 0x02, // Tunnel ID (0x0002)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extended Tunnel ID  (0x0000000000000000)
				0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // IPv6 Tunnel Endpoint Address (2001:db8::2)
				0xCA, 0xFE, 0xBA, 0xBE, // Extra unexpected bytes
			},
			expected: NewIPv6LSPIdentifiers(netip.Addr{}, netip.Addr{}, 0, 0, [16]byte{}),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv IPv6LSPIdentifiers
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv, "Decoded value mismatch")
			}
		})
	}
}

// TestIPv6LSPIdentifiers_Serialize tests the Serialize method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *IPv6LSPIdentifiers
		expected []byte
	}{
		{
			name:  "Serialize: Valid IPv6 LSP Identifiers",
			input: NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{}),
			expected: []byte{
				byte(TLVIPv6LSPIdentifiers >> 8), byte(TLVIPv6LSPIdentifiers & 0xFF), 0x00, 0x34, // Type IPV6-LSP-IDENTIFIERS (0x13), Length 52 (0x34)
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IPv6 Tunnel Sender Address (2001:db8::1)
				0x00, 0x01, // LSP ID (0x0001)
				0x00, 0x02, // Tunnel ID (0x0002)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extended Tunnel ID  (0x0000000000000000)
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // IPv6 Tunnel Endpoint Address (2001:db8::2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestIPv6LSPIdentifiers_MarshalLogObject tests the MarshalLogObject method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_MarshalLogObject(t *testing.T) {
	tlv := &IPv6LSPIdentifiers{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)

	assert.NoError(t, err, "expected no error while marshaling IPv6LSPIdentifiers")
}

// TestIPv6LSPIdentifiers_Len tests the Len method for IPv6LSPIdentifiers.
func TestIPv6LSPIdentifiers_Len(t *testing.T) {
	tests := []struct {
		name     string
		tlv      *IPv6LSPIdentifiers
		expected uint16
	}{
		{
			name:     "Len: IPv6LSPIdentifiers length",
			tlv:      &IPv6LSPIdentifiers{},
			expected: TLVHeaderLength + TLVIPv6LSPIdentifiersValueLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tlv.Len(), "Length mismatch")
		})
	}
}

// TestLSPDBVersion_DecodeFromBytes tests the DecodeFromBytes method for LSPDBVersion.
func TestLSPDBVersion_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *LSPDBVersion
		err      bool
	}{
		{
			name:     "DecodeFromBytes: Valid LSPDB Version",
			input:    NewLSPDBVersion(12345).Serialize(),
			expected: NewLSPDBVersion(12345),
			err:      false,
		},
		{
			name:     "DecodeFromBytes: Input too short",
			input:    []byte{byte(TLVLSPDBVersion >> 8), byte(TLVLSPDBVersion & 0xFF), 0x00, 0x02},
			expected: NewLSPDBVersion(0),
			err:      true,
		},
		{
			name: "DecodeFromBytes: Input too long",
			input: []byte{
				byte(TLVLSPDBVersion >> 8), byte(TLVLSPDBVersion & 0xFF), 0x00, 0x09,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00,
			},
			expected: NewLSPDBVersion(0),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv LSPDBVersion
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv, "Decoded value mismatch")
			}
		})
	}
}

// TestLSPDBVersion_Serialize tests the Serialize method for LSPDBVersion.
func TestLSPDBVersion_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *LSPDBVersion
		expected []byte
	}{
		{
			name:     "Serialize: Valid LSPDB Version",
			input:    NewLSPDBVersion(12345),
			expected: []byte{byte(TLVLSPDBVersion >> 8), byte(TLVLSPDBVersion & 0xFF), 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestLSPDBVersion_MarshalLogObject tests the MarshalLogObject method for LSPDBVersion.
func TestLSPDBVersion_MarshalLogObject(t *testing.T) {
	tlv := &LSPDBVersion{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)

	assert.NoError(t, err, "expected no error while marshaling LSPDBVersion")
}

// TestLSPDBVersion_Len tests the Len method for LSPDBVersion.
func TestLSPDBVersion_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *LSPDBVersion
		expected uint16
	}{
		{
			name:     "Len: LSPDB Version length",
			input:    NewLSPDBVersion(12345),
			expected: TLVHeaderLength + TLVLSPDBVersionValueLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len(), "Length mismatch")
		})
	}
}

// TestLSPDBVersion_CapStrings tests the CapStrings method for LSPDBVersion.
func TestLSPDBVersion_CapStrings(t *testing.T) {
	tlv := &LSPDBVersion{}

	expected := []string{"LSP-DB-VERSION"}
	actual := tlv.CapStrings()

	assert.Equal(t, expected, actual, "CapStrings() did not return expected value")
}

// TestSRPCECapability_DecodeFromBytes tests the DecodeFromBytes method for SRPCECapability.
func TestSRPCECapability_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *SRPCECapability
		err      bool
	}{
		{
			name:     "DecodeFromBytes: Valid SRPCE Capability",
			input:    NewSRPCECapability(true, true, 42).Serialize(),
			expected: NewSRPCECapability(true, true, 42),
			err:      false,
		},
		{
			name:     "DecodeFromBytes: Input too short",
			input:    []byte{byte(TLVSRPCECapability >> 8), byte(TLVSRPCECapability & 0xFF), 0x00, 0x02},
			expected: NewSRPCECapability(false, false, 0),
			err:      true,
		},
		{
			name:     "DecodeFromBytes: Input too long",
			input:    []byte{byte(TLVSRPCECapability >> 8), byte(TLVSRPCECapability & 0xFF), 0x00, 0x02, 0x00, 0x00, 0x03, 0x05, 0x01},
			expected: NewSRPCECapability(false, false, 0),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv SRPCECapability
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv, "Decoded value mismatch")
			}
		})
	}
}

// TestSRPCECapability_Serialize tests the Serialize method for SRPCECapability.
func TestSRPCECapability_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *SRPCECapability
		expected []byte
	}{
		{
			name:     "Serialize: Valid SRPCE Capability",
			input:    NewSRPCECapability(true, true, 5),
			expected: []byte{byte(TLVSRPCECapability >> 8), byte(TLVSRPCECapability & 0xFF), 0x00, 0x04, 0x03, 0x05, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestSRPCECapability_MarshalLogObject tests the MarshalLogObject method for SRPCECapability.
func TestSRPCECapability_MarshalLogObject(t *testing.T) {
	tests := []struct {
		name     string
		tlv      *SRPCECapability
		expected map[string]interface{}
	}{
		{
			name: "MarshalLogObject: All fields set",
			tlv: &SRPCECapability{
				HasUnlimitedMaxSIDDepth: true,
				IsNAISupported:          true,
				MaximumSidDepth:         255,
			},
			expected: map[string]interface{}{
				"unlimited_max_sid_depth": true,
				"nai_is_supported":        true,
				"maximum_sid_depth":       byte(255),
			},
		},
		{
			name: "MarshalLogObject: No capability set",
			tlv: &SRPCECapability{
				HasUnlimitedMaxSIDDepth: false,
				IsNAISupported:          false,
				MaximumSidDepth:         0,
			},
			expected: map[string]interface{}{
				"unlimited_max_sid_depth": false,
				"nai_is_supported":        false,
				"maximum_sid_depth":       byte(0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			err := tt.tlv.MarshalLogObject(enc)

			assert.NoError(t, err, "MarshalLogObject returned unexpected error")
			for k, v := range tt.expected {
				assert.Equal(t, v, enc.Fields[k], "Field %q mismatch", k)
			}
		})
	}
}

// TestSRPCECapability_Len tests the Len method for SRPCECapability.
func TestSRPCECapability_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *SRPCECapability
		expected uint16
	}{
		{
			name:     "Len: SRPCE Capability length",
			input:    NewSRPCECapability(true, true, 5),
			expected: TLVHeaderLength + TLVSRPCECapabilityValueLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len(), "Length mismatch")
		})
	}
}

// TestSRPCECapability_CapStrings tests the CapStrings method for SRPCECapability.
func TestSRPCECapability_CapStrings(t *testing.T) {
	tests := []struct {
		name     string
		tlv      *SRPCECapability
		expected []string
	}{
		{
			name: "CapStrings: All capabilities enabled (Unlimited-SID-Depth, NAI-Supported)",
			tlv: &SRPCECapability{
				HasUnlimitedMaxSIDDepth: true,
				IsNAISupported:          true,
			},
			expected: []string{"Unlimited-SID-Depth", "NAI-Supported"},
		},
		{
			name: "CapStrings: Only UnlimitedMaxSIDDepth enabled",
			tlv: &SRPCECapability{
				HasUnlimitedMaxSIDDepth: true,
			},
			expected: []string{"Unlimited-SID-Depth"},
		},
		{
			name: "CapStrings: Only NAISupported enabled",
			tlv: &SRPCECapability{
				IsNAISupported: true,
			},
			expected: []string{"NAI-Supported"},
		},
		{
			name:     "CapStrings: No capabilities enabled",
			tlv:      &SRPCECapability{},
			expected: nil, // No capabilities should result in nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.tlv.CapStrings()
			assert.Equal(t, tt.expected, actual, "Capabilities mismatch in test case: %s", tt.name)
		})
	}
}

func TestPst_String(t *testing.T) {
	tests := []struct {
		name     string
		input    Pst
		expected string
	}{
		{
			name:     "Known PathSetupType",
			input:    Pst(0x01),
			expected: "Traffic engineering path is set up using Segment Routing (RFC8664)", // Corrected expected value
		},
		{
			name:     "Unknown PathSetupType",
			input:    Pst(0xFF), // Unknown value
			expected: "Unknown PathSetupType (0xff)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.String())
		})
	}
}

// TestPsts_MarshalJSON tests the MarshalJSON method for Psts.
func TestPsts_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    Psts
		expected string
	}{
		{
			name:     "Nil Psts",
			input:    nil,
			expected: "null",
		},
		{
			name:     "Empty Psts",
			input:    Psts{},
			expected: "",
		},
		{
			name:     "Single Pst",
			input:    Psts{Pst(0x01)},
			expected: "1",
		},
		{
			name:     "Multiple Psts",
			input:    Psts{Pst(0x01), Pst(0x02)},
			expected: "1,2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := tt.input.MarshalJSON()
			assert.NoError(t, err, "MarshalJSON returned unexpected error")
			assert.Equal(t, tt.expected, string(actual), "MarshalJSON output mismatch")
		})
	}
}

// TestPathSetupType_DecodeFromBytes tests the DecodeFromBytes method for PathSetupType.
func TestPathSetupType_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *PathSetupType
		err      bool
	}{
		{
			name:     "Valid PathSetupType SRv6TE",
			input:    NewPathSetupType(PathSetupTypeSRv6TE).Serialize(),
			expected: NewPathSetupType(PathSetupTypeSRv6TE),
			err:      false,
		},
		{
			name:     "Invalid input (too short data)",
			input:    []byte{0x00, 0x15, 0x00, 0x04},
			expected: NewPathSetupType(0),
			err:      true,
		},
		{
			name:     "Invalid input (too long data)",
			input:    append(NewPathSetupType(PathSetupTypeSRTE).Serialize(), 0x00, 0x00),
			expected: NewPathSetupType(0),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv PathSetupType
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv, "Decoded value mismatch")
			}
		})
	}
}

// TestPathSetupType_Serialize tests the Serialize method for PathSetupType.
func TestPathSetupType_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *PathSetupType
		expected []byte
	}{
		{
			name:     "Serialize: PathSetupType SRTE",
			input:    NewPathSetupType(PathSetupTypeSRTE),
			expected: []byte{byte(TLVPathSetupType >> 8), byte(TLVPathSetupType & 0xFF), 0x00, 0x04, 0x00, 0x00, 0x00, byte(PathSetupTypeSRTE)},
		},
		{
			name:     "Serialize: PathSetupType RSVP-TE",
			input:    NewPathSetupType(PathSetupTypeRSVPTE),
			expected: []byte{byte(TLVPathSetupType >> 8), byte(TLVPathSetupType & 0xFF), 0x00, 0x04, 0x00, 0x00, 0x00, byte(PathSetupTypeRSVPTE)},
		},
		{
			name:     "Serialize: PathSetupType SRv6-TE",
			input:    NewPathSetupType(PathSetupTypeSRv6TE),
			expected: []byte{byte(TLVPathSetupType >> 8), byte(TLVPathSetupType & 0xFF), 0x00, 0x04, 0x00, 0x00, 0x00, byte(PathSetupTypeSRv6TE)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestPathSetupType_MarshalLogObject tests the MarshalLogObject method for PathSetupType.
func TestPathSetupType_MarshalLogObject(t *testing.T) {
	tlv := &PathSetupType{}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)

	assert.NoError(t, err, "MarshalLogObject returned unexpected error")
	assert.Empty(t, enc.Fields, "Expected no fields to be marshaled for PathSetupType")
}

// TestPathSetupType_Len tests the Len method for PathSetupType.
func TestPathSetupType_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *PathSetupType
		expected uint16
	}{
		{
			name:     "Length should be header + value length",
			input:    NewPathSetupType(PathSetupTypeRSVPTE),
			expected: TLVHeaderLength + TLVPathSetupTypeValueLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len(), "Length mismatch")
		})
	}
}

// TestExtendedAssociationID_DecodeFromBytes tests the DecodeFromBytes method for ExtendedAssociationID.
func TestExtendedAssociationID_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *ExtendedAssociationID
		err      bool
	}{
		{
			name:     "DecodeFromBytes: Valid IPv4 ExtendedAssociationID with Color 1",
			input:    NewExtendedAssociationID(uint32(1), netip.MustParseAddr("127.0.0.1")).Serialize(),
			expected: &ExtendedAssociationID{Color: 1, Endpoint: netip.MustParseAddr("127.0.0.1")},
			err:      false,
		},
		{
			name:     "DecodeFromBytes: Valid IPv6 ExtendedAssociationID with Color 1",
			input:    NewExtendedAssociationID(uint32(1), netip.MustParseAddr("2001:db8::1")).Serialize(),
			expected: &ExtendedAssociationID{Color: 1, Endpoint: netip.MustParseAddr("2001:db8::1")},
			err:      false,
		},
		{
			name:     "DecodeFromBytes: Input too short (less than TLVHeaderLength)",
			input:    []byte{byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xFF), 0x00},
			expected: &ExtendedAssociationID{},
			err:      true, // Expecting an error because the input is shorter than the minimum TLV header length
		},
		{
			name: "DecodeFromBytes: Invalid length",
			input: []byte{
				byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xFF),
				0x00, 0x10, // IPv6 address length = 16 bytes
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Too long address data (should be 16 bytes)
			},
			expected: &ExtendedAssociationID{},
			err:      true,
		},
		{
			name: "DecodeFromBytes: Unsupported value length (not IPv4 or IPv6)",
			input: []byte{
				byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xFF),
				0x00, 0x0f, // Invalid address length = 15 bytes
				0x00, 0x00, 0x00, 0x01, // Color
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 11 bytes dummy address data (15 - 4 = 11)
			},
			expected: &ExtendedAssociationID{},
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv := &ExtendedAssociationID{}
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "DecodeFromBytes failed for test case: %s", tt.name)
			} else {
				assert.NoError(t, err, "DecodeFromBytes returned unexpected error for test case: %s", tt.name)
				assert.Equal(t, tt.expected, tlv, "Decoded value mismatch in test case: %s", tt.name)
			}
		})
	}
}

// TestExtendedAssociationID_Serialize tests the Serialize method for ExtendedAssociationID.
func TestExtendedAssociationID_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *ExtendedAssociationID
		expected []byte
	}{
		{
			name:     "Serialize: IPv4 ExtendedAssociationID",
			input:    &ExtendedAssociationID{Color: 1, Endpoint: netip.MustParseAddr("127.0.0.1")},
			expected: []byte{byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xFF), 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01},
		},
		{
			name:     "Serialize: IPv6 ExtendedAssociationID",
			input:    &ExtendedAssociationID{Color: 1, Endpoint: netip.MustParseAddr("2001:db8::1")},
			expected: []byte{byte(TLVExtendedAssociationID >> 8), byte(TLVExtendedAssociationID & 0xFF), 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.Serialize()
			assert.Equal(t, tt.expected, actual, "Serialized output mismatch in test case: %s", tt.name)
		})
	}
}

// TestExtendedAssociationID_MarshalLogObject tests the MarshalLogObject method for ExtendedAssociationID.
func TestExtendedAssociationID_MarshalLogObject(t *testing.T) {
	tlv := &ExtendedAssociationID{Color: 1, Endpoint: netip.MustParseAddr("127.0.0.1")}
	enc := zapcore.NewMapObjectEncoder()

	err := tlv.MarshalLogObject(enc)

	assert.NoError(t, err, "MarshalLogObject returned unexpected error")
}

// TestExtendedAssociationID_Len tests the Len method for ExtendedAssociationID.
func TestExtendedAssociationID_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *ExtendedAssociationID
		expected uint16
	}{
		{
			name:     "Len: IPv4 ExtendedAssociationID",
			input:    &ExtendedAssociationID{Color: 1, Endpoint: netip.MustParseAddr("127.0.0.1")},
			expected: TLVHeaderLength + TLVExtendedAssociationIDIPv4ValueLength,
		},
		{
			name:     "Len: IPv6 ExtendedAssociationID",
			input:    &ExtendedAssociationID{Color: 1, Endpoint: netip.MustParseAddr("2001:db8::1")},
			expected: TLVHeaderLength + TLVExtendedAssociationIDIPv6ValueLength,
		},
		{
			name: "Len: Unsupported value length (not IPv4 or IPv6)",
			input: &ExtendedAssociationID{
				Color:    1,
				Endpoint: netip.Addr{}, // Invalid address
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len(), "Length mismatch")
		})
	}
}
