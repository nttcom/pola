// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

func TestStatefulPCECapability_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
		expected *StatefulPCECapability
		err      bool
	}{
		{
			name:     "Single capability: LSP Update enabled",
			input:    NewStatefulPCECapability(0x01).Serialize(),
			expected: NewStatefulPCECapability(0x01),
			err:      false,
		},
		{
			name:     "All capabilities enabled",
			input:    NewStatefulPCECapability(0x3F).Serialize(),
			expected: NewStatefulPCECapability(0x3F),
			err:      false,
		},
		{
			name:     "Input too short (missing TLV body)",
			input:    []uint8{uint8(TLVStatefulPCECapability >> 8), uint8(TLVStatefulPCECapability & 0xFF), 0x00, 0x04}, // type=0x0010, length=4, but body missing
			expected: nil,
			err:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actual StatefulPCECapability
			err := actual.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "expected error for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "unexpected error for input: %v", tt.input)
				assert.Equal(t, *tt.expected, actual, "decoded capability mismatch")
			}
		})
	}
}

func TestStatefulPCECapability_Serialize(t *testing.T) {
	tests := []struct {
		name string
		bits uint32
	}{
		{
			name: "LSP Update Capability enabled",
			bits: 0x01,
		},
		{
			name: "All capabilities enabled",
			bits: 0x3F,
		},
		{
			name: "No capabilities enabled",
			bits: 0x00,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv := NewStatefulPCECapability(tt.bits)
			expected := make([]uint8, TLVHeaderLength+TLVStatefulPCECapabilityValueLength)
			binary.BigEndian.PutUint16(expected[0:2], uint16(TLVStatefulPCECapability))
			binary.BigEndian.PutUint16(expected[2:4], TLVStatefulPCECapabilityValueLength)
			binary.BigEndian.PutUint32(expected[4:8], tlv.CapabilityBits())

			assert.Equal(t, expected, tlv.Serialize(), "serialized output mismatch")
		})
	}
}

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

			assert.NoError(t, err, "expected no error while marshaling log object")
			assert.Equal(t, tt.expected, enc.Fields["lspUpdateCapability"], "field 'lspUpdateCapability' mismatch")
		})
	}
}

func TestStatefulPCECapability_CapStrings(t *testing.T) {
	tests := []struct {
		name     string
		bits     uint32
		expected []string
	}{
		{
			name:     "All capabilities enabled",
			bits:     0x3F,
			expected: []string{"Stateful", "Update", "Include-DB-Ver", "Instantiation", "Triggered-Resync", "Delta-LSP-Sync", "Triggered-Initial-Sync"},
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
			assert.ElementsMatch(t, tt.expected, input.CapStrings(), "capabilities mismatch")
		})
	}
}

func TestSymbolicPathName_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
		expected *SymbolicPathName
		err      bool
	}{
		{
			name:     "Valid Symbolic Path Name",
			input:    NewSymbolicPathName("Test").Serialize(),
			expected: NewSymbolicPathName("Test"),
			err:      false,
		},
		{
			name:     "Invalid input (too short data)",
			input:    []byte{0x00, 0x11, 0x00, 0x02, 'T'}, // Input too short for valid decoding
			expected: NewSymbolicPathName(""),
			err:      true,
		},
		{
			name:     "Invalid input (too long data)",
			input:    []byte{0x00, 0x11, 0x00, 0x01, 'T', 'e'}, // Input too long for valid decoding
			expected: NewSymbolicPathName(""),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv SymbolicPathName
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "expected error for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv)
			}
		})
	}
}

func TestSymbolicPathName_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *SymbolicPathName
		expected []uint8
	}{
		{
			name:     "Valid Symbolic Path Name",
			input:    NewSymbolicPathName("Test"),
			expected: NewSymbolicPathName("Test").Serialize(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Serialize())
		})
	}
}

func TestSymbolicPathName_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *SymbolicPathName
		expected uint16
	}{
		{
			name:     "Symbolic Path Name length",
			input:    NewSymbolicPathName("Test"),
			expected: TLVHeaderLength + 4,
		},
		{
			name:     "Symbolic Path Name with padding",
			input:    NewSymbolicPathName("ABC"), // 3 bytes + 1 byte padding
			expected: TLVHeaderLength + 3 + 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len())
		})
	}
}

func TestIPv4LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
		expected *IPv4LSPIdentifiers
		err      bool
	}{
		{
			name:     "Valid IPv4 LSP Identifiers",
			input:    NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234).Serialize(),
			expected: NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234),
			err:      false,
		},
		{
			name: "Invalid IPv4 LSP Identifiers (truncated '192.0.2.1')",
			input: []uint8{
				0x00, 0x12, 0x00, 0x14, // Type (0x12) and Length (0x10)
				0xC0, 0x00, 0x02, // Incomplete address: missing last byte (0x01)
			},
			expected: NewIPv4LSPIdentifiers(netip.Addr{}, netip.Addr{}, 0, 0, 0),
			err:      true,
		},
		{
			name: "Invalid IPv4 LSP Identifiers (extra bytes after '192.0.2.1')",
			input: []uint8{
				0x00, 0x12, 0x00, 0x14, // Type (0x12) and Length (0x10)
				0xC0, 0x00, 0x02, 0x01, // Valid IPv4 address: 192.0.2.1
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
				assert.Error(t, err, "expected error for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv)
			}
		})
	}
}

func TestIPv4LSPIdentifiers_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *IPv4LSPIdentifiers
		expected []uint8
	}{
		{
			name:     "Valid IPv4 LSP Identifiers",
			input:    NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234),
			expected: NewIPv4LSPIdentifiers(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 1, 2, 1234).Serialize(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Serialize())
		})
	}
}

func TestIPv6LSPIdentifiers_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
		expected *IPv6LSPIdentifiers
		err      bool
	}{
		{
			name:     "Valid IPv6 LSP Identifiers",
			input:    NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{}).Serialize(),
			expected: NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{}),
			err:      false,
		},
		{
			name: "Invalid IPv6 LSP Identifiers (truncated '2001:db8::1')",
			input: []uint8{
				0x00, 0x13, 0x00, 0x20, // Type IPV6-LSP-IDENTIFIERS (0x13)、Length 56 (0x38)
				0x20, 0x01, 0x0D, 0xB8, // Start of '2001:db8::'
				0x00, 0x00, 0x00, // Incomplete (should be 16 bytes total)
			},
			expected: NewIPv6LSPIdentifiers(netip.Addr{}, netip.Addr{}, 0, 0, [16]byte{}),
			err:      true,
		},
		{
			name: "Invalid IPv6 LSP Identifiers (extra bytes after '2001:db8::1')",
			input: []uint8{
				0x00, 0x13, 0x00, 0x20, // Type IPV6-LSP-IDENTIFIERS (0x13)、Length 56 (0x38)
				0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Valid IPv6: 2001:db8::1
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
				assert.Error(t, err, "expected error for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv)
			}
		})
	}
}

func TestIPv6LSPIdentifiers_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *IPv6LSPIdentifiers
		expected []uint8
	}{
		{
			name:     "Valid IPv6 LSP Identifiers",
			input:    NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{}),
			expected: NewIPv6LSPIdentifiers(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), 1, 2, [16]byte{}).Serialize(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Serialize())
		})
	}
}

func TestLSPDBVersion_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
		expected *LSPDBVersion
		err      bool
	}{
		{
			name:     "Valid LSPDB Version",
			input:    NewLSPDBVersion(12345).Serialize(),
			expected: NewLSPDBVersion(12345),
			err:      false,
		},
		{
			name:     "Invalid input (too short data)",
			input:    []byte{0x00, 0x17, 0x00, 0x02}, // Type LSP-DB-VERSION (0x17)、Input too short for valid decoding
			expected: NewLSPDBVersion(0),
			err:      true,
		},
		{
			name: "Invalid input (too long data)",
			input: []byte{
				0x00, 0x17, 0x00, 0x09, // Type LSP-DB-VERSION (0x17)、Length 8
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39,
				0x00, // Extra bytes after version
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
				assert.Error(t, err, "expected error for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv)
			}
		})
	}
}

func TestLSPDBVersion_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *LSPDBVersion
		expected []uint8
	}{
		{
			name:     "Valid LSPDB Version",
			input:    NewLSPDBVersion(12345),
			expected: NewLSPDBVersion(12345).Serialize(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Serialize())
		})
	}
}

func TestLSPDBVersion_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *LSPDBVersion
		expected uint16
	}{
		{
			name:     "LSPDB Version length",
			input:    NewLSPDBVersion(12345),
			expected: TLVHeaderLength + TLVLSPDBVersionValueLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len())
		})
	}
}

func TestSRPCECapability_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
		expected *SRPCECapability
		err      bool
	}{
		{
			name:     "Valid SRPCE Capability",
			input:    NewSRPCECapability(true, true, 42).Serialize(), // Maximum SID Depth 42
			expected: NewSRPCECapability(true, true, 42),
			err:      false,
		},
		{
			name:     "Invalid input (too short data)",
			input:    []uint8{0x00, 0x11, 0x00, 0x02}, // Too short for valid decoding
			expected: NewSRPCECapability(false, false, 0),
			err:      true,
		},
		{
			name:     "Invalid input (too long data)",
			input:    []uint8{0x00, 0x11, 0x00, 0x02, 0x00, 0x00, 0x03, 0x05, 0x01}, // Too long for valid decoding
			expected: NewSRPCECapability(false, false, 0),
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlv SRPCECapability
			err := tlv.DecodeFromBytes(tt.input)
			if tt.err {
				assert.Error(t, err, "expected error for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv)
			}
		})
	}
}

func TestSRPCECapability_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *SRPCECapability
		expected []uint8
	}{
		{
			name:     "Valid SRPCE Capability",
			input:    NewSRPCECapability(true, true, 5),
			expected: NewSRPCECapability(true, true, 5).Serialize(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Serialize())
		})
	}
}

func TestSRPCECapability_Len(t *testing.T) {
	tests := []struct {
		name     string
		input    *SRPCECapability
		expected uint16
	}{
		{
			name:     "SRPCE Capability length",
			input:    NewSRPCECapability(true, true, 5),
			expected: TLVHeaderLength + TLVSRPCECapabilityValueLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len())
		})
	}
}

func TestPathSetupType_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
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
			name:     "Invalid input (too short)",
			input:    []uint8{0x00, 0x15, 0x00, 0x04}, // insufficient data
			expected: NewPathSetupType(0),
			err:      true,
		},
		{
			name:     "Invalid input (too long)",
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
				assert.Error(t, err, "expected error for input: %v", tt.input)
			} else {
				assert.NoError(t, err, "unexpected error for input: %v", tt.input)
				assert.Equal(t, tt.expected, &tlv)
			}
		})
	}
}

func TestPathSetupType_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		input    *PathSetupType
		expected []uint8
	}{
		{
			name:     "Serialize PathSetupType SRTE",
			input:    NewPathSetupType(PathSetupTypeSRTE),
			expected: NewPathSetupType(PathSetupTypeSRTE).Serialize(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Serialize())
		})
	}
}

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
			assert.Equal(t, tt.expected, tt.input.Len())
		})
	}
}
