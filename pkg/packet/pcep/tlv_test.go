// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

func TestStatefulPceCapability_DecodeFromBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint8
		expected *StatefulPceCapability
		err      bool
	}{
		{
			name:     "Single capability: LSP Update enabled",
			input:    NewStatefulPceCapability(0x01).Serialize(),
			expected: NewStatefulPceCapability(0x01),
			err:      false,
		},
		{
			name:     "All capabilities enabled",
			input:    NewStatefulPceCapability(0x3F).Serialize(),
			expected: NewStatefulPceCapability(0x3F),
			err:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actual StatefulPceCapability
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

func TestStatefulPceCapability_Serialize(t *testing.T) {
	tests := []struct {
		name string
		bits uint8
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
			tlv := NewStatefulPceCapability(tt.bits)
			expected := make([]uint8, 8)
			binary.BigEndian.PutUint16(expected[0:2], TLV_STATEFUL_PCE_CAPABILITY)
			binary.BigEndian.PutUint16(expected[2:4], TLV_STATEFUL_PCE_CAPABILITY_LENGTH)
			expected[7] = tlv.CapabilityBits()

			assert.Equal(t, expected, tlv.Serialize(), "serialized output mismatch")
		})
	}
}

func TestStatefulPceCapability_MarshalLogObject(t *testing.T) {
	tests := []struct {
		name     string
		tlv      *StatefulPceCapability
		expected bool
	}{
		{
			name: "LSP Update Capability enabled",
			tlv: &StatefulPceCapability{
				LspUpdateCapability: true,
			},
			expected: true,
		},
		{
			name: "LSP Update Capability disabled",
			tlv: &StatefulPceCapability{
				LspUpdateCapability: false,
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

func TestStatefulPceCapability_CapStrings(t *testing.T) {
	tests := []struct {
		name     string
		bits     uint8
		expected []string
	}{
		{
			name:     "All capabilities enabled",
			bits:     0x3F,
			expected: []string{"Stateful", "Update", "Include-DB-Ver", "Initiate", "Triggered-Resync", "Delta-LSP-Sync", "Triggered-init-sync"},
		},
		{
			name:     "No capabilities enabled",
			bits:     0x00,
			expected: []string{"Stateful"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := NewStatefulPceCapability(tt.bits)
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
			expected: TL_LENGTH + 4,
		},
		{
			name:     "Symbolic Path Name with padding",
			input:    NewSymbolicPathName("ABC"), // 3 bytes + 1 byte padding
			expected: TL_LENGTH + 3 + 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.Len())
		})
	}
}
