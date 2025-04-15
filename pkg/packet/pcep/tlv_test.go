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
