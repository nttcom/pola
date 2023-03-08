// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"bytes"
	"testing"
)

func TestAppendByteSlices(t *testing.T) {
	tests := []struct {
		name     string
		input    [][]byte
		expected []byte
	}{
		{
			name:     "Concatenate non-empty slices",
			input:    [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}},
			expected: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name:     "Concatenate empty slices",
			input:    [][]byte{{}, {}},
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AppendByteSlices(tt.input...)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestUint16ToByteSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    uint16
		expected []byte
	}{
		{
			name:     "Convert 0x0102 to bytes",
			input:    0x0102,
			expected: []byte{0x01, 0x02},
		},
		{
			name:     "Convert 0xFFFF to bytes",
			input:    0xFFFF,
			expected: []byte{0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Uint16ToByteSlice(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestUint32ToByteSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected []byte
	}{
		{
			name:     "Convert 0x01020304 to bytes",
			input:    0x01020304,
			expected: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name:     "Convert 0xFFFFFFFF to bytes",
			input:    0xFFFFFFFF,
			expected: []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Uint32ToByteSlice(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsBitSet(t *testing.T) {
	tests := []struct {
		name     string
		value    uint8
		bit      uint8
		expected bool
	}{
		{
			name:     "Check if bit 0 is set",
			value:    0x01,
			bit:      0x01,
			expected: true,
		},
		{
			name:     "Check if bit 1 is set",
			value:    0x02,
			bit:      0x02,
			expected: true,
		},
		{
			name:     "Check if bit 0 is not set",
			value:    0x00,
			bit:      0x01,
			expected: false,
		},
		{
			name:     "Check if bit 1 is not set",
			value:    0x00,
			bit:      0x02,
			expected: false,
		},
		{
			name:     "Check if bit 2 is not set",
			value:    0x04,
			bit:      0x08,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBitSet(tt.value, tt.bit)
			if result != tt.expected {
				t.Errorf("Test %s failed: expected %v, got %v", tt.name, tt.expected, result)
			}
		})
	}
}

func TestSetBit(t *testing.T) {
	tests := []struct {
		name     string
		value    uint8
		bit      uint8
		expected uint8
	}{
		{
			name:     "Set bit 0",
			value:    0x00,
			bit:      0x01,
			expected: 0x01,
		},
		{
			name:     "Set bit 1",
			value:    0x00,
			bit:      0x02,
			expected: 0x02,
		},
		{
			name:     "Set bit 0 when bit 0 is already set",
			value:    0x01,
			bit:      0x01,
			expected: 0x01,
		},
		{
			name:     "Set bit 1 when bit 0 is already set",
			value:    0x01,
			bit:      0x02,
			expected: 0x03,
		},
		{
			name:     "Set bit 0 when bit 1 is already set",
			value:    0x02,
			bit:      0x01,
			expected: 0x03,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SetBit(tt.value, tt.bit)
			if result != tt.expected {
				t.Errorf("Test %s failed: expected %v, got %v", tt.name, tt.expected, result)
			}
		})
	}
}
