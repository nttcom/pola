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
		input    any
		expected []byte
	}{
		{
			name:     "Convert uint16 0x0102 to bytes",
			input:    uint16(0x0102),
			expected: []byte{0x01, 0x02},
		},
		{
			name:     "Convert uint16 0xFFFF to bytes",
			input:    uint16(0xFFFF),
			expected: []byte{0xFF, 0xFF},
		},
		{
			name:     "Convert TLVType 0x0102 to bytes",
			input:    TLVType(0x0102),
			expected: []byte{0x01, 0x02},
		},
		{
			name:     "Convert TLVType 0xFFFF to bytes",
			input:    TLVType(0xFFFF),
			expected: []byte{0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []byte
			switch v := tt.input.(type) {
			case uint16:
				result = Uint16ToByteSlice(v)
			case TLVType:
				result = Uint16ToByteSlice(v)
			default:
				t.Fatalf("unexpected type %T", v)
			}
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

func TestUint64ToByteSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected []byte
	}{
		{
			name:     "Convert 0x0102030405060708 to bytes",
			input:    0x0102030405060708,
			expected: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name:     "Convert 0xFFFFFFFFFFFFFFFF to bytes",
			input:    0xFFFFFFFFFFFFFFFF,
			expected: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Uint64ToByteSlice(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsBitSet(t *testing.T) {
	type testCase[T Bitwise] struct {
		name     string
		value    T
		mask     T
		expected bool
	}

	t.Run("uint8", func(t *testing.T) {
		tests := []testCase[uint8]{
			{"bit 0 set", 0x01, 0x01, true},
			{"bit 1 set", 0x03, 0x02, true},
			{"bit 2 not set", 0x03, 0x04, false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := IsBitSet(tt.value, tt.mask); got != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, got)
				}
			})
		}
	})

	t.Run("uint16", func(t *testing.T) {
		tests := []testCase[uint16]{
			{"bit 8 set", 0x0100, 0x0100, true},
			{"bit 9 set", 0x0201, 0x0200, true},
			{"bit 10 not set", 0x0201, 0x0400, false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := IsBitSet(tt.value, tt.mask); got != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, got)
				}
			})
		}
	})

	t.Run("uint32", func(t *testing.T) {
		tests := []testCase[uint32]{
			{"bit 16 set", 0x00010000, 0x00010000, true},
			{"bit 17 set", 0x00020001, 0x00020000, true},
			{"bit 18 not set", 0x00020001, 0x00040000, false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := IsBitSet(tt.value, tt.mask); got != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, got)
				}
			})
		}
	})
}

func TestSetBit(t *testing.T) {
	tests := []struct {
		name      string
		value     uint8
		bit       uint8
		condition bool
		expected  uint8
	}{
		{
			name:      "Set bit 0",
			value:     0x00,
			bit:       0x01,
			condition: true,
			expected:  0x01,
		},
		{
			name:      "Set bit 1",
			value:     0x00,
			bit:       0x02,
			condition: true,
			expected:  0x02,
		},
		{
			name:      "Set bit 0 when bit 0 is already set",
			value:     0x01,
			bit:       0x01,
			condition: true,
			expected:  0x01,
		},
		{
			name:      "Set bit 1 when bit 0 is already set",
			value:     0x01,
			bit:       0x02,
			condition: true,
			expected:  0x03,
		},
		{
			name:      "Set bit 0 when bit 1 is already set",
			value:     0x02,
			bit:       0x01,
			condition: true,
			expected:  0x03,
		},
		{
			name:      "Do not set bit 0 when condition is false",
			value:     0x00,
			bit:       0x01,
			condition: false,
			expected:  0x00,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SetBit(tt.value, tt.bit, tt.condition)
			if result != tt.expected {
				t.Errorf("Test %s failed: expected %v, got %v", tt.name, tt.expected, result)
			}
		})
	}
}
