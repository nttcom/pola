// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"golang.org/x/exp/constraints"
)

// AppendByteSlices concatenates multiple byte slices into a single slice.
func AppendByteSlices(slices ...[]byte) []byte {
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}

	result := make([]byte, totalLen)
	offset := 0
	for _, s := range slices {
		copy(result[offset:], s)
		offset += len(s)
	}

	return result
}

// Uint16ToByteSlice converts a uint16 or TLVType value to a big-endian byte slice.
func Uint16ToByteSlice[T ~uint16](v T) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

// Uint32ToByteSlice converts a uint32 value to a big-endian byte slice.
func Uint32ToByteSlice(v uint32) []byte {
	return []byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

// Bitwise is a type constraint for unsigned integer types (uint8, uint16, uint32).
type Bitwise interface {
	constraints.Unsigned
	~uint8 | ~uint16 | ~uint32
}

// IsBitSet checks if a specific bit is set in the value, with bit 0 as the least significant bit (LSB).
func IsBitSet[T Bitwise](value, mask T) bool {
	return value&mask != 0
}

// SetBit sets a specific bit in the value of any unsigned integer type.
func SetBit[T Bitwise](value, bit T, condition bool) T {
	if condition {
		return value | bit
	}
	return value
}
