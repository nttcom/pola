// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"

	"golang.org/x/exp/constraints"
)

// AppendByteSlices concatenates byte slices into a single slice.
func AppendByteSlices(byteSlices ...[]byte) []byte {
	// Calculate the total length of the joined slice.
	joinedSliceLength := 0
	for _, byteSlice := range byteSlices {
		joinedSliceLength += len(byteSlice)
	}
	// Allocate the joined slice with the total length and copy the byte slices.
	joinedSlice := make([]byte, joinedSliceLength)
	var index int
	for _, byteSlice := range byteSlices {
		copy(joinedSlice[index:], byteSlice)
		index += len(byteSlice)
	}
	return joinedSlice
}

// Uint16ToByteSlice converts a uint16 value to a big-endian byte slice.
func Uint16ToByteSlice(input uint16) []byte {
	uint16Bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(uint16Bytes, input)
	return uint16Bytes
}

// Uint32ToByteSlice converts a uint32 value to a big-endian byte slice.
func Uint32ToByteSlice(input uint32) []byte {
	uint32Bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(uint32Bytes, input)
	return uint32Bytes
}

// Bitwise is a type constraint for unsigned integer types (uint8, uint16, uint32).
type Bitwise interface {
	constraints.Unsigned
	~uint8 | ~uint16 | ~uint32
}

// IsBitSet checks if a bit is set, with bit 0 as the least significant bit (LSB).
func IsBitSet[T Bitwise](value, mask T) bool {
	return value&mask != 0
}

// SetBit sets a specific bit in a value of any unsigned integer type.
func SetBit[T Bitwise](value, bit T) T {
	return value | bit
}
