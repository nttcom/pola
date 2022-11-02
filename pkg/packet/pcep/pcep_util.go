// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import "encoding/binary"

// utils
func AppendByteSlices(byteSlices ...[]uint8) []uint8 {
	joinedSliceLength := 0
	for _, byteSlice := range byteSlices {
		joinedSliceLength += len(byteSlice)
	}
	joinedSlice := make([]uint8, 0, joinedSliceLength)
	for _, byteSlice := range byteSlices {
		joinedSlice = append(joinedSlice, byteSlice...)
	}
	return joinedSlice
}

func removePadding(data []uint8) []uint8 {
	for {
		if data[len(data)-1] == 0x00 {
			data = data[:len(data)-1]
		} else {
			return data
		}
	}
}

func uint16ToListUint8(input uint16) []uint8 {
	uint8Fmt := make([]uint8, 2)
	binary.BigEndian.PutUint16(uint8Fmt, input)
	return uint8Fmt
}

func uint32ToListUint8(input uint32) []uint8 {
	uint8Fmt := make([]uint8, 4)
	binary.BigEndian.PutUint32(uint8Fmt, input)
	return uint8Fmt
}
