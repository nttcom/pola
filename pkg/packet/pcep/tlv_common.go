// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"fmt"
)

func decodeTLVLength(data []byte) (int, error) {
	if len(data) < TLVValueOffset {
		return 0, fmt.Errorf("tlv: too short (got %d bytes, want ≥ %d)", len(data), TLVValueOffset)
	}

	length := int(binary.BigEndian.Uint16(data[2:4]))
	expected := TLVValueOffset + length

	if len(data) != expected {
		return 0, fmt.Errorf("tlv: invalid length (expected %d bytes, got %d)", expected, len(data))
	}

	return length, nil
}

func paddedLength(n uint16, align uint16) uint16 {
	if n%align == 0 {
		return n
	}
	return n + (align - (n % align))
}

// isIPv4Bytes returns true if the given 16-byte slice encodes an IPv4 address (upper 12 bytes zero).
func isIPv4Bytes(b []byte) bool {
	if len(b) != 16 {
		return false
	}
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
