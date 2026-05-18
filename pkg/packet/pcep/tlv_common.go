// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"fmt"
)

func decodeTLVLength(data []byte, allowPadding bool) (int, error) {
	if len(data) < TLVValueOffset {
		return 0, fmt.Errorf("tlv: too short (got %d bytes, want ≥ %d)", len(data), TLVValueOffset)
	}

	length := int(binary.BigEndian.Uint16(data[TLVLengthOffset:TLVValueOffset]))
	expected := TLVValueOffset + length

	// Validate length and optional padding strictly.
	if len(data) < expected {
		return 0, fmt.Errorf("tlv: invalid length (expected at least %d bytes, got %d)", expected, len(data))
	}

	// No padding case: length must match exactly.
	if len(data) == expected {
		return length, nil
	}

	// Padding is present; ensure it is allowed and correctly aligned.
	if !allowPadding || TLVAlignment <= 0 {
		return 0, fmt.Errorf("tlv: invalid length (expected %d bytes, got %d)", expected, len(data))
	}

	paddedExpected := paddedLength(expected, TLVAlignment)
	if len(data) != paddedExpected {
		return 0, fmt.Errorf("tlv: invalid length (expected %d or %d bytes with padding, got %d)", expected, paddedExpected, len(data))
	}

	// If padding bytes exist, ensure they are all zero.
	for _, b := range data[expected:] {
		if b != 0 {
			return 0, fmt.Errorf("tlv: invalid padding (expected zero bytes after offset %d)", expected)
		}
	}

	return length, nil
}

func paddedLength(n int, align int) int {
	if n%align == 0 {
		return n
	}
	return n + (align - (n % align))
}

const (
	IPv4InIPv6Offset = 12
)

// isIPv4Bytes returns true if the given 16-byte slice encodes an IPv4 address (upper 12 bytes zero).
func isIPv4Bytes(b []byte) bool {
	if len(b) != IPv6AddrLen {
		return false
	}
	for i := 0; i < IPv4InIPv6Offset; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
