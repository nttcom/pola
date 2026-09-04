// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package safecast provides narrowing integer conversions that report
// overflow instead of silently truncating (see gosec G115).
package safecast

import (
	"fmt"
	"math"
)

// Uint16 converts v to uint16, returning an error if it would overflow.
func Uint16(v uint32, field string) (uint16, error) {
	if v > math.MaxUint16 {
		return 0, fmt.Errorf("%s %d exceeds %d", field, v, math.MaxUint16)
	}

	return uint16(v), nil
}

// Uint8 converts v to uint8, returning an error if it would overflow.
func Uint8(v uint32, field string) (uint8, error) {
	if v > math.MaxUint8 {
		return 0, fmt.Errorf("%s %d exceeds %d", field, v, math.MaxUint8)
	}

	return uint8(v), nil
}
