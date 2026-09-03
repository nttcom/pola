// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package safecast

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUint16(t *testing.T) {
	t.Parallel()

	t.Run("within range", func(t *testing.T) {
		t.Parallel()

		got, err := Uint16(math.MaxUint16, "field")
		require.NoError(t, err)
		assert.Equal(t, uint16(math.MaxUint16), got)
	})

	t.Run("overflow", func(t *testing.T) {
		t.Parallel()

		_, err := Uint16(math.MaxUint16+1, "field")
		require.EqualError(t, err, "field 65536 exceeds 65535")
	})
}

func TestUint8(t *testing.T) {
	t.Parallel()

	t.Run("within range", func(t *testing.T) {
		t.Parallel()

		got, err := Uint8(math.MaxUint8, "field")
		require.NoError(t, err)
		assert.Equal(t, uint8(math.MaxUint8), got)
	})

	t.Run("overflow", func(t *testing.T) {
		t.Parallel()

		_, err := Uint8(math.MaxUint8+1, "field")
		require.EqualError(t, err, "field 256 exceeds 255")
	})
}
