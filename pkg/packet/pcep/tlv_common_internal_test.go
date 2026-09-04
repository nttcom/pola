// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeTLVLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		data         []byte
		allowPadding bool
		wantLen      int
		wantError    bool
	}{
		{
			name:         "Valid TLV, length=4, no padding, allowPadding=false",
			data:         []byte{0x00, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF},
			allowPadding: false,
			wantLen:      4,
			wantError:    false,
		},
		{
			name:         "Valid TLV, length=4, no padding, allowPadding=true",
			data:         []byte{0x00, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF},
			allowPadding: true,
			wantLen:      4,
			wantError:    false,
		},
		{
			name:         "Fixed length TLV, extra zero byte, allowPadding=false",
			data:         []byte{0x00, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00},
			allowPadding: false,
			wantError:    true,
		},
		{
			name:         "Too short TLV, less than header, allowPadding=false",
			data:         []byte{0x00, 0x01, 0x00},
			allowPadding: false,
			wantError:    true,
		},
		{
			name:         "Invalid length, shorter than value, allowPadding=false",
			data:         []byte{0x00, 0x01, 0x00, 0x04, 0xDE, 0xAD},
			allowPadding: false,
			wantError:    true,
		},
		{
			name:         "Invalid length, longer than value, allowPadding=false",
			data:         []byte{0x00, 0x01, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF},
			allowPadding: false,
			wantError:    true,
		},
		{
			name:         "Valid TLV, zero padding, allowPadding=true",
			data:         []byte{0x00, 0x01, 0x00, 0x02, 0xDE, 0xAD, 0x00, 0x00},
			allowPadding: true,
			wantLen:      2,
			wantError:    false,
		},
		{
			name:         "Invalid padding, non-zero bytes, allowPadding=true",
			data:         []byte{0x00, 0x01, 0x00, 0x02, 0xDE, 0xAD, 0x01, 0x02},
			allowPadding: true,
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotLen, err := decodeTLVLength(tt.data, tt.allowPadding)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantLen, gotLen)
		})
	}
}

func TestPaddedLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		n        int
		align    int
		expected int
	}{
		{
			name:     "Already aligned",
			n:        8,
			align:    4,
			expected: 8,
		},
		{
			name:     "Needs padding",
			n:        6,
			align:    4,
			expected: 8,
		},
		{
			name:     "Zero length",
			n:        0,
			align:    4,
			expected: 0,
		},
		{
			name:     "Length 1",
			n:        1,
			align:    4,
			expected: 4,
		},
		{
			name:     "Non-4 alignment",
			n:        10,
			align:    8,
			expected: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, paddedLength(tt.n, tt.align))
		})
	}
}

func TestIsIPv4Bytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{
			name: "Valid IPv4-compatible IPv6 (12 leading zero bytes)",
			b:    append(make([]byte, 12), 192, 0, 2, 1),
			want: true,
		},
		{
			name: "Not IPv4-compatible (first byte non-zero)",
			b:    append([]byte{1}, append(make([]byte, 11), 192, 0, 2, 1)...),
			want: false,
		},
		{
			name: "Not IPv4-compatible (random bytes in first 12)",
			b:    append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, 192, 0, 2, 1),
			want: false,
		},
		{
			name: "Exactly 16 zero bytes (IPv4-compatible all zeros)",
			b:    make([]byte, 16),
			want: true,
		},
		{
			name: "Too short (<16 bytes)",
			b:    make([]byte, 15),
			want: false,
		},
		{
			name: "Too long (>16 bytes)",
			b:    make([]byte, 17),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isIPv4Bytes(tt.b))
		})
	}
}
