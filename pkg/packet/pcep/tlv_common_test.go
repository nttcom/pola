// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import "testing"

func TestDecodeTLVLength(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantLen   int
		wantError bool
	}{
		{
			name: "Valid TLV (length=4)",
			data: []byte{
				0x00, 0x01, // Type
				0x00, 0x04, // Length = 4
				0xAA, 0xBB, 0xCC, 0xDD, // Value (4 bytes)
			},
			wantLen:   4,
			wantError: false,
		},
		{
			name: "Too short (< TLVValueOffset)",
			data: []byte{
				0x00, 0x01,
				0x00,
			},
			wantError: true,
		},
		{
			name: "Invalid length (data shorter than expected)",
			data: []byte{
				0x00, 0x01,
				0x00, 0x04, // Length = 4
				0xAA, 0xBB, // Only 2 bytes
			},
			wantError: true,
		},
		{
			name: "Invalid length (data longer than expected)",
			data: []byte{
				0x00, 0x01,
				0x00, 0x02, // Length = 2
				0xAA, 0xBB,
				0xCC, 0xDD, // Extra bytes
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLen, err := decodeTLVLength(tt.data)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotLen != tt.wantLen {
				t.Errorf("expected length %d, got %d", tt.wantLen, gotLen)
			}
		})
	}
}

func TestPaddedLength(t *testing.T) {
	tests := []struct {
		name     string
		n        uint16
		align    uint16
		expected uint16
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
			result := paddedLength(tt.n, tt.align)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestIsIPv4Bytes(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{
			name: "Valid IPv4-mapped IPv6",
			b:    append(make([]byte, 12), 192, 0, 2, 1),
			want: true,
		},
		{
			name: "Not IPv4-mapped (first byte non-zero)",
			b:    append([]byte{1}, append(make([]byte, 11), 192, 0, 2, 1)...),
			want: false,
		},
		{
			name: "Not IPv4-mapped (random bytes in first 12)",
			b:    append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, 192, 0, 2, 1),
			want: false,
		},
		{
			name: "Exactly 16 zero bytes (still IPv4?)",
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
			got := isIPv4Bytes(tt.b)
			if got != tt.want {
				t.Errorf("isIPv4Bytes(%v) = %v; want %v", tt.b, got, tt.want)
			}
		})
	}
}
