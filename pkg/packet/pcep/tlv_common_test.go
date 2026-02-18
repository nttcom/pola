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
