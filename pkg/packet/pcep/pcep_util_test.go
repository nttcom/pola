// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"bytes"
	"testing"
)

func TestAppendByteSlices(t *testing.T) {
	// Test case 1
	input := [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}}
	expectedOutput := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	output := AppendByteSlices(input...)
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Test case 1 failed: expected %v, got %v", expectedOutput, output)
	}

	// Test case 2
	input = [][]byte{{}, {}}
	expectedOutput = []byte{}
	output = AppendByteSlices(input...)
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Test case 2 failed: expected %v, got %v", expectedOutput, output)
	}
}

func TestUint16ToByteSlice(t *testing.T) {
	// Test case 1
	input := uint16(0x0102)
	expectedOutput := []byte{0x01, 0x02}
	output := Uint16ToByteSlice(input)
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Test case 1 failed: expected %v, got %v", expectedOutput, output)
	}

	// Test case 2
	input = uint16(0xFFFF)
	expectedOutput = []byte{0xFF, 0xFF}
	output = Uint16ToByteSlice(input)
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Test case 2 failed: expected %v, got %v", expectedOutput, output)
	}
}

func TestUint32ToByteSlice(t *testing.T) {
	// Test case 1
	input := uint32(0x01020304)
	expectedOutput := []byte{0x01, 0x02, 0x03, 0x04}
	output := Uint32ToByteSlice(input)
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Test case 1 failed: expected %v, got %v", expectedOutput, output)
	}

	// Test case 2
	input = uint32(0xFFFFFFFF)
	expectedOutput = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	output = Uint32ToByteSlice(input)
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Test case 2 failed: expected %v, got %v", expectedOutput, output)
	}
}
