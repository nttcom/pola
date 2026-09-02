// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFieldConstructors(t *testing.T) {
	lg, rec := NewRecorder(LevelDebug)
	lg.Info(
		"msg",
		Any("any", 42),
		Error(errors.New("boom")),
		Int("int", -1),
		String("string", "val"),
		Uint8("uint8", 8),
		Uint32("uint32", 32),
		Uint32s("uint32s", []uint32{1, 2, 3}),
	)

	entries := rec.All()
	assert.Len(t, entries, 1)
	assert.Equal(t, map[string]any{
		"any":     int64(42),
		"error":   "boom",
		"int":     int64(-1),
		"string":  "val",
		"uint8":   uint8(8),
		"uint32":  uint32(32),
		"uint32s": []any{uint32(1), uint32(2), uint32(3)},
	}, entries[0].Fields)
}

func TestZapFieldsNil(t *testing.T) {
	assert.Nil(t, zapFields(nil))
	assert.Nil(t, zapFields([]Field{}))
}
