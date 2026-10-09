// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nttcom/pola/pkg/logger"
)

func TestFieldConstructors(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info(
		"msg",
		logger.Any("any", 42),
		logger.Error(errors.New("boom")),
		logger.Int("int", -1),
		logger.String("string", "val"),
		logger.Uint8("uint8", 8),
		logger.Uint32("uint32", 32),
		logger.Uint32s("uint32s", []uint32{1, 2, 3}),
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
