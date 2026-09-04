// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/logger"
)

func TestNewRecorderFiltersByLevel(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelWarn)
	lg.Debug("debug")
	lg.Info("info")
	lg.Warn("warn")
	lg.Error("error")

	require.Equal(t, 2, rec.Len())
	msgs := []string{rec.All()[0].Message, rec.All()[1].Message}
	assert.Equal(t, []string{"warn", "error"}, msgs)
}

func TestNewRecorderLevels(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Debug("debug")
	lg.Info("info")
	lg.Warn("warn")
	lg.Error("error")

	entries := rec.All()
	require.Len(t, entries, 4)
	assert.Equal(t, []logger.Level{logger.LevelDebug, logger.LevelInfo, logger.LevelWarn, logger.LevelError}, []logger.Level{
		entries[0].Level, entries[1].Level, entries[2].Level, entries[3].Level,
	})
}

func TestLoggerWithMergesFields(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	child := lg.With(logger.String("server", "grpc"))
	child.Info("started")
	lg.Info("root")

	entries := rec.All()
	require.Len(t, entries, 2)
	assert.Equal(t, map[string]any{"server": "grpc"}, entries[0].Fields)
	assert.Empty(t, entries[1].Fields)
}

func TestRecorderFilterByMessage(t *testing.T) {
	t.Parallel()

	_, rec := logger.NewRecorder(logger.LevelDebug)
	assert.Nil(t, rec.FilterByMessage("missing"))

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("hello")
	lg.Info("world")
	lg.Info("hello")

	assert.Len(t, rec.FilterByMessage("hello"), 2)
	assert.Len(t, rec.FilterByMessage("world"), 1)
	assert.Nil(t, rec.FilterByMessage("missing"))
}

func TestRecorderAllReturnsCopy(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("first")

	entries := rec.All()
	entries[0].Message = "mutated"

	assert.Equal(t, "first", rec.All()[0].Message)
}

func TestRecorderAllFieldsNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("first", logger.String("key", "orig"))

	entries := rec.All()
	entries[0].Fields["key"] = "mutated"
	entries[0].Fields["extra"] = "added"

	again := rec.All()
	assert.Equal(t, map[string]any{"key": "orig"}, again[0].Fields)
}

func TestRecorderAllFieldSlicesNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("first", logger.Uint32s("uint32s", []uint32{1, 2, 3}))

	entries := rec.All()
	entries[0].Fields["uint32s"].([]any)[0] = uint32(99)

	again := rec.All()
	assert.Equal(t, []any{uint32(1), uint32(2), uint32(3)}, again[0].Fields["uint32s"])
}

func TestRecorderAllNestedMapFieldsNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("first", logger.Any("nested", map[string]any{"inner": "orig"}))

	entries := rec.All()
	entries[0].Fields["nested"].(map[string]any)["inner"] = "mutated"

	again := rec.All()
	assert.Equal(t, map[string]any{"inner": "orig"}, again[0].Fields["nested"])
}

func TestRecorderAllNilNestedMapField(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("first", logger.Any("nested", map[string]any(nil)))

	entries := rec.All()
	assert.Nil(t, entries[0].Fields["nested"])
}

func TestRecorderFilterByMessageFieldsNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("hello", logger.String("key", "orig"))

	entries := rec.FilterByMessage("hello")
	entries[0].Fields["key"] = "mutated"

	again := rec.FilterByMessage("hello")
	assert.Equal(t, map[string]any{"key": "orig"}, again[0].Fields)
}

func TestRecorderConcurrentAccess(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			lg.Info("concurrent")

			_ = rec.Len()
			_ = rec.All()
		})
	}

	wg.Wait()

	assert.Equal(t, 100, rec.Len())
}

func TestRecorderSync(t *testing.T) {
	t.Parallel()

	lg, _ := logger.NewRecorder(logger.LevelDebug)
	require.NoError(t, lg.Sync())
}
