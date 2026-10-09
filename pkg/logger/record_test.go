// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger_test

import (
	"reflect"
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
	uint32s, ok := entries[0].Fields["uint32s"].([]any)
	require.True(t, ok)

	uint32s[0] = uint32(99)

	again := rec.All()
	assert.Equal(t, []any{uint32(1), uint32(2), uint32(3)}, again[0].Fields["uint32s"])
}

func TestRecorderAllNestedMapFieldsNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("first", logger.Any("nested", map[string]any{"inner": "orig"}))

	entries := rec.All()
	nested, ok := entries[0].Fields["nested"].(map[string]any)
	require.True(t, ok)

	nested["inner"] = "mutated"

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

func TestRecorderAllTypedMapFieldNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	labels := map[string]string{"env": "prod"}
	lg.Info("first", logger.Any("labels", labels))

	labels["env"] = "mutated"
	labels["extra"] = "added"

	entries := rec.All()
	assert.Equal(t, map[string]string{"env": "prod"}, entries[0].Fields["labels"])
}

func TestRecorderAllTypedSliceFieldNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	items := [][]string{{"a", "b"}}
	lg.Info("first", logger.Any("items", items))

	items[0][0] = "mutated"

	entries := rec.All()
	assert.Equal(t, [][]string{{"a", "b"}}, entries[0].Fields["items"])
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

type point struct{ X int }

func TestRecorderAllNilPointerField(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	var p *point
	lg.Info("first", logger.Any("ptr", p))

	entries := rec.All()
	assert.Nil(t, entries[0].Fields["ptr"])
}

func TestRecorderAllPointerFieldNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	val := &point{X: 5}
	lg.Info("first", logger.Any("ptr", val))
	val.X = 99

	entries := rec.All()
	ptr, ok := entries[0].Fields["ptr"].(*point)
	require.True(t, ok)
	assert.Equal(t, 5, ptr.X)
}

func TestRecorderAllNilTypedMapField(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	var labels map[string]string
	lg.Info("first", logger.Any("labels", labels))

	entries := rec.All()
	assert.Nil(t, entries[0].Fields["labels"])
}

func TestRecorderAllNilTypedSliceField(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	var items [][]string
	lg.Info("first", logger.Any("items", items))

	entries := rec.All()
	assert.Nil(t, entries[0].Fields["items"])
}

func TestRecorderAllArrayFieldNotShared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	arr := [3]int{1, 2, 3}
	lg.Info("first", logger.Any("arr", arr))

	entries := rec.All()
	assert.Equal(t, [3]int{1, 2, 3}, entries[0].Fields["arr"])
}

func TestRecorderAllArrayOfAnyFieldWithNilElement(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	arr := [2]any{nil, "value"}
	lg.Info("first", logger.Any("mix", arr))

	entries := rec.All()
	assert.Equal(t, [2]any{nil, "value"}, entries[0].Fields["mix"])
}

func TestRecorderAllCyclicMapFieldLeftUnshared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	lg.Info("first", logger.Any("m", cyclic))

	entries := rec.All()
	got, ok := entries[0].Fields["m"].(map[string]any)
	require.True(t, ok)
	assert.NotEqual(t, reflect.ValueOf(cyclic).Pointer(), reflect.ValueOf(got).Pointer())
	self, ok := got["self"].(map[string]any)
	require.True(t, ok, "cyclic map field should still be a map after cloning")
	assert.Equal(t, reflect.ValueOf(got).Pointer(), reflect.ValueOf(self).Pointer(), "back-edge should point at the clone, not the original")
}

func TestRecorderAllNilAnySliceField(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)
	lg.Info("first", logger.Any("items", []any(nil)))

	entries := rec.All()
	assert.Nil(t, entries[0].Fields["items"])
}

func TestRecorderAllCyclicAnySliceFieldLeftUnshared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	cyclic := make([]any, 1)
	cyclic[0] = cyclic
	lg.Info("first", logger.Any("s", cyclic))

	entries := rec.All()
	got, ok := entries[0].Fields["s"].([]any)
	require.True(t, ok)
	assert.NotEqual(t, reflect.ValueOf(cyclic).Pointer(), reflect.ValueOf(got).Pointer())
	require.Len(t, got, 1)
	self, ok := got[0].([]any)
	require.True(t, ok, "cyclic slice field should still be a slice after cloning")
	assert.Equal(t, reflect.ValueOf(got).Pointer(), reflect.ValueOf(self).Pointer(), "back-edge should point at the clone, not the original")
}

type selfNode struct{ Self *selfNode }

func TestRecorderAllCyclicPointerFieldLeftUnshared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	n := &selfNode{}
	n.Self = n
	lg.Info("first", logger.Any("n", n))

	entries := rec.All()
	got, ok := entries[0].Fields["n"].(*selfNode)
	require.True(t, ok)
	assert.NotSame(t, n, got)
	require.NotNil(t, got.Self)
	assert.Same(t, got, got.Self, "back-edge should point at the clone, not the original")
}

type recMap map[string]recMap

func TestRecorderAllCyclicTypedMapFieldLeftUnshared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	rm := recMap{}
	rm["self"] = rm
	lg.Info("first", logger.Any("rm", rm))

	entries := rec.All()
	got, ok := entries[0].Fields["rm"].(recMap)
	require.True(t, ok)
	assert.NotEqual(t, reflect.ValueOf(rm).Pointer(), reflect.ValueOf(got).Pointer())
	self, ok := got["self"]
	require.True(t, ok, "cyclic typed map field should retain its self entry after cloning")
	assert.Equal(t, reflect.ValueOf(got).Pointer(), reflect.ValueOf(self).Pointer(), "back-edge should point at the clone, not the original")
}

type recSlice []recSlice

func TestRecorderAllCyclicTypedSliceFieldLeftUnshared(t *testing.T) {
	t.Parallel()

	lg, rec := logger.NewRecorder(logger.LevelDebug)

	rs := make(recSlice, 1)
	rs[0] = rs
	lg.Info("first", logger.Any("rs", rs))

	entries := rec.All()
	got, ok := entries[0].Fields["rs"].(recSlice)
	require.True(t, ok)
	assert.NotEqual(t, reflect.ValueOf(rs).Pointer(), reflect.ValueOf(got).Pointer())
	require.Len(t, got, 1)
	assert.Equal(t, reflect.ValueOf(got).Pointer(), reflect.ValueOf(got[0]).Pointer(), "back-edge should point at the clone, not the original")
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
