// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestRecordCore_Check_DisabledLevel(t *testing.T) {
	t.Parallel()

	_, rec := NewRecorder(LevelWarn)
	core := &recordCore{min: LevelWarn.zapLevel(), rec: rec}

	entry := zapcore.Entry{Level: LevelDebug.zapLevel(), Message: "debug"}
	checked := &zapcore.CheckedEntry{}

	result := core.Check(entry, checked)

	require.Equal(t, checked, result)
	require.Equal(t, 0, rec.Len())
}

func TestLevelZapLevel(t *testing.T) {
	t.Parallel()

	cases := map[Level]zapcore.Level{
		LevelDebug: zapcore.DebugLevel,
		LevelInfo:  zapcore.InfoLevel,
		LevelWarn:  zapcore.WarnLevel,
		LevelError: zapcore.ErrorLevel,
		Level(99):  zapcore.InfoLevel,
	}
	for level, want := range cases {
		assert.Equal(t, want, level.zapLevel())
	}
}

func TestZapFieldsNil(t *testing.T) {
	t.Parallel()

	assert.Nil(t, zapFields(nil))
	assert.Nil(t, zapFields([]Field{}))
}

func TestCloneFieldsNil(t *testing.T) {
	t.Parallel()

	assert.Nil(t, cloneFields(nil))
}
