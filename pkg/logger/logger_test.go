// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		level           Level
		wantDebugLogged bool
		wantInfoLogged  bool
	}{
		{
			name:            "info level logs only info and above",
			level:           LevelInfo,
			wantDebugLogged: false,
			wantInfoLogged:  true,
		},
		{
			name:            "debug level logs debug and above",
			level:           LevelDebug,
			wantDebugLogged: true,
			wantInfoLogged:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logPath := filepath.Join(t.TempDir(), "pola.log")
			fp, err := os.Create(logPath)

			require.NoError(t, err)
			defer func() {
				require.NoError(t, fp.Close())
			}()

			var console bytes.Buffer

			l := New(fp, &console, tt.level)
			l.Debug("debug message")
			l.Info("info message")

			stdout := console.String()

			fileContent, err := os.ReadFile(logPath)
			require.NoError(t, err)

			got := struct {
				debugInFile   bool
				infoInFile    bool
				debugInStdout bool
				infoInStdout  bool
			}{
				debugInFile:   strings.Contains(string(fileContent), "debug message"),
				infoInFile:    strings.Contains(string(fileContent), "info message"),
				debugInStdout: strings.Contains(stdout, "debug message"),
				infoInStdout:  strings.Contains(stdout, "info message"),
			}
			want := struct {
				debugInFile   bool
				infoInFile    bool
				debugInStdout bool
				infoInStdout  bool
			}{
				debugInFile:   tt.wantDebugLogged,
				infoInFile:    tt.wantInfoLogged,
				debugInStdout: tt.wantDebugLogged,
				infoInStdout:  tt.wantInfoLogged,
			}
			assert.Equal(t, want, got)

			if tt.wantInfoLogged {
				lines := strings.Split(strings.TrimSpace(string(fileContent)), "\n")
				require.NotEmpty(t, lines)

				var entry map[string]any
				require.NoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &entry))
				assert.Equal(t, "info", entry["level"])
				assert.Equal(t, "info message", entry["msg"])
				assert.Contains(t, entry, "ts")
			}
		})
	}
}

func TestNewNop(t *testing.T) {
	t.Parallel()

	l := NewNop()
	l.Debug("debug message")
	l.Info("info message")
	l.Warn("warn message")
	l.Error("error message")
	require.NoError(t, l.Sync())
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
