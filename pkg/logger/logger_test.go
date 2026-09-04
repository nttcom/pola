// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/logger"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		level           logger.Level
		wantDebugLogged bool
		wantInfoLogged  bool
	}{
		{
			name:            "info level logs only info and above",
			level:           logger.LevelInfo,
			wantDebugLogged: false,
			wantInfoLogged:  true,
		},
		{
			name:            "debug level logs debug and above",
			level:           logger.LevelDebug,
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

			l := logger.New(fp, &console, tt.level)
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

func TestParseLevel(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		name    string
		want    logger.Level
		wantErr bool
	}{
		"empty defaults to info": {name: "", want: logger.LevelInfo},
		"info":                   {name: "info", want: logger.LevelInfo},
		"debug":                  {name: "debug", want: logger.LevelDebug},
		"warn":                   {name: "warn", want: logger.LevelWarn},
		"error":                  {name: "error", want: logger.LevelError},
		"unsupported": {
			name:    "trace",
			wantErr: true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := logger.ParseLevel(tt.name)

			if tt.wantErr {
				require.ErrorContains(t, err, `log level "trace" is not supported`)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewNop(t *testing.T) {
	t.Parallel()

	l := logger.NewNop()
	l.Debug("debug message")
	l.Info("info message")
	l.Warn("warn message")
	l.Error("error message")
	require.NoError(t, l.Sync())
}
