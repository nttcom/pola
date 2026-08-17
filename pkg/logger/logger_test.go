// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout captures output written to os.Stdout while f runs.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	f()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestLogInit(t *testing.T) {
	tests := []struct {
		name            string
		dbg             bool
		wantDebugLogged bool
		wantInfoLogged  bool
	}{
		{
			name:            "debug disabled logs only info and above",
			dbg:             false,
			wantDebugLogged: false,
			wantInfoLogged:  true,
		},
		{
			name:            "debug enabled logs debug and above",
			dbg:             true,
			wantDebugLogged: true,
			wantInfoLogged:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "pola.log")
			fp, err := os.Create(logPath)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, fp.Close())
			}()

			stdout := captureStdout(t, func() {
				l := LogInit(fp, tt.dbg)
				l.Debug("debug message")
				l.Info("info message")
			})

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
