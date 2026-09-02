// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nttcom/pola/pkg/logger"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/pkg/server"
	"github.com/nttcom/pola/pkg/table"
)

const (
	testAddr        = "127.0.0.1"
	testLogFileName = "polad.log"
)

func validConfig(t *testing.T) config.Config {
	t.Helper()

	return config.Config{
		Global: config.Global{
			PCEP:       config.PCEP{Address: testAddr, Port: "4189"},
			GRPCServer: config.GRPCServer{Address: testAddr, Port: "50051"},
			Log: config.Log{
				Path: t.TempDir() + string(filepath.Separator),
				Name: testLogFileName,
			},
			TED: &config.TED{Enable: false},
		},
	}
}

func writeConfigFile(t *testing.T, c config.Config) string {
	t.Helper()

	tedBlock := "  ted:\n    enable: false\n"
	if c.Global.TED != nil && c.Global.TED.Enable {
		tedBlock = fmt.Sprintf("  ted:\n    enable: true\n    asn: %d\n    source: %q\n", c.Global.TED.ASN, c.Global.TED.Source)
	}

	content := fmt.Sprintf(`global:
  pcep:
    address: %q
    port: %q
  grpcServer:
    address: %q
    port: %q
  log:
    path: %q
    name: %q
    level: %q
%s`,
		c.Global.PCEP.Address, c.Global.PCEP.Port,
		c.Global.GRPCServer.Address, c.Global.GRPCServer.Port,
		c.Global.Log.Path, c.Global.Log.Name, c.Global.Log.Level,
		tedBlock,
	)

	path := filepath.Join(t.TempDir(), "polad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]struct {
		level   string
		want    logger.Level
		wantErr bool
	}{
		"empty defaults to info": {level: "", want: logger.LevelInfo},
		"info":                   {level: "info", want: logger.LevelInfo},
		"debug":                  {level: "debug", want: logger.LevelDebug},
		"warn":                   {level: "warn", want: logger.LevelWarn},
		"error":                  {level: "error", want: logger.LevelError},
		"unsupported":            {level: "trace", wantErr: true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseLogLevel(tt.level)

			if tt.wantErr {
				require.ErrorContains(t, err, "global.log.level")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("returns an error when the config file does not exist", func(t *testing.T) {
		_, err := loadConfig(filepath.Join(t.TempDir(), "missing.yaml"))

		require.ErrorContains(t, err, "failed to read config file")
	})

	t.Run("returns an error when required fields are missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "polad.yaml")
		require.NoError(t, os.WriteFile(path, []byte("global:\n  pcep:\n    address: \"127.0.0.1\"\n"), 0o600))

		_, err := loadConfig(path)

		require.ErrorContains(t, err, "invalid config file")
	})

	t.Run("returns an error when TED is enabled without a source", func(t *testing.T) {
		c := validConfig(t)
		c.Global.TED = &config.TED{Enable: true, ASN: 65000}
		path := writeConfigFile(t, c)

		_, err := loadConfig(path)

		require.ErrorContains(t, err, "invalid config file")
		require.ErrorContains(t, err, "global.ted.source is required")
	})

	t.Run("succeeds for a valid config", func(t *testing.T) {
		c := validConfig(t)
		path := writeConfigFile(t, c)

		got, err := loadConfig(path)

		require.NoError(t, err)
		require.Equal(t, c.Global.PCEP, got.Global.PCEP)
	})
}

func TestOpenLogFile(t *testing.T) {
	t.Run("returns an error when the log directory cannot be created", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "blocker")
		require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

		c := &config.Config{Global: config.Global{Log: config.Log{
			Path: filepath.Join(blocker, "nested") + string(filepath.Separator),
			Name: testLogFileName,
		}}}

		_, err := openLogFile(c)

		require.ErrorContains(t, err, "failed to create log directory")
	})

	t.Run("returns an error when the log file cannot be opened", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root; directory permissions are not enforced")
		}

		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o500))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		c := &config.Config{Global: config.Global{Log: config.Log{
			Path: dir + string(filepath.Separator),
			Name: testLogFileName,
		}}}

		_, err := openLogFile(c)

		require.ErrorContains(t, err, "failed to open log file")
	})

	t.Run("succeeds and restricts the file permissions", func(t *testing.T) {
		dir := t.TempDir()
		c := &config.Config{Global: config.Global{Log: config.Log{
			Path: dir + string(filepath.Separator),
			Name: testLogFileName,
		}}}

		fp, err := openLogFile(c)
		require.NoError(t, err)
		defer func() { _ = fp.Close() }()

		info, err := fp.Stat()
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})
}

func TestNewTEDElemsChan(t *testing.T) {
	t.Run("returns nil when TED is not configured", func(t *testing.T) {
		c := &config.Config{Global: config.Global{}}

		ch, err := newTEDElemsChan(context.Background(), c, logger.NewNop(), nil)

		require.NoError(t, err)
		require.Nil(t, ch)
	})

	t.Run("returns nil when TED is disabled", func(t *testing.T) {
		c := &config.Config{Global: config.Global{TED: &config.TED{Enable: false}}}

		ch, err := newTEDElemsChan(context.Background(), c, logger.NewNop(), nil)

		require.NoError(t, err)
		require.Nil(t, ch)
	})

	t.Run("returns an error when ASN is missing", func(t *testing.T) {
		c := &config.Config{Global: config.Global{TED: &config.TED{Enable: true, Source: tedSourceGoBGP}}}

		ch, err := newTEDElemsChan(context.Background(), c, logger.NewNop(), nil)

		require.ErrorContains(t, err, "Global.TED.ASN")
		require.Nil(t, ch)
	})

	t.Run("returns an error when the source is not supported", func(t *testing.T) {
		c := &config.Config{Global: config.Global{TED: &config.TED{Enable: true, ASN: 65000, Source: "unknown"}}}

		ch, err := newTEDElemsChan(context.Background(), c, logger.NewNop(), nil)

		require.ErrorContains(t, err, "not defined")
		require.Nil(t, ch)
	})

	t.Run("starts the configured monitor and returns a channel", func(t *testing.T) {
		c := &config.Config{
			Global: config.Global{
				TED: &config.TED{Enable: true, ASN: 65000, Source: tedSourceGoBGP},
				GoBGP: config.GoBGP{
					GRPCClient: config.GRPCClient{Address: testAddr, Port: "0"},
				},
			},
		}
		called := make(chan struct{})
		monitor := func(_ context.Context, addr, port string, _ chan []table.TEDElem, _ *logger.Logger) {
			require.Equal(t, testAddr, addr)
			require.Equal(t, "0", port)
			close(called)
		}

		ch, err := newTEDElemsChan(context.Background(), c, logger.NewNop(), monitor)

		require.NoError(t, err)
		require.NotNil(t, ch)
		<-called
	})
}

func TestRun(t *testing.T) {
	t.Run("prints the version and exits without touching config", func(t *testing.T) {
		err := run([]string{versionFlag}, runDeps{})

		require.NoError(t, err)
	})

	t.Run("returns an error for an unrecognized flag", func(t *testing.T) {
		err := run([]string{"-nonexistent-flag"}, defaultRunDeps())

		require.Error(t, err)
	})

	t.Run("returns an error when the config file cannot be loaded", func(t *testing.T) {
		err := run([]string{"-f", filepath.Join(t.TempDir(), "missing.yaml")}, defaultRunDeps())

		require.ErrorContains(t, err, "failed to read config file")
	})

	t.Run("returns an error when the log file cannot be opened", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root; directory permissions are not enforced")
		}

		c := validConfig(t)
		blockedDir := filepath.Join(t.TempDir(), "blocked")
		require.NoError(t, os.Mkdir(blockedDir, 0o700))
		require.NoError(t, os.Chmod(blockedDir, 0o500))
		t.Cleanup(func() { _ = os.Chmod(blockedDir, 0o700) })
		c.Global.Log.Path = filepath.Join(blockedDir, "nested") + string(filepath.Separator)
		path := writeConfigFile(t, c)

		err := run([]string{"-f", path}, defaultRunDeps())

		require.ErrorContains(t, err, "failed to create log directory")
	})

	t.Run("returns an error when the config is invalid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "polad.yaml")
		require.NoError(t, os.WriteFile(path, []byte("global:\n  pcep:\n    address: \"127.0.0.1\"\n"), 0o600))

		err := run([]string{"-f", path}, defaultRunDeps())

		require.ErrorContains(t, err, "invalid config file")
	})

	t.Run("returns an error when the log level is invalid", func(t *testing.T) {
		c := validConfig(t)
		c.Global.Log.Level = "trace"
		path := writeConfigFile(t, c)

		err := run([]string{"-f", path}, defaultRunDeps())

		require.ErrorContains(t, err, "invalid config file")
		require.ErrorContains(t, err, "global.log.level")
	})

	t.Run("returns an error when TED is misconfigured", func(t *testing.T) {
		c := validConfig(t)
		c.Global.TED = &config.TED{Enable: true, ASN: 65000, Source: "unsupported"}
		path := writeConfigFile(t, c)

		err := run([]string{"-f", path}, defaultRunDeps())

		require.ErrorContains(t, err, "invalid config file")
	})

	t.Run("propagates the server error", func(t *testing.T) {
		path := writeConfigFile(t, validConfig(t))
		wantErr := errors.New("boom")
		deps := runDeps{
			newPCE: func(context.Context, *server.PCEOptions, *logger.Logger, chan []table.TEDElem) server.Error {
				return server.Error{Server: "pcep", Error: wantErr}
			},
		}

		err := run([]string{"-f", path}, deps)

		require.ErrorContains(t, err, "pcep")
		require.ErrorIs(t, err, wantErr)
	})

	t.Run("starts the server for a valid config", func(t *testing.T) {
		path := writeConfigFile(t, validConfig(t))
		called := make(chan struct{})
		deps := runDeps{
			newPCE: func(context.Context, *server.PCEOptions, *logger.Logger, chan []table.TEDElem) server.Error {
				close(called)
				return server.Error{}
			},
		}

		err := run([]string{"-f", path}, deps)

		require.NoError(t, err)
		select {
		case <-called:
		default:
			t.Fatal("expected newPCE to be called")
		}
	})
}

func TestMainRun(t *testing.T) {
	t.Run("returns 0 on success", func(t *testing.T) {
		require.Equal(t, 0, mainRun([]string{versionFlag}))
	})

	t.Run("returns 1 when run fails", func(t *testing.T) {
		require.Equal(t, 1, mainRun([]string{"-f", filepath.Join(t.TempDir(), "missing.yaml")}))
	})
}
