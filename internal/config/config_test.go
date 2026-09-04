// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package config_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/internal/config"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "polad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

const validConfig = `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: true
    source: "gobgp"
    asn: 65000
  gobgp:
    grpcClient:
      address: "127.0.0.1"
      port: 50051
  usidMode: true
`

func TestReadConfigFile_Valid(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, validConfig)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	assert.Equal(t, config.GRPCServer{Address: "127.0.0.1", Port: "50052"}, c.Global.GRPCServer)
	assert.Equal(t, &config.TED{Enable: true, Source: "gobgp", ASN: 65000}, c.Global.TED)
	assert.NoError(t, c.Validate())
}

// Regression test: v1.3.0 configs used kebab-case keys (grpc-server, usid-mode,
// grpc-client), which were renamed to camelCase. These must now fail loudly
// instead of silently decoding to empty values.
func TestReadConfigFile_LegacyKebabCaseKeysRejected(t *testing.T) {
	t.Parallel()

	legacyConfig := `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpc-server:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  usid-mode: true
`
	path := writeConfig(t, legacyConfig)

	_, err := config.ReadConfigFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "grpc-server")
}

func TestReadConfigFile_FileNotFound(t *testing.T) {
	t.Parallel()

	_, err := config.ReadConfigFile(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      string
		wantErr     bool
		errContains string
	}{
		{
			name:   "valid, TED enabled",
			config: validConfig,
		},
		{
			name: "valid, TED disabled without source/asn",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`,
		},
		{
			name: "missing grpcServer.address",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`,
			wantErr: true,
		},
		{
			name: "missing grpcServer section entirely",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`,
			wantErr: true,
		},
		{
			name: "missing ted section",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
`,
			wantErr: true,
		},
		{
			name: "ted enabled without asn",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: true
    source: "gobgp"
`,
			wantErr: true,
		},
		{
			name: "missing pcep.address",
			config: `
global:
  pcep:
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`,
			wantErr:     true,
			errContains: "global.pcep.address is required",
		},
		{
			name: "missing pcep.port",
			config: `
global:
  pcep:
    address: "127.0.0.1"
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`,
			wantErr:     true,
			errContains: "global.pcep.port is required",
		},
		{
			name: "missing log.path",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    name: "polad.log"
  ted:
    enable: false
`,
			wantErr:     true,
			errContains: "global.log.path is required",
		},
		{
			name: "missing log.name",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
  ted:
    enable: false
`,
			wantErr:     true,
			errContains: "global.log.name is required",
		},
		{
			name: "ted enabled without source",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: true
    asn: 65000
`,
			wantErr:     true,
			errContains: "global.ted.source is required when global.ted.enable is true",
		},
		{
			name: "ted enabled with unsupported source",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: true
    source: "bmp"
    asn: 65000
`,
			wantErr:     true,
			errContains: `global.ted.source "bmp" is not supported`,
		},
		{
			name: "unsupported log.level",
			config: `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
    level: "trace"
  ted:
    enable: false
`,
			wantErr:     true,
			errContains: `global.log.level: log level "trace" is not supported`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeConfig(t, tt.config)
			c, err := config.ReadConfigFile(path)
			require.NoError(t, err)

			err = c.Validate()
			if tt.wantErr {
				assert.Error(t, err)

				if tt.errContains != "" {
					require.ErrorContains(t, err, tt.errContains)
				}

				return
			}

			require.NoError(t, err)
		})
	}
}

// yaml.v3 decodes an unquoted integer scalar into a string field without
// error; pin this behavior since Port is typed as string.
func TestReadConfigFile_UnquotedIntegerPort(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, validConfig)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	assert.Equal(t, "50052", c.Global.GRPCServer.Port)
}

func TestPCEPTimers_AreOptionalAndDistinguishZeroFromUnset(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    keepalive: 0
    deadTimer: 0
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	require.NoError(t, c.Validate())
	require.NotNil(t, c.Global.PCEP.Keepalive)
	assert.Zero(t, *c.Global.PCEP.Keepalive)
	require.NotNil(t, c.Global.PCEP.DeadTimer)
	assert.Zero(t, *c.Global.PCEP.DeadTimer)
}

func TestPCEPTimers_UnsetLeavesTimersNil(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, validConfig)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)

	assert.Nil(t, c.Global.PCEP.Keepalive)
	assert.Nil(t, c.Global.PCEP.DeadTimer)
}

func TestValidate_RejectsNonZeroDeadTimerWithZeroKeepalive(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    keepalive: 0
    deadTimer: 120
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	require.ErrorContains(t, c.Validate(), "global.pcep.deadTimer must be 0")
}

func TestValidate_RejectsDeadTimerLessThanKeepalive(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    keepalive: 30
    deadTimer: 10
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	require.ErrorContains(t, c.Validate(), "global.pcep.deadTimer must be greater than keepalive")
}

func TestValidate_RejectsDeadTimerLessThanDefaultKeepaliveWhenKeepaliveUnset(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    deadTimer: 10
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	require.ErrorContains(t, c.Validate(), "global.pcep.deadTimer must be greater than keepalive")
}

func TestValidate_RejectsDeadTimerEqualToKeepalive(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    keepalive: 30
    deadTimer: 30
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	require.ErrorContains(t, c.Validate(), "global.pcep.deadTimer must be greater than keepalive")
}

func TestValidate_RejectsKeepalive255WithDefaultedDeadTimer(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    keepalive: 255
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	require.ErrorContains(t, c.Validate(), "global.pcep.deadTimer must be greater than keepalive")
}

func TestPCEPKeepaliveRange_ReadsConfiguredValues(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    minKeepalive: 10
    maxKeepalive: 60
    allowNegotiation: false
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)
	require.NoError(t, c.Validate())

	require.NotNil(t, c.Global.PCEP.MinKeepalive)
	assert.Equal(t, uint8(10), *c.Global.PCEP.MinKeepalive)
	require.NotNil(t, c.Global.PCEP.MaxKeepalive)
	assert.Equal(t, uint8(60), *c.Global.PCEP.MaxKeepalive)
	require.NotNil(t, c.Global.PCEP.AllowNegotiation)
	assert.False(t, *c.Global.PCEP.AllowNegotiation)
}

func TestPCEPKeepaliveRange_UnsetLeavesFieldsNil(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, validConfig)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)

	assert.Nil(t, c.Global.PCEP.MinKeepalive)
	assert.Nil(t, c.Global.PCEP.MaxKeepalive)
	assert.Nil(t, c.Global.PCEP.AllowNegotiation)
}

func TestValidate_RejectsMinKeepaliveGreaterThanMaxKeepalive(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
global:
  pcep:
    address: "127.0.0.1"
    port: 4189
    minKeepalive: 60
    maxKeepalive: 10
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
`)

	c, err := config.ReadConfigFile(path)
	require.NoError(t, err)

	require.ErrorContains(t, c.Validate(), "global.pcep.minKeepalive must be <= global.pcep.maxKeepalive")
}
