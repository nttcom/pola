// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRootCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()

	names := make([]string, 0, len(cmd.Commands()))
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}

	assert.ElementsMatch(t, []string{"session", "sr-policy", "ted"}, names)

	assert.Equal(t, "false", cmd.PersistentFlags().Lookup("json").DefValue)
	assert.Equal(t, "127.0.0.1", cmd.PersistentFlags().Lookup("host").DefValue)
	assert.Equal(t, "50051", cmd.PersistentFlags().Lookup("port").DefValue)
}

func TestPersistentPreRunE(t *testing.T) {
	t.Parallel()

	t.Run("success sets the client", func(t *testing.T) {
		t.Parallel()

		c := &cli{}
		cmd := newRootCmd()
		require.NoError(t, persistentPreRunE(c)(cmd, []string{}))
		assert.NotNil(t, c.client)
	})

	t.Run("malformed host is rejected before dialing", func(t *testing.T) {
		t.Parallel()

		c := &cli{}
		cmd := newRootCmd()
		require.NoError(t, cmd.PersistentFlags().Set("host", "bad%zzhost"))
		err := persistentPreRunE(c)(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to dial polad connection")
	})
}

func TestRunRootCmd_PrintsHelp(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	runRootCmd(cmd, []string{})
	assert.Contains(t, buf.String(), "Usage:")
}

func TestMainRun_VersionFprintf_Error(t *testing.T) {
	t.Parallel()

	code := mainRun([]string{"--version"}, erroringWriter{}, &bytes.Buffer{})
	assert.Equal(t, 1, code)
}
