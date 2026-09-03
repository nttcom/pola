// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMainRun(t *testing.T) {
	t.Parallel()

	t.Run("--version exits successfully", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		require.Equal(t, 0, mainRun([]string{"--version"}, &out, &errOut))
	})

	t.Run("unknown subcommand exits with failure", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		require.Equal(t, 1, mainRun([]string{"no-such-command"}, &out, &errOut))
	})
}
