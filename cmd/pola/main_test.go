// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMainRun(t *testing.T) {
	t.Run("--version exits successfully", func(t *testing.T) {
		require.Equal(t, 0, mainRun([]string{"--version"}))
	})

	t.Run("unknown subcommand exits with failure", func(t *testing.T) {
		require.Equal(t, 1, mainRun([]string{"no-such-command"}))
	})
}
