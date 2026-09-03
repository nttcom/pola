// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSRPolicyCmd(t *testing.T) {
	t.Parallel()

	cmd := newSRPolicyCmd(&cli{})

	names := make([]string, 0, len(cmd.Commands()))
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}
	assert.ElementsMatch(t, []string{"list", "add", cmdNameDelete}, names)

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.Run(cmd, []string{})
	assert.Contains(t, buf.String(), "Usage:")
}
