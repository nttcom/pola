// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/stretchr/testify/assert"
)

func TestNewSRPolicyCmd(t *testing.T) {
	var client pb.PCEServiceClient
	jsonFmt := false
	cmd := newSRPolicyCmd(&client, &jsonFmt)

	var names []string
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}
	assert.ElementsMatch(t, []string{"list", "add", cmdNameDelete}, names)

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.Run(cmd, []string{})
	assert.Contains(t, buf.String(), "Usage:")
}
