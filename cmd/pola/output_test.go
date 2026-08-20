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

func TestResolveOutputFormat(t *testing.T) {
	assert.Equal(t, outputText, resolveOutputFormat(false))
	assert.Equal(t, outputJSON, resolveOutputFormat(true))
}

type erroringWriter struct{}

func (erroringWriter) Write([]byte) (int, error) { return 0, assert.AnError }

func TestWriteJSON_PropagatesWriteError(t *testing.T) {
	err := writeJSON(erroringWriter{}, []sessionView{{}})
	require.ErrorIs(t, err, assert.AnError)
}

func TestWriteJSON_PropagatesMarshalError(t *testing.T) {
	err := writeJSON(&bytes.Buffer{}, make(chan int))
	require.Error(t, err)
}
