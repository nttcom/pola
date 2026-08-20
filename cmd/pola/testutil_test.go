// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, f func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	f()

	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

func captureStderr(t *testing.T, f func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	f()

	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

// condFailWriter injects a write error when the content matches its predicate.
type condFailWriter struct {
	fail func(string) bool
	buf  bytes.Buffer
}

func (w *condFailWriter) Write(p []byte) (int, error) {
	if w.fail != nil && w.fail(string(p)) {
		return 0, assert.AnError
	}
	return w.buf.Write(p)
}

func containsFail(sub string) func(string) bool {
	return func(s string) bool { return strings.Contains(s, sub) }
}

func exactFail(s string) func(string) bool {
	return func(p string) bool { return p == s }
}
