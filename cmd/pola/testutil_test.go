// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"strings"

	"github.com/stretchr/testify/assert"
)

const (
	testPeerAddr1 = "192.0.2.1"
	testPeerAddr2 = "192.0.2.2"

	testRouterID1 = "0000.0aff.0001"
	testRouterID2 = "0000.0aff.0002"

	testPolicyName = "pol1"

	testSrv6EndXSID = "fc00:0:1:endx::"
)

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
