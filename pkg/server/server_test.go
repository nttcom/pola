// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// Regression test: strconv.Atoi accepts negative numbers, which used to
// wrap around to a valid uint16 (e.g. -1 -> 65535) instead of being rejected.
func TestServer_Serve_NegativePortRejected(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	assert.Error(t, s.Serve("127.0.0.1", "-1", false))
}

func TestServer_Serve_PortOutOfRange(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	assert.Error(t, s.Serve("127.0.0.1", "70000", false))
}
