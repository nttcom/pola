// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"testing"

	"go.uber.org/zap"
)

// Regression test: strconv.Atoi accepts negative numbers, which used to
// wrap around to a valid uint16 (e.g. -1 -> 65535) instead of being rejected.
func TestServer_Serve_NegativePortRejected(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	if err := s.Serve("127.0.0.1", "-1", false); err == nil {
		t.Fatal("expected error for negative port")
	}
}

func TestServer_Serve_PortOutOfRange(t *testing.T) {
	s := &Server{logger: zap.NewNop()}
	if err := s.Serve("127.0.0.1", "70000", false); err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}
