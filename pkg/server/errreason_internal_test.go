// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
)

func TestNewStatus_OKCodeReturnsNilError(t *testing.T) {
	t.Parallel()

	err := newStatus(codes.OK, ReasonInvalidRequest, "no error")
	assert.NoError(t, err)
}
