// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	want := fmt.Sprintf("%d.%d.%d", Major, Minor, Patch)
	assert.Equal(t, want, Version())
}
