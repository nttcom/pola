// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nttcom/pola/pkg/packet/pcep"
)

const enterpriseJuniperString = "Juniper (2636)"

func TestEnterpriseNumber_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		enterpriseNumber pcep.EnterpriseNumber
		expected         string
	}{
		"Cisco":       {pcep.EnterpriseNumberCisco, "Cisco (9)"},
		"Huawei":      {pcep.EnterpriseNumberHuawei, "Huawei (2011)"},
		"Juniper":     {pcep.EnterpriseNumberJuniper, enterpriseJuniperString},
		"UnknownEN":   {12345, "Unknown Enterprise (12345)"},
		"ZeroEN":      {0, "Unknown Enterprise (0)"},
		"MaxUint32EN": {pcep.EnterpriseNumber(^uint32(0)), "Unknown Enterprise (4294967295)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := tt.enterpriseNumber.String()
			assert.Equal(t, tt.expected, actual, "unexpected EnterpriseNumber.String() result")
		})
	}
}

func TestEnterpriseNumber_DisplayLabel(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		enterpriseNumber pcep.EnterpriseNumber
		expected         string
	}{
		"Cisco":     {pcep.EnterpriseNumberCisco, "9 (Cisco Systems, Inc.)"},
		"Huawei":    {pcep.EnterpriseNumberHuawei, "2011 (Huawei Technologies Co., Ltd.)"},
		"Juniper":   {pcep.EnterpriseNumberJuniper, "2636 (Juniper Networks, Inc.)"},
		"UnknownEN": {99999, "99999 (Unknown)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.enterpriseNumber.DisplayLabel())
		})
	}
}
