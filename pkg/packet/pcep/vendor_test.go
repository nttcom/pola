// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const enterpriseJuniperString = "Juniper (2636)"

func TestEnterpriseNumber_String(t *testing.T) {
	cases := map[string]struct {
		enterpriseNumber EnterpriseNumber
		expected         string
	}{
		"Cisco":       {EnterpriseNumberCisco, "Cisco (9)"},
		"Huawei":      {EnterpriseNumberHuawei, "Huawei (2011)"},
		"Juniper":     {EnterpriseNumberJuniper, enterpriseJuniperString},
		"UnknownEN":   {12345, "Unknown Enterprise (12345)"},
		"ZeroEN":      {0, "Unknown Enterprise (0)"},
		"MaxUint32EN": {EnterpriseNumber(^uint32(0)), "Unknown Enterprise (4294967295)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			actual := tt.enterpriseNumber.String()
			assert.Equal(t, tt.expected, actual, "unexpected EnterpriseNumber.String() result")
		})
	}
}

func TestEnterpriseNumber_DisplayLabel(t *testing.T) {
	cases := map[string]struct {
		enterpriseNumber EnterpriseNumber
		expected         string
	}{
		"Cisco":     {EnterpriseNumberCisco, "9 (Cisco Systems, Inc.)"},
		"Huawei":    {EnterpriseNumberHuawei, "2011 (Huawei Technologies Co., Ltd.)"},
		"Juniper":   {EnterpriseNumberJuniper, "2636 (Juniper Networks, Inc.)"},
		"UnknownEN": {99999, "99999 (Unknown)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.enterpriseNumber.DisplayLabel())
		})
	}
}
