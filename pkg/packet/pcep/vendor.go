// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"fmt"
	"strconv"
)

// EnterpriseNumber is an IANA Private Enterprise Number, used by the VENDOR-INFORMATION TLV and Object (RFC7470).
// See https://www.iana.org/assignments/enterprise-numbers/
type EnterpriseNumber uint32

// EnterpriseNumberLength is the wire length of the Enterprise Number field.
const EnterpriseNumberLength uint16 = 4

// Enterprise Numbers of vendors whose PCEP implementation has been verified against pola.
const (
	EnterpriseNumberCisco   EnterpriseNumber = 9
	EnterpriseNumberHuawei  EnterpriseNumber = 2011
	EnterpriseNumberJuniper EnterpriseNumber = 2636
)

// enterpriseNumberNames holds space-free vendor names so they can be used in capability listings.
var enterpriseNumberNames = map[EnterpriseNumber]string{
	EnterpriseNumberCisco:   "Cisco",
	EnterpriseNumberHuawei:  "Huawei",
	EnterpriseNumberJuniper: "Juniper",
}

func (en EnterpriseNumber) String() string {
	if name, ok := enterpriseNumberNames[en]; ok {
		return fmt.Sprintf("%s (%d)", name, uint32(en))
	}
	return fmt.Sprintf("Unknown Enterprise (%d)", uint32(en))
}

// capLabel returns a compact, space-free vendor label for capability listings.
func (en EnterpriseNumber) capLabel() string {
	if name, ok := enterpriseNumberNames[en]; ok {
		return name
	}
	return "EN-" + strconv.FormatUint(uint64(en), 10)
}
