// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"fmt"
)

// EnterpriseNumber is an IANA Private Enterprise Number, used by the VENDOR-INFORMATION TLV and Object (RFC 7470).
// See https://www.iana.org/assignments/enterprise-numbers/
type EnterpriseNumber uint32

// EnterpriseNumberLength is the wire length of the Enterprise Number field.
const EnterpriseNumberLength uint16 = 4

// Enterprise Numbers of vendors whose PCEP implementation has been verified against pola.
const (
	// EnterpriseNumberCisco is the IANA enterprise number for Cisco.
	EnterpriseNumberCisco EnterpriseNumber = 9
	// EnterpriseNumberHuawei is the IANA enterprise number for Huawei.
	EnterpriseNumberHuawei EnterpriseNumber = 2011
	// EnterpriseNumberJuniper is the IANA enterprise number for Juniper.
	EnterpriseNumberJuniper EnterpriseNumber = 2636
)

// enterpriseNumberNames holds space-free vendor names so they can be used in capability listings.
var enterpriseNumberNames = map[EnterpriseNumber]string{
	EnterpriseNumberCisco:   "Cisco",
	EnterpriseNumberHuawei:  "Huawei",
	EnterpriseNumberJuniper: "Juniper",
}

// String returns a human-readable representation of the enterprise number.
func (en EnterpriseNumber) String() string {
	if name, ok := enterpriseNumberNames[en]; ok {
		return fmt.Sprintf("%s (%d)", name, uint32(en))
	}

	return fmt.Sprintf("Unknown Enterprise (%d)", uint32(en))
}

var enterpriseNumberFullNames = map[EnterpriseNumber]string{
	EnterpriseNumberCisco:   "Cisco Systems, Inc.",
	EnterpriseNumberHuawei:  "Huawei Technologies Co., Ltd.",
	EnterpriseNumberJuniper: "Juniper Networks, Inc.",
}

// DisplayLabel returns the enterprise number and vendor name.
func (en EnterpriseNumber) DisplayLabel() string {
	name, ok := enterpriseNumberFullNames[en]
	if !ok {
		name = "Unknown"
	}

	return fmt.Sprintf("%d (%s)", uint32(en), name)
}
