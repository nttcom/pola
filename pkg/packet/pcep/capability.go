// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

// CapabilityInterface is a common interface for PCEP capability TLVs.
type CapabilityInterface interface {
	TLVInterface
	CapStrings() []string
}

// polaStatefulCapability returns Pola's Stateful PCE Capability (RFC 8231).
func polaStatefulCapability() *StatefulPCECapability {
	return &StatefulPCECapability{
		LSPUpdateCapability:            true,
		IncludeDBVersion:               false,
		LSPInstantiationCapability:     true,
		TriggeredResync:                false,
		DeltaLSPSyncCapability:         false,
		TriggeredInitialSync:           false,
		P2mpCapability:                 false,
		P2mpLSPUpdateCapability:        false,
		P2mpLSPInstantiationCapability: false,
		LSPSchedulingCapability:        false,
		PdLSPCapability:                false,
		ColorCapability:                true,
		PathRecomputationCapability:    false,
		StrictPathCapability:           false,
		Relax:                          false,
	}
}

// polaPathSetupTypeCapability returns Pola's supported path setup types
// and their corresponding SR capability sub-TLVs.
func polaPathSetupTypeCapability() *PathSetupTypeCapability {
	return &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeSRTE, PathSetupTypeSRv6TE},
		SubTLVs: []TLVInterface{
			&SRPCECapability{HasUnlimitedMaxSIDDepth: true},
			&SRv6PCECapability{},
		},
	}
}

// polaAssocTypeList returns Pola's ASSOC-TYPE-LIST TLV.
//
// Only the IANA-assigned SR Policy Association type is advertised.
// Legacy Cisco (0x14) and Juniper (0xffe1) values are peer-specific
// interop quirks and are handled after the peer's OPEN is received.
func polaAssocTypeList() *AssocTypeList {
	return &AssocTypeList{
		AssocTypes: []AssocType{AssocTypeSRPolicyAssociation},
	}
}

// FlattenCapabilities appends PATH-SETUP-TYPE-CAPABILITY sub-capabilities
// to the top-level list. This normalizes the two nesting forms allowed by
// RFC 8664 Appendix A. Only one level of nesting is expanded.
func FlattenCapabilities(caps []CapabilityInterface) []CapabilityInterface {
	ret := make([]CapabilityInterface, 0, len(caps))
	ret = append(ret, caps...)

	for _, c := range caps {
		if pstCap, ok := c.(*PathSetupTypeCapability); ok {
			ret = append(ret, pstCap.SubCapabilities()...)
		}
	}

	return ret
}

// DefaultCapabilities returns the capabilities Pola advertises in its OPEN.
func DefaultCapabilities() []CapabilityInterface {
	return []CapabilityInterface{
		polaStatefulCapability(),
		polaPathSetupTypeCapability(),
		polaAssocTypeList(),
	}
}
