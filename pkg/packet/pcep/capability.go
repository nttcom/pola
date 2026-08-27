// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

// CapabilityInterface identifies TLVs valid in an OPEN object's capability list.
type CapabilityInterface interface {
	TLVInterface
	isCapability()
}

// polaStatefulCapability returns Pola's Stateful PCE Capability.
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

// polaPathSetupTypeCapability returns Pola's supported path setup types.
func polaPathSetupTypeCapability() *PathSetupTypeCapability {
	return &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeSRTE, PathSetupTypeSRv6TE},
		SubTLVs: []TLVInterface{
			&SRPCECapability{HasUnlimitedMaxSIDDepth: true},
			&SRv6PCECapability{},
		},
	}
}

// polaAssocTypeList returns the IANA-assigned SR Policy Association type.
// Legacy Cisco (0x14) and Juniper (0xffe1) values are handled separately
// after the peer's OPEN is received.
func polaAssocTypeList() *AssocTypeList {
	return &AssocTypeList{
		AssocTypes: []AssocType{AssocTypeSRPolicyAssociation},
	}
}

// polaMultipathCapability advertises support for a single path per request.
func polaMultipathCapability() *MultipathCapability {
	return NewMultipathCapability(1, false, false, false, false)
}

// FlattenCapabilities normalizes the two capability nesting forms allowed by
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
		polaMultipathCapability(),
	}
}
