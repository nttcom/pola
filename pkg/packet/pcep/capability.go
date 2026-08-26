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
func polaAssocTypeList() *AssocTypeList {
	return &AssocTypeList{
		AssocTypes: []AssocType{AssocTypeSRPolicyAssociation},
	}
}

// DefaultCapabilities returns the capabilities Pola advertises in its OPEN.
func DefaultCapabilities() []CapabilityInterface {
	return []CapabilityInterface{
		polaStatefulCapability(),
		polaPathSetupTypeCapability(),
		polaAssocTypeList(),
	}
}
