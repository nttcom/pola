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

// DefaultCapabilities returns Pola's default advertised capabilities.
func DefaultCapabilities() []CapabilityInterface {
	return []CapabilityInterface{polaStatefulCapability()}
}

// PolaCapability converts received capabilities to those advertised by Pola.
func PolaCapability(caps []CapabilityInterface) []CapabilityInterface {
	polaCaps := []CapabilityInterface{}
	for _, cap := range caps {
		switch tlv := cap.(type) {
		case *StatefulPCECapability:
			polaCaps = append(polaCaps, polaStatefulCapability())
		case *LSPDBVersion:
			continue
		default:
			polaCaps = append(polaCaps, tlv)
		}
	}
	return polaCaps
}
