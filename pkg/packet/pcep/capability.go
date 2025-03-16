// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

type CapabilityInterface interface {
	TLVInterface
	CapStrings() []string
}

func PolaCapability(caps []CapabilityInterface) []CapabilityInterface {
	polaCaps := []CapabilityInterface{}
	for _, cap := range caps {
		switch tlv := cap.(type) {
		case *StatefulPceCapability:
			tlv = &StatefulPceCapability{
				LspUpdateCapability:            true,
				IncludeDBVersion:               false,
				LspInstantiationCapability:     true,
				TriggeredResync:                false,
				DeltaLspSyncCapability:         false,
				TriggeredInitialSync:           false,
				P2mpCapability:                 false,
				P2mpLspUpdateCapability:        false,
				P2mpLspInstantiationCapability: false,
				LspSchedulingCapability:        false,
				PdLspCapability:                false,
				PathRecomputationCapability:    false,
				StrictPathCapability:           false,
				Relax:                          false,
			}
			polaCaps = append(polaCaps, tlv)
		case *LSPDBVersion:
			continue
		default:
			polaCaps = append(polaCaps, tlv)
		}
	}
	return polaCaps
}
