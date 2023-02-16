// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

type CapabilityInterface interface {
	TlvInterface
}

func PolaCapability() []CapabilityInterface {
	return []CapabilityInterface{
		&StatefulPceCapability{
			LspUpdateCapability:        true,
			IncludeDBVersion:           false,
			LspInstantiationCapability: true,
			TriggeredResync:            false,
			DeltaLspSyncCapability:     false,
			TriggeredInitialSync:       false,
		},
		&PathSetupTypeCapability{
			Length:         uint16(10),
			PathSetupTypes: Psts{PST_RSVP_TE, PST_SR_TE, PST_SRV6_TE},
			SubTlvs: []TlvInterface{
				&SrPceCapability{
					UnlimitedMSD:    false,
					SupportNAI:      false,
					MaximumSidDepth: uint8(16),
				},
			},
		},
		&SrPceCapability{
			UnlimitedMSD:    false,
			SupportNAI:      false,
			MaximumSidDepth: uint8(16),
		},
		&AssocTypeList{
			AssocTypes: []AssocType{AT_PATH_PROTECTION_ASSOCIATION, AT_SR_POLICY_ASSOCIATION},
		},
	}
}
