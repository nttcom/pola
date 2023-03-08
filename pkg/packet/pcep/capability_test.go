// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"reflect"
	"testing"
)

func TestPolaCapability(t *testing.T) {
	tests := []struct {
		name     string
		input    []CapabilityInterface
		expected []CapabilityInterface
	}{
		{
			name: "Basic Capability Test",
			input: []CapabilityInterface{
				&StatefulPceCapability{
					LspUpdateCapability:        false,
					IncludeDBVersion:           true,
					LspInstantiationCapability: false,
					TriggeredResync:            true,
					DeltaLspSyncCapability:     true,
					TriggeredInitialSync:       true,
				},
				&PathSetupTypeCapability{
					PathSetupTypes: Psts{PST_RSVP_TE, PST_SR_TE, PST_SRV6_TE},
					SubTLVs: []TLVInterface{
						&SRPceCapability{
							UnlimitedMSD:    false,
							SupportNAI:      false,
							MaximumSidDepth: uint8(16),
						},
					},
				},
				&SRPceCapability{
					UnlimitedMSD:    false,
					SupportNAI:      false,
					MaximumSidDepth: uint8(16),
				},
				&AssocTypeList{
					AssocTypes: []AssocType{AT_PATH_PROTECTION_ASSOCIATION, AT_SR_POLICY_ASSOCIATION},
				},
			},
			expected: []CapabilityInterface{
				&StatefulPceCapability{
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
					ColorCapability:                true,
					PathRecomputationCapability:    false,
					StrictPathCapability:           false,
					Relax:                          false,
				},
				&PathSetupTypeCapability{
					PathSetupTypes: Psts{PST_RSVP_TE, PST_SR_TE, PST_SRV6_TE},
					SubTLVs: []TLVInterface{
						&SRPceCapability{
							UnlimitedMSD:    false,
							SupportNAI:      false,
							MaximumSidDepth: uint8(16),
						},
					},
				},
				&SRPceCapability{
					UnlimitedMSD:    false,
					SupportNAI:      false,
					MaximumSidDepth: uint8(16),
				},
				&AssocTypeList{
					AssocTypes: []AssocType{AT_PATH_PROTECTION_ASSOCIATION, AT_SR_POLICY_ASSOCIATION},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PolaCapability(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Fatalf("%s: expected %+v, got %+v", tt.name, tt.expected, result)
			}
		})
	}
}
