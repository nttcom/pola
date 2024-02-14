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
	expected := []CapabilityInterface{
		&StatefulPceCapability{
			LspUpdateCapability:        true,
			IncludeDBVersion:           false,
			LspInstantiationCapability: true,
			TriggeredResync:            false,
			DeltaLspSyncCapability:     false,
			TriggeredInitialSync:       false,
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
	}

	result := PolaCapability()
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Unexpected result, expected: %v, got: %v", expected, result)
	}
}
