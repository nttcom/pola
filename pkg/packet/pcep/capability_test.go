// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
				&StatefulPCECapability{
					LSPUpdateCapability:        false,
					IncludeDBVersion:           true,
					LSPInstantiationCapability: false,
					TriggeredResync:            true,
					DeltaLSPSyncCapability:     true,
					TriggeredInitialSync:       true,
				},
				&PathSetupTypeCapability{
					PathSetupTypes: Psts{PathSetupTypeRSVPTE, PathSetupTypeSRTE, PathSetupTypeSRv6TE},
					SubTLVs: []TLVInterface{
						&SRPCECapability{
							HasUnlimitedMaxSIDDepth: false,
							IsNAISupported:          false,
							MaximumSidDepth:         uint8(16),
						},
					},
				},
				&SRPCECapability{
					HasUnlimitedMaxSIDDepth: false,
					IsNAISupported:          false,
					MaximumSidDepth:         uint8(16),
				},
				&AssocTypeList{
					AssocTypes: []AssocType{AssocTypePathProtectionAssociation, AssocTypeSRPolicyAssociation},
				},
			},
			expected: []CapabilityInterface{
				&StatefulPCECapability{
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
				},
				&PathSetupTypeCapability{
					PathSetupTypes: Psts{PathSetupTypeRSVPTE, PathSetupTypeSRTE, PathSetupTypeSRv6TE},
					SubTLVs: []TLVInterface{
						&SRPCECapability{
							HasUnlimitedMaxSIDDepth: false,
							IsNAISupported:          false,
							MaximumSidDepth:         uint8(16),
						},
					},
				},
				&SRPCECapability{
					HasUnlimitedMaxSIDDepth: false,
					IsNAISupported:          false,
					MaximumSidDepth:         uint8(16),
				},
				&AssocTypeList{
					AssocTypes: []AssocType{AssocTypePathProtectionAssociation, AssocTypeSRPolicyAssociation},
				},
			},
		},
		{
			name: "Includes LSPDBVersion (should be skipped)",
			input: []CapabilityInterface{
				&LSPDBVersion{},
			},
			expected: []CapabilityInterface{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, PolaCapability(tt.input))
		})
	}
}

func TestPolaCapability_OutputAlwaysSerializes(t *testing.T) {
	caps := []CapabilityInterface{
		&StatefulPCECapability{LSPUpdateCapability: true},
		&SRPCECapability{MaximumSidDepth: 16},
		&PathSetupTypeCapability{PathSetupTypes: Psts{PathSetupTypeSRTE}},
		&AssocTypeList{AssocTypes: []AssocType{AssocTypeSRPolicyAssociation}},
		&LSPDBVersion{VersionNumber: 1},
	}

	for _, cap := range PolaCapability(caps) {
		_, err := cap.Serialize()
		assert.NoError(t, err, "PolaCapability output must always serialize: %T", cap)
	}
}
