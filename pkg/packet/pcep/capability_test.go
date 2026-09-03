// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCapabilities(t *testing.T) {
	t.Parallel()

	caps := DefaultCapabilities()
	require.Len(t, caps, 4)

	statefulCap, ok := caps[0].(*StatefulPCECapability)
	require.True(t, ok, "expected DefaultCapabilities[0] to be a StatefulPCECapability")
	assert.True(t, statefulCap.LSPUpdateCapability)
	assert.True(t, statefulCap.LSPInstantiationCapability)
	assert.True(t, statefulCap.ColorCapability)

	pstCap, ok := caps[1].(*PathSetupTypeCapability)
	require.True(t, ok, "expected DefaultCapabilities[1] to be a PathSetupTypeCapability")
	assert.Equal(t, Psts{PathSetupTypeSRTE, PathSetupTypeSRv6TE}, pstCap.PathSetupTypes)
	require.Len(t, pstCap.SubTLVs, 2)

	srCap, ok := pstCap.SubTLVs[0].(*SRPCECapability)
	require.True(t, ok, "expected the first PST-CAPABILITY sub-TLV to be SR-PCE-CAPABILITY")
	// RFC 8664 §5.1: a PCE MUST set N-Flag=0, X-Flag=1, and MSD=0.
	assert.False(t, srCap.IsNAISupported)
	assert.True(t, srCap.HasUnlimitedMaxSIDDepth)
	assert.Equal(t, uint8(0), srCap.MaximumSidDepth)

	srv6Cap, ok := pstCap.SubTLVs[1].(*SRv6PCECapability)
	require.True(t, ok, "expected the second PST-CAPABILITY sub-TLV to be SRv6-PCE-CAPABILITY")
	// RFC 9603 §5.1: a PCE MUST set the N flag to zero and omit the MSD.
	assert.False(t, srv6Cap.IsNAISupported)

	assocCap, ok := caps[2].(*AssocTypeList)
	require.True(t, ok, "expected DefaultCapabilities[2] to be an AssocTypeList")
	// RFC 9862 §5.2: a PCEP speaker MUST advertise the SRPA type before using it.
	assert.Equal(t, []AssocType{AssocTypeSRPolicyAssociation}, assocCap.AssocTypes)
	assert.NotContains(t, assocCap.AssocTypes, AssocTypeSRPolicyAssociationCisco)
	assert.NotContains(t, assocCap.AssocTypes, AssocTypeSRPolicyAssociationJuniper)

	multipathCap, ok := caps[3].(*MultipathCapability)
	require.True(t, ok, "expected DefaultCapabilities[3] to be a MultipathCapability")
	assert.Equal(t, uint16(1), multipathCap.MaxMultipaths)
	assert.False(t, multipathCap.IsWeightedSupported)
	assert.False(t, multipathCap.IsOppositeDirSupported)
	assert.False(t, multipathCap.IsForwardClassSupported)
	assert.False(t, multipathCap.IsCompositePathSupported)
}

func TestFlattenCapabilities(t *testing.T) {
	t.Parallel()

	statefulCap := &StatefulPCECapability{LSPUpdateCapability: true}
	srCap := &SRPCECapability{HasUnlimitedMaxSIDDepth: true}
	srv6Cap := &SRv6PCECapability{IsNAISupported: true}
	pstCap := &PathSetupTypeCapability{
		PathSetupTypes: Psts{PathSetupTypeSRTE, PathSetupTypeSRv6TE},
		SubTLVs:        []TLVInterface{srCap, srv6Cap},
	}

	cases := map[string]struct {
		input    []CapabilityInterface
		expected []CapabilityInterface
	}{
		"Nil": {nil, []CapabilityInterface{}},
		"TopLevelOnly": {
			[]CapabilityInterface{statefulCap},
			[]CapabilityInterface{statefulCap},
		},
		"PSTCapAppendsSubCapabilitiesAfterTopLevel": {
			[]CapabilityInterface{statefulCap, pstCap},
			[]CapabilityInterface{statefulCap, pstCap, srCap, srv6Cap},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.expected, FlattenCapabilities(c.input))
		})
	}
}

func TestDefaultCapabilities_WireRoundTrip(t *testing.T) {
	t.Parallel()

	for _, cap := range DefaultCapabilities() {
		b, err := cap.Serialize()
		require.NoError(t, err, "%T must serialize", cap)

		decodedTLVs, err := DecodeTLVs(b)
		require.NoError(t, err, "%T must decode its own serialized bytes", cap)
		require.Len(t, decodedTLVs, 1)
		assert.Equal(t, cap, decodedTLVs[0], "%T round-trip mismatch", cap)
	}
}
