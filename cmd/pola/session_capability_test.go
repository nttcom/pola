// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"testing"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBuildCapabilitiesView_StatefulFlagDiffersFallsToOnlySets(t *testing.T) {
	// The TLV is common, but Color is local-only, so capabilities are compared
	// at token granularity.
	local := []grpc.Capability{
		{Type: "STATEFUL", Detail: grpc.StatefulCapability{LSPUpdate: true, LSPInstantiation: true, Color: true}},
	}
	peer := []grpc.Capability{
		{Type: "STATEFUL", Detail: grpc.StatefulCapability{LSPUpdate: true, LSPInstantiation: true}},
	}

	view := buildCapabilitiesView(local, peer)

	assert.True(t, view.Common.Stateful)
	assert.True(t, view.Common.Update)
	assert.True(t, view.Common.Instantiation)
	assert.Equal(t, []capabilityView{{Name: "color"}}, view.LocalOnly)
	assert.Empty(t, view.PeerOnly)
}

func TestBuildCapabilitiesView_MismatchedMSDFallsToBothOnlySets(t *testing.T) {
	local := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}}}
	peer := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(16)}}}

	view := buildCapabilitiesView(local, peer)

	assert.Nil(t, view.Common.SRMSD, "MSD mismatch must not appear in common")
	assert.Equal(t, []capabilityView{{Name: "msd", Value: "10"}}, view.LocalOnly)
	assert.Equal(t, []capabilityView{{Name: "msd", Value: "16"}}, view.PeerOnly)
}

func TestBuildCapabilitiesView_MatchingMSDIsCommon(t *testing.T) {
	local := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}}}
	peer := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}}}

	view := buildCapabilitiesView(local, peer)

	require.NotNil(t, view.Common.SRMSD)
	assert.Equal(t, uint32(10), *view.Common.SRMSD)
	assert.Empty(t, view.LocalOnly)
	assert.Empty(t, view.PeerOnly)
}

func TestBuildCapabilitiesView_AssociationTypesAndUnrecognizedTLVs(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "ASSOC_TYPE_LIST", Detail: grpc.AssocTypeListCapability{AssocTypes: []uint32{6, 9}}},
		{Type: "UNKNOWN", Detail: grpc.UnknownCapability{TLVType: 73}},
	}

	view := buildCapabilitiesView(caps, caps)

	assert.Equal(t, []uint32{6, 9}, view.Common.AssociationTypes)
	assert.Equal(t, []uint32{73}, view.Common.UnrecognizedTLVTypes)
}

func TestBuildCapabilitiesView_CapabilityAbsentFromOneSideIsWhollyOnOtherSide(t *testing.T) {
	local := []grpc.Capability{
		{Type: "MULTIPATH", Detail: grpc.MultipathCapability{MaxMultipaths: 4}},
	}

	view := buildCapabilitiesView(local, nil)

	assert.Contains(t, view.LocalOnly, capabilityView{Name: "multipath"})
	assert.Contains(t, view.LocalOnly, capabilityView{Name: "maxmultipaths", Value: "4"})
	assert.Empty(t, view.PeerOnly)
}

func TestBuildCapabilitiesView_EmptyBothSidesProducesEmptySlicesNotNil(t *testing.T) {
	view := buildCapabilitiesView(nil, nil)

	assert.NotNil(t, view.Common.PathSetupTypes)
	assert.Empty(t, view.Common.PathSetupTypes)
	assert.NotNil(t, view.Common.AssociationTypes)
	assert.NotNil(t, view.Common.UnrecognizedTLVTypes)
	assert.NotNil(t, view.LocalOnly)
	assert.NotNil(t, view.PeerOnly)
}

func TestOnlyTokens_DeduplicatesAndSorts(t *testing.T) {
	features := []capFeature{
		{group: "STATEFUL", token: "Color"},
		{group: "OTHER", token: "Color"}, // same token, different group
		{group: "SR", token: "MSD=10"},
	}

	got := onlyTokens(features)
	assert.Equal(t, []string{"color", "msd=10"}, got)
}

func TestUnrecognizedTLVItem(t *testing.T) {
	tests := map[string]struct {
		tlvType uint32
		want    string
	}{
		"RFC-defined":      {0x38, "type=56: SRPOLICY-POL-NAME (draft-ietf-pce-segment-routing-policy-cp-14)"},
		"vendor-specific":  {0xffe3, "type=65507: vendor-specific, no RFC"},
		"fully unassigned": {0xdead, "type=57005: unassigned/vendor-specific, no RFC"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, unrecognizedTLVItem(tt.tlvType))
		})
	}
}

func TestAssocTypeLabel(t *testing.T) {
	assert.Equal(t, "6 SR Policy Association", assocTypeLabel(6))
	assert.Equal(t, "9 P2MP SR Policy Association (draft)", assocTypeLabel(9))
	assert.Equal(t, "65535 Unknown AssocType (0xffff)", assocTypeLabel(0xffff))
}

func TestAssocTypeLabel_OutOfRange(t *testing.T) {
	assert.Equal(t, "65536 (out-of-range for AssocType)", assocTypeLabel(0x10000))
}

func TestUnrecognizedTLVItem_OutOfRange(t *testing.T) {
	assert.Equal(t, "type=65536: out of TLV registry range, no RFC", unrecognizedTLVItem(0x10000))
}

func TestParseTokenUint32_NonNumericSuffixReturnsFalse(t *testing.T) {
	_, ok := parseTokenUint32("MSD=notanumber", "MSD=")
	assert.False(t, ok)
}

func TestBuildCapabilitiesView_CommonPathSetupTypesAreCollected(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "PATH_SETUP_TYPE", Detail: grpc.PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}},
	}

	view := buildCapabilitiesView(caps, caps)
	assert.Equal(t, []string{"SR-TE", "SRv6-TE"}, view.Common.PathSetupTypes)
}

func TestCapGroupLabel_UnknownGroupReturnsGroupItself(t *testing.T) {
	assert.Equal(t, "FOO", capGroupLabel("FOO"))
}

func TestCommonCapabilityLines_GroupsByTLVExceptAssocTypeAndUnknown(t *testing.T) {
	common := []capFeature{
		{group: "STATEFUL", token: "Stateful"},
		{group: "STATEFUL", token: "Update"},
		{group: "ASSOC_TYPE_LIST", token: "AssocType:6"},
		{group: "ASSOC_TYPE_LIST", token: "AssocType:9"},
		{group: "UNKNOWN", token: "unknown_type_73"},
	}

	lines := commonCapabilityLines(common)
	assert.Equal(t, []capDisplayLine{
		{Header: "STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful, Update"},
		{Header: "ASSOC-TYPE-LIST [RFC8697]", Items: []string{
			"6 SR Policy Association",
			"9 P2MP SR Policy Association (draft)",
		}},
		{Header: "Unrecognized TLVs", Items: []string{
			"type=73: SR-P2MP-POLICY-CAPABILITY (draft-ietf-pce-sr-p2mp-policy-11)",
		}},
	}, lines)
}

func TestCommonCapabilityLines_OrdersByTLVTypeRegardlessOfInputOrder(t *testing.T) {
	common := []capFeature{
		{group: "MULTIPATH", token: "Multipath"},
		{group: "SR", token: "SR"},
		{group: "VENDOR_INFORMATION", token: "2636 (Juniper Networks, Inc.)"},
		{group: "STATEFUL", token: "Stateful"},
	}

	lines := commonCapabilityLines(common)
	var headers []string
	for _, line := range lines {
		headers = append(headers, line.Header)
	}
	assert.Equal(t, []string{
		"VENDOR-INFORMATION [RFC7470]: 2636 (Juniper Networks, Inc.)",
		"STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful",
		"SR-PCE-CAPABILITY [RFC8664]: SR",
		"MULTIPATH-CAP [draft-ietf-pce-multipath]: Multipath",
	}, headers)
}

func TestCommonCapabilityLines_UnknownGroupSortsLast(t *testing.T) {
	common := []capFeature{
		{group: "UNKNOWN", token: "unknown_type_73"},
		{group: "MULTIPATH", token: "Multipath"},
	}

	lines := commonCapabilityLines(common)
	assert.Equal(t, "MULTIPATH-CAP [draft-ietf-pce-multipath]: Multipath", lines[0].Header)
	assert.Equal(t, "Unrecognized TLVs", lines[1].Header)
}

func TestBuildCapabilitiesView_UntypedCommonCapabilitiesLandInOther(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "VENDOR_INFORMATION", Detail: grpc.VendorInformationCapability{EnterpriseNumber: uint32(pcep.EnterpriseNumberJuniper)}},
		{Type: "MULTIPATH", Detail: grpc.MultipathCapability{MaxMultipaths: 4, Weighted: true}},
		{Type: "LSP_DB_VERSION", Detail: grpc.LSPDBVersionCapability{VersionNumber: 1}},
		{Type: "SRV6", Detail: grpc.SRv6Capability{NAISupported: true}},
		{Type: "STATEFUL", Detail: grpc.StatefulCapability{TriggeredResync: true}},
	}

	view := buildCapabilitiesView(caps, caps)

	assert.Contains(t, view.Common.Other, capabilityView{Name: pcep.EnterpriseNumberJuniper.DisplayLabel()})
	assert.Contains(t, view.Common.Other, capabilityView{Name: "Multipath"})
	assert.Contains(t, view.Common.Other, capabilityView{Name: "MaxMultipaths", Value: "4"})
	assert.Contains(t, view.Common.Other, capabilityView{Name: "Weighted"})
	assert.Contains(t, view.Common.Other, capabilityView{Name: "LSP-DB-VERSION"})
	assert.Contains(t, view.Common.Other, capabilityView{Name: "SRv6-NAI-Supported"})
	assert.Contains(t, view.Common.Other, capabilityView{Name: "Triggered-Resync"})
	assert.True(t, view.Common.Stateful)
	assert.NotContains(t, view.Common.Other, capabilityView{Name: "Stateful"})
}

func TestBuildCapabilitiesView_OtherPreservesOriginalTokenCasing(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "VENDOR_INFORMATION", Detail: grpc.VendorInformationCapability{EnterpriseNumber: uint32(pcep.EnterpriseNumberJuniper)}},
	}

	view := buildCapabilitiesView(caps, caps)

	require.Len(t, view.Common.Other, 1)
	assert.Contains(t, view.Common.Other[0].Name, "Juniper")
}

func TestBuildCapabilitiesView_OtherIsSortedByNameThenValue(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "MULTIPATH", Detail: grpc.MultipathCapability{MaxMultipaths: 4, Weighted: true, OppositeDir: true}},
		{Type: "STATEFUL", Detail: grpc.StatefulCapability{TriggeredResync: true, Color: true}},
	}

	expected := []capabilityView{
		{Name: "Color"},
		{Name: "MaxMultipaths", Value: "4"},
		{Name: "Multipath"},
		{Name: "OppositeDir"},
		{Name: "Triggered-Resync"},
		{Name: "Weighted"},
	}

	view1 := buildCapabilitiesView(caps, caps)
	view2 := buildCapabilitiesView(caps, caps)

	assert.Equal(t, expected, view1.Common.Other)
	assert.Equal(t, view1.Common.Other, view2.Common.Other, "Other must be sorted deterministically across calls")
}

func TestBuildCapabilitiesView_OtherTiesOnNameSortByValue(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "MULTIPATH", Detail: grpc.MultipathCapability{MaxMultipaths: 8}},
		{Type: "MULTIPATH", Detail: grpc.MultipathCapability{MaxMultipaths: 4}},
	}

	view := buildCapabilitiesView(caps, caps)

	require.GreaterOrEqual(t, len(view.Common.Other), 2)
	assert.Equal(t, capabilityView{Name: "MaxMultipaths", Value: "4"}, view.Common.Other[0])
	assert.Equal(t, capabilityView{Name: "MaxMultipaths", Value: "8"}, view.Common.Other[1])
}

func TestBuildCapabilitiesView_TypedFieldsDoNotDuplicateIntoOther(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "STATEFUL", Detail: grpc.StatefulCapability{LSPUpdate: true, LSPInstantiation: true}},
		{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}},
		{Type: "ASSOC_TYPE_LIST", Detail: grpc.AssocTypeListCapability{AssocTypes: []uint32{6}}},
	}

	view := buildCapabilitiesView(caps, caps)

	assert.Equal(t, []capabilityView{{Name: "SR"}}, view.Common.Other)
}

func TestCommonCapabilityLines_SingleAssocTypeStillUsesHeadingForm(t *testing.T) {
	common := []capFeature{
		{group: "ASSOC_TYPE_LIST", token: "AssocType:6"},
	}

	lines := commonCapabilityLines(common)
	assert.Equal(t, []capDisplayLine{
		{Header: "ASSOC-TYPE-LIST [RFC8697]", Items: []string{"6 SR Policy Association"}},
	}, lines)
}
