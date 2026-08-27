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
	assert.Equal(t, []capGroupView{{Capability: "STATEFUL", Items: []string{"Color"}}}, view.LocalOnly)
	assert.Empty(t, view.PeerOnly)
}

func TestBuildCapabilitiesView_MismatchedMSDFallsToBothOnlySets(t *testing.T) {
	local := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}}}
	peer := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(16)}}}

	view := buildCapabilitiesView(local, peer)

	assert.Equal(t, []capGroupView{{Capability: "SR", Items: []string{"SR"}}}, view.Common.Other,
		"the shared \"SR\" token must appear in common, but the mismatched MSD must not")
	assert.Equal(t, []capGroupView{{Capability: "SR", Items: []string{"MSD=10"}}}, view.LocalOnly)
	assert.Equal(t, []capGroupView{{Capability: "SR", Items: []string{"MSD=16"}}}, view.PeerOnly)
}

func TestBuildCapabilitiesView_MatchingMSDIsCommon(t *testing.T) {
	local := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}}}
	peer := []grpc.Capability{{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}}}

	view := buildCapabilitiesView(local, peer)

	assert.Equal(t, []capGroupView{{Capability: "SR", Items: []string{"SR", "MSD=10"}}}, view.Common.Other)
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

	require.Len(t, view.LocalOnly, 1)
	assert.Equal(t, "MULTIPATH", view.LocalOnly[0].Capability)
	assert.Contains(t, view.LocalOnly[0].Items, "Multipath")
	assert.Contains(t, view.LocalOnly[0].Items, "MaxMultipaths=4")
	assert.Empty(t, view.PeerOnly)
}

func TestBuildCapabilitiesView_PathSetupTypeSubCapabilitiesActAsOwnGroups(t *testing.T) {
	local := []grpc.Capability{
		{Type: "PATH_SETUP_TYPE", Detail: grpc.PathSetupTypeCapability{
			PathSetupTypes: []uint32{1, 3},
			SubCapabilities: []grpc.Capability{
				{Type: "SR", Detail: grpc.SRCapability{UnlimitedMSD: true}},
				{Type: "SRV6", Detail: grpc.SRv6Capability{}},
			},
		}},
	}
	peer := []grpc.Capability{
		{Type: "PATH_SETUP_TYPE", Detail: grpc.PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}},
		{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(0)}},
		{Type: "SRV6", Detail: grpc.SRv6Capability{}},
	}

	view := buildCapabilitiesView(local, peer)

	lines := view.commonLines()
	headers := make([]string, len(lines))
	for i, l := range lines {
		headers[i] = l.Header
	}
	assert.Contains(t, headers, "SR-PCE-CAPABILITY [RFC8664]: SR",
		"SR sub-capability must render as its own common group")
	assert.Contains(t, headers, "SRv6-PCE-CAPABILITY [RFC9603]: SRv6",
		"SRv6 sub-capability must render as its own common group")

	assert.Equal(t, []capGroupView{{Capability: "SR", Items: []string{"Unlimited-SID-Depth"}}}, view.LocalOnly)
	assert.Equal(t, []capGroupView{{Capability: "SR", Items: []string{"MSD=0"}}}, view.PeerOnly)
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

func TestCapabilitiesFeatures_DeduplicatesByGroupAndToken(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "SR", Detail: grpc.SRCapability{UnlimitedMSD: true}},
	}

	got := capabilitiesFeatures(caps)
	assert.Equal(t, []capFeature{{group: "SR", token: "SR"}, {group: "SR", token: "Unlimited-SID-Depth"}}, got)
}

func TestBuildCapabilitiesView_PeerSRAdvertisedTopLevelAndNestedDedupesToOneCommonEntry(t *testing.T) {
	peer := []grpc.Capability{
		{Type: "SR", Detail: grpc.SRCapability{UnlimitedMSD: true}},
		{Type: "PATH_SETUP_TYPE", Detail: grpc.PathSetupTypeCapability{
			PathSetupTypes: []uint32{1},
			SubCapabilities: []grpc.Capability{
				{Type: "SR", Detail: grpc.SRCapability{UnlimitedMSD: true}},
			},
		}},
	}

	view := buildCapabilitiesView(peer, peer)

	require.Len(t, view.Common.Other, 1)
	assert.Equal(t, capGroupView{Capability: "SR", Items: []string{"SR", "Unlimited-SID-Depth"}}, view.Common.Other[0])
	assert.Empty(t, view.LocalOnly)
	assert.Empty(t, view.PeerOnly)
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

func TestParseTokenUint32_PrefixMismatchReturnsFalse(t *testing.T) {
	_, ok := parseTokenUint32("AssocType:6", "MSD=")
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

	lines := capabilityLines(capabilityGroups(common))
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

	lines := capabilityLines(capabilityGroups(common))
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

	lines := capabilityLines(capabilityGroups(common))
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

	otherByGroup := make(map[string][]string, len(view.Common.Other))
	for _, g := range view.Common.Other {
		otherByGroup[g.Capability] = g.Items
	}
	assert.Contains(t, otherByGroup["VENDOR_INFORMATION"], pcep.EnterpriseNumberJuniper.DisplayLabel())
	assert.Contains(t, otherByGroup["MULTIPATH"], "Multipath")
	assert.Contains(t, otherByGroup["MULTIPATH"], "MaxMultipaths=4")
	assert.Contains(t, otherByGroup["MULTIPATH"], "Weighted")
	assert.Contains(t, otherByGroup["LSP_DB_VERSION"], "LSP-DB-VERSION")
	assert.Contains(t, otherByGroup["SRV6"], "SRv6-NAI-Supported")
	assert.Contains(t, otherByGroup["STATEFUL"], "Triggered-Resync")
	assert.True(t, view.Common.Stateful)
	assert.NotContains(t, otherByGroup["STATEFUL"], "Stateful")
}

func TestBuildCapabilitiesView_OtherPreservesOriginalTokenCasing(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "VENDOR_INFORMATION", Detail: grpc.VendorInformationCapability{EnterpriseNumber: uint32(pcep.EnterpriseNumberJuniper)}},
	}

	view := buildCapabilitiesView(caps, caps)

	require.Len(t, view.Common.Other, 1)
	require.Len(t, view.Common.Other[0].Items, 1)
	assert.Contains(t, view.Common.Other[0].Items[0], "Juniper")
}

func TestBuildCapabilitiesView_OtherIsGroupedDeterministically(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "MULTIPATH", Detail: grpc.MultipathCapability{MaxMultipaths: 4, Weighted: true, OppositeDir: true}},
		{Type: "STATEFUL", Detail: grpc.StatefulCapability{TriggeredResync: true, Color: true}},
	}

	expected := []capGroupView{
		{Capability: "STATEFUL", Items: []string{"Triggered-Resync", "Color"}},
		{Capability: "MULTIPATH", Items: []string{"Multipath", "MaxMultipaths=4", "Weighted", "OppositeDir"}},
	}

	view1 := buildCapabilitiesView(caps, caps)
	view2 := buildCapabilitiesView(caps, caps)

	assert.Equal(t, expected, view1.Common.Other)
	assert.Equal(t, view1.Common.Other, view2.Common.Other, "Other must be grouped deterministically across calls")
}

func TestBuildCapabilitiesView_TypedFieldsDoNotDuplicateIntoOther(t *testing.T) {
	caps := []grpc.Capability{
		{Type: "STATEFUL", Detail: grpc.StatefulCapability{LSPUpdate: true, LSPInstantiation: true}},
		{Type: "SR", Detail: grpc.SRCapability{MSD: proto.Uint32(10)}},
		{Type: "ASSOC_TYPE_LIST", Detail: grpc.AssocTypeListCapability{AssocTypes: []uint32{6}}},
	}

	view := buildCapabilitiesView(caps, caps)

	assert.Equal(t, []capGroupView{{Capability: "SR", Items: []string{"SR", "MSD=10"}}}, view.Common.Other)
}

func TestCommonCapabilityLines_SingleAssocTypeStillUsesHeadingForm(t *testing.T) {
	common := []capFeature{
		{group: "ASSOC_TYPE_LIST", token: "AssocType:6"},
	}

	lines := capabilityLines(capabilityGroups(common))
	assert.Equal(t, []capDisplayLine{
		{Header: "ASSOC-TYPE-LIST [RFC8697]", Items: []string{"6 SR Policy Association"}},
	}, lines)
}

func TestBuildCapabilitiesView_PeerOnlyUnrecognizedTLVUsesRegistryLabel(t *testing.T) {
	peer := []grpc.Capability{
		{Type: "UNKNOWN", Detail: grpc.UnknownCapability{TLVType: 73}},
	}

	view := buildCapabilitiesView(nil, peer)

	assert.Equal(t, []capGroupView{{
		Capability: "UNKNOWN",
		Items:      []string{"type=73: SR-P2MP-POLICY-CAPABILITY (draft-ietf-pce-sr-p2mp-policy-11)"},
	}}, view.PeerOnly)
}

func TestBuildCapabilitiesView_LocalOnlyAssocTypeUsesRegistryLabel(t *testing.T) {
	local := []grpc.Capability{
		{Type: "ASSOC_TYPE_LIST", Detail: grpc.AssocTypeListCapability{AssocTypes: []uint32{6}}},
	}

	view := buildCapabilitiesView(local, nil)

	assert.Equal(t, []capGroupView{{
		Capability: "ASSOC_TYPE_LIST",
		Items:      []string{"6 SR Policy Association"},
	}}, view.LocalOnly)
}

func TestBuildCapabilitiesView_VendorInformationTokenIsNotLowercased(t *testing.T) {
	peer := []grpc.Capability{
		{Type: "VENDOR_INFORMATION", Detail: grpc.VendorInformationCapability{EnterpriseNumber: uint32(pcep.EnterpriseNumberJuniper)}},
	}

	view := buildCapabilitiesView(nil, peer)

	require.Len(t, view.PeerOnly, 1)
	require.Len(t, view.PeerOnly[0].Items, 1)
	assert.Contains(t, view.PeerOnly[0].Items[0], "Juniper")
}
