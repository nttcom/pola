// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/pkg/packet/pcep"
)

// Capability group identifiers, as reported by grpc.Capability.Type.
const (
	capGroupStateful          = "STATEFUL"
	capGroupSRv6              = "SRV6"
	capGroupPathSetupType     = "PATH_SETUP_TYPE"
	capGroupAssocTypeList     = "ASSOC_TYPE_LIST" //nolint:gosec // capability identifier, not a credential.
	capGroupLSPDBVersion      = "LSP_DB_VERSION"
	capGroupMultipath         = "MULTIPATH"
	capGroupVendorInformation = "VENDOR_INFORMATION"
	capGroupUnknown           = "UNKNOWN"
)

const assocTypeListLabel = "ASSOC-TYPE-LIST [RFC8697]"

// capFeature represents a capability feature with an optional numeric value.
type capFeature struct {
	group  string
	token  string
	num    uint32
	hasNum bool
}

// capabilitiesFeatures flattens capabilities into deduplicated features.
func capabilitiesFeatures(caps []grpc.Capability) []capFeature {
	seen := make(map[capFeature]struct{})

	features := make([]capFeature, 0, len(caps))
	for _, c := range caps {
		features = appendCapabilityFeatures(features, seen, c)
	}

	return features
}

// capabilityFeatures turns c into its features.
func capabilityFeatures(c grpc.Capability) []capFeature {
	switch detail := c.Detail.(type) {
	case grpc.AssocTypeListCapability:
		features := make([]capFeature, 0, len(detail.AssocTypes))
		for _, assocType := range detail.AssocTypes {
			features = append(features, capFeature{
				group:  c.Type,
				token:  grpc.AssocTypeToken(assocType),
				num:    assocType,
				hasNum: true,
			})
		}

		return features

	case grpc.UnknownCapability:
		return []capFeature{{
			group:  c.Type,
			token:  grpc.UnknownTLVToken(detail.TLVType),
			num:    detail.TLVType,
			hasNum: true,
		}}
	}

	tokens := c.Strings()

	features := make([]capFeature, 0, len(tokens))
	for _, token := range tokens {
		features = append(features, capFeature{group: c.Type, token: token})
	}

	return features
}

// appendCapabilityFeatures adds c's features and its sub-capabilities.
func appendCapabilityFeatures(features []capFeature, seen map[capFeature]struct{}, c grpc.Capability) []capFeature {
	for _, f := range capabilityFeatures(c) {
		if _, ok := seen[f]; ok {
			continue
		}

		seen[f] = struct{}{}
		features = append(features, f)
	}

	if pst, ok := c.Detail.(grpc.PathSetupTypeCapability); ok {
		for _, sub := range pst.SubCapabilities {
			features = appendCapabilityFeatures(features, seen, sub)
		}
	}

	return features
}

type capabilitySets struct {
	common    []capFeature
	localOnly []capFeature
	peerOnly  []capFeature
}

func splitCapabilities(localCaps, peerCaps []grpc.Capability) capabilitySets {
	local := capabilitiesFeatures(localCaps)
	peer := capabilitiesFeatures(peerCaps)

	peerSet := make(map[capFeature]struct{}, len(peer))
	for _, f := range peer {
		peerSet[f] = struct{}{}
	}

	localSet := make(map[capFeature]struct{}, len(local))
	for _, f := range local {
		localSet[f] = struct{}{}
	}

	var sets capabilitySets

	for _, f := range local {
		if _, ok := peerSet[f]; ok {
			sets.common = append(sets.common, f)
		} else {
			sets.localOnly = append(sets.localOnly, f)
		}
	}

	for _, f := range peer {
		if _, ok := localSet[f]; !ok {
			sets.peerOnly = append(sets.peerOnly, f)
		}
	}

	return sets
}

// capGroupView is a capability group and its human-readable items.
type capGroupView struct {
	Capability string   `json:"capability"`
	Items      []string `json:"items"`
}

type capabilitiesView struct {
	Common    commonCapView  `json:"common"`
	LocalOnly []capGroupView `json:"localOnly"`
	PeerOnly  []capGroupView `json:"peerOnly"`

	// commonGroups holds grouped common capabilities for text output.
	commonGroups []capGroupView
}

func (c capabilitiesView) commonLines() []capDisplayLine {
	return capabilityLines(c.commonGroups)
}

// commonCapView exposes capabilities shared by both sides.
type commonCapView struct {
	Stateful             bool           `json:"stateful"`
	Update               bool           `json:"update"`
	Instantiation        bool           `json:"instantiation"`
	PathSetupTypes       []string       `json:"pathSetupTypes"`
	AssociationTypes     []uint32       `json:"associationTypes"`
	UnrecognizedTLVTypes []uint32       `json:"unrecognizedTlvTypes"`
	Other                []capGroupView `json:"other"`
}

func buildCapabilitiesView(localCaps, peerCaps []grpc.Capability) capabilitiesView {
	sets := splitCapabilities(localCaps, peerCaps)

	view := capabilitiesView{
		Common: commonCapView{
			PathSetupTypes:       []string{},
			AssociationTypes:     []uint32{},
			UnrecognizedTLVTypes: []uint32{},
		},
		LocalOnly:    capabilityGroups(sets.localOnly),
		PeerOnly:     capabilityGroups(sets.peerOnly),
		commonGroups: capabilityGroups(sets.common),
	}

	var otherFeatures []capFeature

	for _, f := range sets.common {
		if !applyCommonFeature(&view.Common, f) {
			otherFeatures = append(otherFeatures, f)
		}
	}

	view.Common.Other = capabilityGroups(otherFeatures)

	slices.Sort(view.Common.PathSetupTypes)
	slices.Sort(view.Common.AssociationTypes)
	slices.Sort(view.Common.UnrecognizedTLVTypes)

	return view
}

func applyStatefulFeature(common *commonCapView, token string) bool {
	switch token {
	case grpc.CapTokenStateful:
		common.Stateful = true
	case grpc.CapTokenUpdate:
		common.Update = true
	case grpc.CapTokenInstantiation:
		common.Instantiation = true
	default:
		return false
	}

	return true
}

// applyCommonFeature applies f to common and reports whether it was consumed.
func applyCommonFeature(common *commonCapView, f capFeature) bool {
	switch f.group {
	case capGroupStateful:
		return applyStatefulFeature(common, f.token)
	case capGroupPathSetupType:
		common.PathSetupTypes = append(common.PathSetupTypes, f.token)
		return true
	case capGroupAssocTypeList:
		if f.hasNum {
			common.AssociationTypes = append(common.AssociationTypes, f.num)
			return true
		}
	case capGroupUnknown:
		if f.hasNum {
			common.UnrecognizedTLVTypes = append(common.UnrecognizedTLVTypes, f.num)
			return true
		}
	}

	return false
}

// capabilityGroups groups features by capability.
func capabilityGroups(features []capFeature) []capGroupView {
	order := make([]string, 0)

	byGroup := make(map[string][]capFeature)
	for _, f := range features {
		if _, ok := byGroup[f.group]; !ok {
			order = append(order, f.group)
		}

		byGroup[f.group] = append(byGroup[f.group], f)
	}

	slices.SortFunc(order, func(a, b string) int {
		return cmp.Compare(capGroupOrderKey(a), capGroupOrderKey(b))
	})

	groups := make([]capGroupView, 0, len(order))
	for _, group := range order {
		groups = append(groups, capGroupView{Capability: group, Items: groupItems(group, byGroup[group])})
	}

	return groups
}

func groupItems(group string, features []capFeature) []string {
	switch group {
	case capGroupAssocTypeList:
		return sortedNumericLabels(features, assocTypeLabel)
	case capGroupUnknown:
		return sortedNumericLabels(features, unrecognizedTLVItem)
	default:
		items := make([]string, len(features))
		for i, f := range features {
			items[i] = f.token
		}

		return items
	}
}

func sortedNumericLabels(features []capFeature, label func(uint32) string) []string {
	ns := make([]uint32, 0, len(features))
	for _, f := range features {
		if f.hasNum {
			ns = append(ns, f.num)
		}
	}

	slices.Sort(ns)

	items := make([]string, len(ns))
	for i, n := range ns {
		items[i] = label(n)
	}

	return items
}

// capGroupLabels maps capability types to their display labels.
// STATEFUL is listed explicitly because it has two defining RFCs.
var capGroupLabels = map[string]string{
	capGroupStateful:          "STATEFUL-PCE-CAPABILITY [RFC8231/8281]",
	"SR":                      "SR-PCE-CAPABILITY [RFC8664]",
	capGroupSRv6:              "SRv6-PCE-CAPABILITY [RFC9603]",
	capGroupPathSetupType:     "PATH-SETUP-TYPE-CAPABILITY [RFC8408]",
	capGroupAssocTypeList:     assocTypeListLabel,
	capGroupLSPDBVersion:      "LSP-DB-VERSION [RFC8232]",
	capGroupMultipath:         "MULTIPATH-CAP [draft-ietf-pce-multipath]",
	capGroupVendorInformation: "VENDOR-INFORMATION [RFC7470]",
}

func capGroupLabel(group string) string {
	if label, ok := capGroupLabels[group]; ok {
		return label
	}

	return group
}

var capGroupOrder = map[string]int{
	capGroupVendorInformation: int(pcep.TLVVendorInformation),
	capGroupStateful:          int(pcep.TLVStatefulPCECapability),
	capGroupLSPDBVersion:      int(pcep.TLVLSPDBVersion),
	"SR":                      int(pcep.TLVSRPCECapability),
	capGroupSRv6:              int(pcep.TLVSRv6PCECapability),
	capGroupPathSetupType:     int(pcep.TLVPathSetupTypeCapability),
	capGroupAssocTypeList:     int(pcep.TLVAssocTypeList),
	capGroupMultipath:         int(pcep.TLVMultipathCap),
}

func capGroupOrderKey(group string) int {
	if key, ok := capGroupOrder[group]; ok {
		return key
	}

	return math.MaxInt
}

func assocTypeLabel(n uint32) string {
	if n > math.MaxUint16 {
		return fmt.Sprintf("%d (out-of-range for AssocType)", n)
	}

	return pcep.AssocType(n).StringWithReference()
}

// unrecognizedTLVItem names a TLV using the registry, or notes why it has no
// assigned name, for display under the "Unrecognized TLVs" group.
func unrecognizedTLVItem(tlvType uint32) string {
	if tlvType > math.MaxUint16 {
		return fmt.Sprintf("type=%d: out of TLV registry range, no RFC", tlvType)
	}

	t := pcep.TLVType(tlvType)
	name := t.Name()
	ref := t.Reference()

	switch {
	case name == "":
		return fmt.Sprintf("type=%d: unassigned/vendor-specific, no RFC", tlvType)
	case !ref.HasDocument():
		return fmt.Sprintf("type=%d: %s, no RFC", tlvType, ref)
	default:
		return fmt.Sprintf("type=%d: %s (%s)", tlvType, name, ref)
	}
}

// capDisplayLine represents a capability group and its optional items.
type capDisplayLine struct {
	Header string
	Items  []string
}

// capabilityLines renders capability groups as display lines.
func capabilityLines(groups []capGroupView) []capDisplayLine {
	lines := make([]capDisplayLine, 0, len(groups))
	for _, group := range groups {
		switch group.Capability {
		case capGroupAssocTypeList:
			lines = append(lines, capDisplayLine{Header: capGroupLabel(group.Capability), Items: group.Items})
		case capGroupUnknown:
			lines = append(lines, capDisplayLine{Header: "Unrecognized TLVs", Items: group.Items})
		default:
			lines = append(lines, capDisplayLine{Header: capGroupLabel(group.Capability) + ": " + strings.Join(group.Items, ", ")})
		}
	}

	return lines
}
