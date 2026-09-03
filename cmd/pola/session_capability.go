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
	"strconv"
	"strings"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/pkg/packet/pcep"
)

// Capability group identifiers, as reported by grpc.Capability.Type.
const (
	capGroupStateful          = "STATEFUL"
	capGroupSRv6              = "SRV6"
	capGroupPathSetupType     = "PATH_SETUP_TYPE"
	capGroupAssocTypeList     = "ASSOC_TYPE_LIST" //nolint:gosec // G101: capability group identifier, not a credential
	capGroupLSPDBVersion      = "LSP_DB_VERSION"
	capGroupMultipath         = "MULTIPATH"
	capGroupVendorInformation = "VENDOR_INFORMATION"
	capGroupUnknown           = "UNKNOWN"
)

// assocTypeListLabel is the display header for the ASSOC_TYPE_LIST group.
const assocTypeListLabel = "ASSOC-TYPE-LIST [RFC8697]"

// capFeature is a comparable capability token.
type capFeature struct {
	group string
	token string
}

// capabilitiesFeatures flattens capabilities into deduplicated
// (group, token) features, preserving first-seen order.
func capabilitiesFeatures(caps []grpc.Capability) []capFeature {
	seen := make(map[capFeature]struct{})

	features := make([]capFeature, 0, len(caps))
	for _, c := range caps {
		features = appendCapabilityFeatures(features, seen, c)
	}

	return features
}

// appendCapabilityFeatures adds c's tokens and recursively processes
// PATH-SETUP-TYPE-CAPABILITY sub-capabilities.
func appendCapabilityFeatures(features []capFeature, seen map[capFeature]struct{}, c grpc.Capability) []capFeature {
	for _, token := range c.Strings() {
		f := capFeature{group: c.Type, token: token}
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

func parseTokenUint32(token, prefix string) (uint32, bool) {
	if !strings.HasPrefix(token, prefix) {
		return 0, false
	}

	n, err := strconv.ParseUint(strings.TrimPrefix(token, prefix), 10, 32)
	if err != nil {
		return 0, false
	}

	return uint32(n), true
}

func applyStatefulFeature(common *commonCapView, token string) bool {
	switch token {
	case "Stateful":
		common.Stateful = true
	case "Update":
		common.Update = true
	case "Instantiation":
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
		if n, ok := parseTokenUint32(f.token, "AssocType:"); ok {
			common.AssociationTypes = append(common.AssociationTypes, n)
			return true
		}
	case capGroupUnknown:
		if n, ok := parseTokenUint32(f.token, "unknown_type_"); ok {
			common.UnrecognizedTLVTypes = append(common.UnrecognizedTLVTypes, n)
			return true
		}
	}

	return false
}

// capabilityGroups groups features by capability and formats their items
// according to the capability type.
func capabilityGroups(features []capFeature) []capGroupView {
	order := make([]string, 0)

	tokensByGroup := make(map[string][]string)
	for _, f := range features {
		if _, ok := tokensByGroup[f.group]; !ok {
			order = append(order, f.group)
		}

		tokensByGroup[f.group] = append(tokensByGroup[f.group], f.token)
	}

	slices.SortFunc(order, func(a, b string) int {
		return cmp.Compare(capGroupOrderKey(a), capGroupOrderKey(b))
	})

	groups := make([]capGroupView, 0, len(order))
	for _, group := range order {
		groups = append(groups, capGroupView{Capability: group, Items: groupItems(group, tokensByGroup[group])})
	}

	return groups
}

func groupItems(group string, tokens []string) []string {
	switch group {
	case capGroupAssocTypeList:
		return sortedUint32Labels(tokens, "AssocType:", assocTypeLabel)
	case capGroupUnknown:
		return sortedUint32Labels(tokens, "unknown_type_", unrecognizedTLVItem)
	default:
		return tokens
	}
}

// sortedUint32Labels sorts token values numerically and renders them with label.
func sortedUint32Labels(tokens []string, prefix string, label func(uint32) string) []string {
	ns := make([]uint32, 0, len(tokens))
	for _, token := range tokens {
		if n, ok := parseTokenUint32(token, prefix); ok {
			ns = append(ns, n)
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
