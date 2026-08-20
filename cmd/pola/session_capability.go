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

// capFeature is one comparable capability token. Capabilities are compared
// at token granularity because a TLV may be present on both sides while
// individual flags or values differ.
type capFeature struct {
	group string
	token string
}

func capabilitiesFeatures(caps []grpc.Capability) []capFeature {
	features := make([]capFeature, 0, len(caps))
	for _, c := range caps {
		for _, token := range c.Strings() {
			features = append(features, capFeature{group: c.Type, token: token})
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

type capabilityView struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type capabilitiesView struct {
	Common    commonCapView    `json:"common"`
	LocalOnly []capabilityView `json:"localOnly"`
	PeerOnly  []capabilityView `json:"peerOnly"`

	// rawCommon retains the raw grouped tokens needed by the text renderer.
	rawCommon []capFeature
}

func (c capabilitiesView) commonLines() []capDisplayLine {
	return commonCapabilityLines(c.rawCommon)
}

// commonCapView exposes selected capability dimensions shared by both sides.
// It is not an exhaustive representation; other common capabilities remain
// visible in the text output.
type commonCapView struct {
	Stateful       bool     `json:"stateful"`
	Update         bool     `json:"update"`
	Instantiation  bool     `json:"instantiation"`
	PathSetupTypes []string `json:"pathSetupTypes"`

	// SRMSD and SRv6MSD are set only when both sides advertise the same value;
	// mismatches remain in localOnly/peerOnly.
	// SRv6MSD is currently always nil because the wire decoder and gRPC schema
	// do not carry the RFC 9603 MSD field yet.
	SRMSD                *uint32  `json:"srMsd,omitempty"`
	SRv6MSD              *uint32  `json:"srv6Msd,omitempty"`
	AssociationTypes     []uint32 `json:"associationTypes"`
	UnrecognizedTLVTypes []uint32 `json:"unrecognizedTlvTypes"`
}

func buildCapabilitiesView(localCaps, peerCaps []grpc.Capability) capabilitiesView {
	sets := splitCapabilities(localCaps, peerCaps)

	view := capabilitiesView{
		Common: commonCapView{
			PathSetupTypes:       []string{},
			AssociationTypes:     []uint32{},
			UnrecognizedTLVTypes: []uint32{},
		},
		LocalOnly: onlyCapabilities(sets.localOnly),
		PeerOnly:  onlyCapabilities(sets.peerOnly),
		rawCommon: sets.common,
	}

	for _, f := range sets.common {
		applyCommonFeature(&view.Common, f)
	}

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

func applyStatefulFeature(common *commonCapView, token string) {
	switch token {
	case "Stateful":
		common.Stateful = true
	case "Update":
		common.Update = true
	case "Instantiation":
		common.Instantiation = true
	}
}

func applyCommonFeature(common *commonCapView, f capFeature) {
	switch f.group {
	case "STATEFUL":
		applyStatefulFeature(common, f.token)
	case "PATH_SETUP_TYPE":
		common.PathSetupTypes = append(common.PathSetupTypes, f.token)
	case "SR":
		if n, ok := parseTokenUint32(f.token, "MSD="); ok {
			common.SRMSD = &n
		}
	case "ASSOC_TYPE_LIST":
		if n, ok := parseTokenUint32(f.token, "AssocType:"); ok {
			common.AssociationTypes = append(common.AssociationTypes, n)
		}
	case "UNKNOWN":
		if n, ok := parseTokenUint32(f.token, "unknown_type_"); ok {
			common.UnrecognizedTLVTypes = append(common.UnrecognizedTLVTypes, n)
		}
	}
}

func onlyTokens(features []capFeature) []string {
	seen := make(map[string]struct{}, len(features))
	out := make([]string, 0, len(features))
	for _, f := range features {
		token := strings.ToLower(f.token)
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	slices.Sort(out)
	return out
}

func onlyCapabilities(features []capFeature) []capabilityView {
	tokens := onlyTokens(features)
	views := make([]capabilityView, 0, len(tokens))
	for _, token := range tokens {
		views = append(views, capabilityViewFromToken(token))
	}
	return views
}

func capabilityViewFromToken(token string) capabilityView {
	if i := strings.IndexAny(token, "=:"); i >= 0 {
		return capabilityView{Name: token[:i], Value: token[i+1:]}
	}
	return capabilityView{Name: token}
}

// capGroupLabels maps capability types to their display labels.
// STATEFUL is listed explicitly because it has two defining RFCs.
var capGroupLabels = map[string]string{
	"STATEFUL":           "STATEFUL-PCE-CAPABILITY [RFC8231/8281]",
	"SR":                 "SR-PCE-CAPABILITY [RFC8664]",
	"SRV6":               "SRv6-PCE-CAPABILITY [RFC9603]",
	"PATH_SETUP_TYPE":    "PATH-SETUP-TYPE-CAPABILITY [RFC8408]",
	"ASSOC_TYPE_LIST":    "ASSOC-TYPE-LIST [RFC8697]",
	"LSP_DB_VERSION":     "LSP-DB-VERSION [RFC8232]",
	"MULTIPATH":          "MULTIPATH-CAP [draft-ietf-pce-multipath]",
	"VENDOR_INFORMATION": "VENDOR-INFORMATION [RFC7470]",
}

func capGroupLabel(group string) string {
	if label, ok := capGroupLabels[group]; ok {
		return label
	}
	return group
}

var capGroupOrder = map[string]int{
	"VENDOR_INFORMATION": int(pcep.TLVVendorInformation),
	"STATEFUL":           int(pcep.TLVStatefulPCECapability),
	"LSP_DB_VERSION":     int(pcep.TLVLSPDBVersion),
	"SR":                 int(pcep.TLVSRPCECapability),
	"SRV6":               int(pcep.TLVSRv6PCECapability),
	"PATH_SETUP_TYPE":    int(pcep.TLVPathSetupTypeCapability),
	"ASSOC_TYPE_LIST":    int(pcep.TLVAssocTypeList),
	"MULTIPATH":          int(pcep.TLVMultipathCap),
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
	return fmt.Sprintf("%d %s", n, pcep.AssocType(n).String())
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
	case ref == "vendor-specific":
		return fmt.Sprintf("type=%d: vendor-specific, no RFC", tlvType)
	default:
		return fmt.Sprintf("type=%d: %s (%s)", tlvType, name, ref)
	}
}

// capDisplayLine represents a capability group and its optional items.
type capDisplayLine struct {
	Header string
	Items  []string
}

// commonCapabilityLines renders capability groups as display lines.
// ASSOC_TYPE_LIST and UNKNOWN render as a heading with one item per entry.
func commonCapabilityLines(common []capFeature) []capDisplayLine {
	order := make([]string, 0)
	tokensByGroup := make(map[string][]string)
	for _, f := range common {
		if _, ok := tokensByGroup[f.group]; !ok {
			order = append(order, f.group)
		}
		tokensByGroup[f.group] = append(tokensByGroup[f.group], f.token)
	}
	slices.SortFunc(order, func(a, b string) int {
		return cmp.Compare(capGroupOrderKey(a), capGroupOrderKey(b))
	})

	var lines []capDisplayLine
	for _, group := range order {
		switch group {
		case "ASSOC_TYPE_LIST":
			items := make([]string, 0, len(tokensByGroup[group]))
			for _, token := range tokensByGroup[group] {
				if n, ok := parseTokenUint32(token, "AssocType:"); ok {
					items = append(items, assocTypeLabel(n))
				}
			}
			lines = append(lines, capDisplayLine{Header: capGroupLabel(group), Items: items})
		case "UNKNOWN":
			items := make([]string, 0, len(tokensByGroup[group]))
			for _, token := range tokensByGroup[group] {
				if n, ok := parseTokenUint32(token, "unknown_type_"); ok {
					items = append(items, unrecognizedTLVItem(n))
				}
			}
			lines = append(lines, capDisplayLine{Header: "Unrecognized TLVs", Items: items})
		default:
			lines = append(lines, capDisplayLine{Header: capGroupLabel(group) + ": " + strings.Join(tokensByGroup[group], ", ")})
		}
	}
	return lines
}
