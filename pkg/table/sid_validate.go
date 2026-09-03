// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package table provides the in-memory Traffic Engineering Database (TED) and SR Policy tables.
package table

import (
	"errors"
	"fmt"
	"net/netip"
)

// adjKeyMPLS is the lookup key for an SR-MPLS adjacency SID owned by a specific node.
type adjKeyMPLS struct {
	owner string
	sid   uint32
}

// adjKeySRv6 is the lookup key for an SRv6 End.X SID owned by a specific node.
type adjKeySRv6 struct {
	owner string
	sid   netip.Addr
}

// MPLSLabelMax is the maximum 20-bit MPLS label value.
const MPLSLabelMax uint32 = 0xFFFFF

// SIDIndex is a lookup structure over the SIDs advertised by the TED.
type SIDIndex struct {
	mplsSIDs     map[uint32]struct{}       // prefix SIDs and adjacency SIDs
	srv6SIDs     map[netip.Addr]struct{}   // End / End.X SIDs, matched exactly
	srv6Locators map[netip.Prefix]struct{} // locator prefixes derived from SID structures

	// path-aware: node SID → owning router ID
	mplsNodeSIDOwner map[uint32]string
	srv6NodeSIDOwner map[netip.Addr]string

	// path-aware: (owner router ID, adj SID) → next-hop router ID
	mplsAdjSIDNextHop map[adjKeyMPLS]string
	srv6AdjSIDNextHop map[adjKeySRv6]string
}

// MissingSegment identifies one rejected segment by its position in the
// segment list and its SID.
type MissingSegment struct {
	Hop int // 1-origin position in the segment list
	SID string
}

func (m MissingSegment) String() string {
	return fmt.Sprintf("hop %d (%s)", m.Hop, m.SID)
}

// NewSIDIndex builds a SIDIndex from the TED.
func NewSIDIndex(ted *LsTED) *SIDIndex {
	idx := &SIDIndex{
		mplsSIDs:          map[uint32]struct{}{},
		srv6SIDs:          map[netip.Addr]struct{}{},
		srv6Locators:      map[netip.Prefix]struct{}{},
		mplsNodeSIDOwner:  map[uint32]string{},
		srv6NodeSIDOwner:  map[netip.Addr]string{},
		mplsAdjSIDNextHop: map[adjKeyMPLS]string{},
		srv6AdjSIDNextHop: map[adjKeySRv6]string{},
	}
	if ted == nil {
		return idx
	}
	for _, node := range ted.Nodes {
		if node == nil {
			continue
		}
		idx.addNodePrefixSIDs(node)
		idx.addLinkSIDs(node)
		idx.addSRv6NodeSIDs(node)
	}
	return idx
}

// addNodePrefixSIDs registers SR-MPLS prefix SIDs.
func (idx *SIDIndex) addNodePrefixSIDs(node *LsNode) {
	// Without an SRGB, a Prefix-SID index cannot be converted to a label.
	if node.SrgbBegin == 0 {
		return
	}
	for _, p := range node.Prefixes {
		if !p.HasPrefixSID() {
			continue
		}
		if label, ok := srgbLabel(node, p.SidIndex); ok {
			idx.mplsSIDs[label] = struct{}{}
			idx.mplsNodeSIDOwner[label] = node.RouterID
		}
	}
}

// srgbLabel converts a Prefix-SID index to an MPLS label within the SRGB.
// It returns false if the resulting label is out of range.
func srgbLabel(node *LsNode, sidIndex uint32) (uint32, bool) {
	label := uint64(node.SrgbBegin) + uint64(sidIndex)
	if label > uint64(MPLSLabelMax) {
		return 0, false
	}
	if node.SrgbEnd > node.SrgbBegin && label >= uint64(node.SrgbEnd) {
		return 0, false
	}
	return uint32(label), true
}

// addLinkSIDs registers adjacency SIDs and SRv6 End.X SIDs.
func (idx *SIDIndex) addLinkSIDs(node *LsNode) {
	for _, l := range node.Links {
		if l == nil {
			continue
		}
		idx.addAdjSID(node, l)
		idx.addEndXSID(node, l)
	}
}

// addAdjSID registers a link's SR-MPLS adjacency SID and its next hop.
func (idx *SIDIndex) addAdjSID(node *LsNode, l *LsLink) {
	if l.AdjSid == 0 {
		return
	}
	idx.mplsSIDs[l.AdjSid] = struct{}{}
	if l.RemoteNode != nil {
		idx.mplsAdjSIDNextHop[adjKeyMPLS{node.RouterID, l.AdjSid}] = l.RemoteNode.RouterID
	}
}

// addEndXSID registers a link's SRv6 End.X SIDs and their next hop.
func (idx *SIDIndex) addEndXSID(node *LsNode, l *LsLink) {
	if l.Srv6EndXSID == nil {
		return
	}
	idx.addSRv6(l.Srv6EndXSID.Sids, l.Srv6EndXSID.Srv6SIDStructure)
	if l.RemoteNode == nil {
		return
	}
	for _, s := range l.Srv6EndXSID.Sids {
		if addr, err := netip.ParseAddr(s); err == nil {
			idx.srv6AdjSIDNextHop[adjKeySRv6{node.RouterID, addr}] = l.RemoteNode.RouterID
		}
	}
}

// addSRv6NodeSIDs registers the SRv6 End SIDs a node advertises.
func (idx *SIDIndex) addSRv6NodeSIDs(node *LsNode) {
	for _, s := range node.SRv6SIDs {
		if s != nil {
			idx.addSRv6(s.Sids, s.SIDStructure)
			for _, sidStr := range s.Sids {
				if addr, err := netip.ParseAddr(sidStr); err == nil {
					idx.srv6NodeSIDOwner[addr] = node.RouterID
				}
			}
		}
	}
}

// addSRv6 registers exact SIDs and their locator prefixes.
func (idx *SIDIndex) addSRv6(sids []string, st SIDStructure) {
	locBits := int(st.LocalBlock) + int(st.LocalNode)
	for _, s := range sids {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is6() {
			continue
		}
		idx.srv6SIDs[addr] = struct{}{}
		if locBits <= 0 || locBits > SRv6SIDBitLength {
			continue
		}
		if p, err := addr.Prefix(locBits); err == nil {
			idx.srv6Locators[p] = struct{}{}
		}
	}
}

// Has reports whether the TED knows about seg.
func (idx *SIDIndex) Has(seg Segment) bool {
	switch s := seg.(type) {
	case SegmentSRMPLS:
		_, ok := idx.mplsSIDs[s.Sid]
		return ok
	case SegmentSRv6:
		return idx.hasSRv6(s)
	}
	return false
}

func (idx *SIDIndex) hasSRv6(s SegmentSRv6) bool {
	// End / End.X SIDs are advertised verbatim, so prefer the exact match.
	if _, ok := idx.srv6SIDs[s.Sid]; ok {
		return true
	}
	if !s.USid {
		return false
	}
	// Fall back to locator containment for uSID containers.
	locBits := 0
	if len(s.Structure) == 4 {
		locBits = int(s.Structure[0]) + int(s.Structure[1])
	}
	for loc := range idx.srv6Locators {
		if !loc.Contains(s.Sid) {
			continue
		}
		// Reject a request whose declared locator is shorter than the TED's.
		if locBits > 0 && loc.Bits() > locBits {
			continue
		}
		return true
	}
	return false
}

// NextHop returns the next-hop router ID after traversing seg from owner.
// For node SIDs it returns the SID's owning router ID (valid from any owner).
// For adjacency SIDs it verifies the SID is local to owner, then returns the remote router ID.
// Returns an error if the SID is unknown or does not belong to owner.
func (idx *SIDIndex) NextHop(owner string, seg Segment) (string, error) {
	switch s := seg.(type) {
	case SegmentSRMPLS:
		return idx.nextHopMPLS(owner, s)
	case SegmentSRv6:
		return idx.nextHopSRv6(owner, s)
	default:
		return "", errors.New("unknown segment family")
	}
}

// ownerUnknown indicates that the current router is unknown.
const ownerUnknown = ""

func (idx *SIDIndex) nextHopMPLS(owner string, s SegmentSRMPLS) (string, error) {
	// Node SID (prefix SID)?
	if next, ok := idx.mplsNodeSIDOwner[s.Sid]; ok {
		return next, nil
	}
	if owner == ownerUnknown {
		if _, exists := idx.mplsSIDs[s.Sid]; exists {
			return ownerUnknown, nil
		}
		return "", fmt.Errorf("SID %s not found in TED", s.SidString())
	}
	// Adjacency SID — must be on owner.
	if next, ok := idx.mplsAdjSIDNextHop[adjKeyMPLS{owner, s.Sid}]; ok {
		return next, nil
	}
	if _, exists := idx.mplsSIDs[s.Sid]; exists {
		return "", fmt.Errorf("%s does not have adjacency SID %s", owner, s.SidString())
	}
	return "", fmt.Errorf("SID %s not found in TED", s.SidString())
}

func (idx *SIDIndex) nextHopSRv6(owner string, s SegmentSRv6) (string, error) {
	// Node SID (End SID)?
	if next, ok := idx.srv6NodeSIDOwner[s.Sid]; ok {
		return next, nil
	}
	if owner == ownerUnknown {
		if idx.hasSRv6(s) {
			return ownerUnknown, nil
		}
		return "", fmt.Errorf("SID %s not found in TED", s.SidString())
	}
	// Adjacency SID (End.X) — must be on owner.
	if next, ok := idx.srv6AdjSIDNextHop[adjKeySRv6{owner, s.Sid}]; ok {
		return next, nil
	}
	if idx.hasSRv6(s) {
		return "", fmt.Errorf("%s does not have adjacency SID %s", owner, s.SidString())
	}
	return "", fmt.Errorf("SID %s not found in TED", s.SidString())
}

// ValidateExplicitPath performs path-aware SID validation on an explicit segment list.
// Starting from srcRouterID, it verifies each SID via SIDIndex.NextHop:
//   - Node SIDs are valid from any owner; the owner advances to that node.
//   - Adjacency SIDs must be local to the current owner; owner advances to the link's remote node.
func ValidateExplicitPath(ted *LsTED, srcRouterID string, segmentList []Segment) error {
	if ted == nil {
		return errors.New("TED is nil")
	}
	if srcRouterID == "" {
		return errors.New("source router ID is empty")
	}
	if _, ok := ted.Nodes[srcRouterID]; !ok {
		return fmt.Errorf("source router ID %s not found in TED", srcRouterID)
	}

	if len(segmentList) == 0 {
		return nil
	}
	idx := NewSIDIndex(ted)
	owner := srcRouterID
	for i, seg := range segmentList {
		if seg == nil {
			return fmt.Errorf("hop %d: nil segment", i+1)
		}
		next, err := idx.NextHop(owner, seg)
		if err != nil {
			return fmt.Errorf("hop %d (%s): %w", i+1, seg.SidString(), err)
		}
		owner = next
	}
	return nil
}

// MissingSegments reports the segments not found in the TED.
func MissingSegments(ted *LsTED, segmentList []Segment) []MissingSegment {
	idx := NewSIDIndex(ted)
	var missing []MissingSegment
	for i, seg := range segmentList {
		if seg == nil || !idx.Has(seg) {
			sid := "<nil>"
			if seg != nil {
				sid = seg.SidString()
			}
			missing = append(missing, MissingSegment{Hop: i + 1, SID: sid})
		}
	}
	return missing
}

// OutOfRangeSRMPLSLabels reports SR-MPLS segments with labels outside the 20-bit range.
func OutOfRangeSRMPLSLabels(segmentList []Segment) []MissingSegment {
	var invalid []MissingSegment
	for i, segment := range segmentList {
		seg, ok := segment.(SegmentSRMPLS)
		if !ok || seg.Sid <= MPLSLabelMax {
			continue
		}
		invalid = append(invalid, MissingSegment{Hop: i + 1, SID: seg.SidString()})
	}
	return invalid
}

// HasUnknownSegmentType reports whether segmentList contains a segment with an unknown family.
func HasUnknownSegmentType(segmentList []Segment) bool {
	for _, segment := range segmentList {
		if segment == nil {
			continue
		}
		if segmentFamily(segment) == SegmentUnknown {
			return true
		}
	}
	return false
}

// HasMixedSegmentTypes reports whether segmentList contains both SRv6 and SR-MPLS segments.
func HasMixedSegmentTypes(segmentList []Segment) bool {
	var family SegmentFamily

	for _, segment := range segmentList {
		if segment == nil {
			continue
		}

		current := segmentFamily(segment)
		if current == SegmentUnknown {
			continue
		}

		if family == SegmentUnknown {
			family = current
			continue
		}

		if family != current {
			return true
		}
	}

	return false
}
