// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"fmt"
	"net/netip"
)

// SIDIndex is a lookup structure over the SIDs advertised by the TED.
type SIDIndex struct {
	mplsSIDs     map[uint32]struct{}       // prefix SIDs and adjacency SIDs
	srv6SIDs     map[netip.Addr]struct{}   // End / End.X SIDs, matched exactly
	srv6Locators map[netip.Prefix]struct{} // locator prefixes derived from SID structures
}

// MissingSegment identifies one segment the TED does not know about.
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
		mplsSIDs:     map[uint32]struct{}{},
		srv6SIDs:     map[netip.Addr]struct{}{},
		srv6Locators: map[netip.Prefix]struct{}{},
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
	for _, p := range node.Prefixes {
		if p != nil && p.SidIndex > FirstSIDIndex {
			idx.mplsSIDs[node.SrgbBegin+p.SidIndex] = struct{}{}
		}
	}
}

// addLinkSIDs registers adjacency SIDs and SRv6 End.X SIDs.
func (idx *SIDIndex) addLinkSIDs(node *LsNode) {
	for _, l := range node.Links {
		if l == nil {
			continue
		}
		if l.AdjSid != 0 {
			idx.mplsSIDs[l.AdjSid] = struct{}{}
		}
		if l.Srv6EndXSID != nil {
			idx.addSRv6(l.Srv6EndXSID.Sids, l.Srv6EndXSID.Srv6SIDStructure)
		}
	}
}

// addSRv6NodeSIDs registers the SRv6 End SIDs a node advertises.
func (idx *SIDIndex) addSRv6NodeSIDs(node *LsNode) {
	for _, s := range node.SRv6SIDs {
		if s != nil {
			idx.addSRv6(s.Sids, s.SIDStructure)
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

// HasUnknownSegmentType reports whether segmentList contains a segment with an unknown family.
func HasUnknownSegmentType(segmentList []Segment) bool {
	for _, seg := range segmentList {
		if seg == nil {
			continue
		}
		if seg.GetFamily() == SegmentUnknown {
			return true
		}
	}
	return false
}

// HasMixedSegmentTypes reports whether segmentList contains both SRv6 and SR-MPLS segments.
func HasMixedSegmentTypes(segmentList []Segment) bool {
	var hasSRv6, hasSRMPLS bool
	for _, seg := range segmentList {
		if seg == nil {
			continue
		}
		switch seg.GetFamily() {
		case SegmentSRv6Family:
			hasSRv6 = true
		case SegmentSRMPLSFamily:
			hasSRMPLS = true
		}
		if hasSRv6 && hasSRMPLS {
			return true
		}
	}
	return false
}
