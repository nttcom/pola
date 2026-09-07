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
	mplsSIDs     map[uint32]struct{}              // prefix SIDs and adjacency SIDs
	srv6SIDs     map[netip.Addr]struct{}          // End / End.X SIDs, matched exactly
	srv6Locators map[netip.Prefix]srv6LocatorInfo // locator prefixes derived from SID structures

	// path-aware: node SID → owning router ID
	mplsNodeSIDOwner map[uint32]string
	srv6NodeSIDOwner map[netip.Addr]string

	// path-aware: (owner router ID, adj SID) → next-hop router ID
	mplsAdjSIDNextHop map[adjKeyMPLS]string
	srv6AdjSIDNextHop map[adjKeySRv6]string
}

// srv6Structure is the [Locator-Block, Locator-Node, Function] bit-length
// split of an SRv6 SID.
type srv6Structure struct {
	blockBits int
	nodeBits  int
	funcBits  int
}

// locatorBits returns the node-identifying locator width (LBL + LNL).
func (s srv6Structure) locatorBits() int { return s.blockBits + s.nodeBits }

// stride returns the width of one micro-segment slot (LNL + FL).
func (s srv6Structure) stride() int { return s.nodeBits + s.funcBits }

// srv6LocatorInfo describes an SRv6 locator advertised into the TED.
// Conflicting advertisements make owner/structure explicitly unknown.
type srv6LocatorInfo struct {
	owner          string // ownerUnknown when owners conflict
	structure      srv6Structure
	structureKnown bool // false when SID Structures conflict
}

// MissingSegment identifies a rejected segment.
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
		srv6Locators:      map[netip.Prefix]srv6LocatorInfo{},
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
			mergeSIDOwner(idx.mplsNodeSIDOwner, label, node.RouterID)
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

	addrs := parseSRv6Addrs(l.Srv6EndXSID.Sids)
	idx.addSRv6(node.RouterID, addrs, l.Srv6EndXSID.Srv6SIDStructure)

	if l.RemoteNode == nil {
		return
	}

	for _, addr := range addrs {
		idx.srv6AdjSIDNextHop[adjKeySRv6{node.RouterID, addr}] = l.RemoteNode.RouterID
	}
}

// addSRv6NodeSIDs registers the SRv6 End SIDs a node advertises.
func (idx *SIDIndex) addSRv6NodeSIDs(node *LsNode) {
	for _, s := range node.SRv6SIDs {
		if s != nil {
			addrs := parseSRv6Addrs(s.Sids)
			idx.addSRv6(node.RouterID, addrs, s.SIDStructure)

			for _, addr := range addrs {
				mergeSIDOwner(idx.srv6NodeSIDOwner, addr, node.RouterID)
			}
		}
	}
}

// parseSRv6Addrs keeps only valid IPv6 addresses.
func parseSRv6Addrs(sids []string) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(sids))

	for _, sid := range sids {
		if addr, err := netip.ParseAddr(sid); err == nil && addr.Is6() {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

// Conflicting locator advertisements are merged as unknown/ambiguous
// rather than letting the latest advertisement win.
//
// A nil SID Structure means it was not advertised, which is distinct
// from an advertised zero-valued structure.
func (idx *SIDIndex) addSRv6(owner string, addrs []netip.Addr, st *SIDStructure) {
	for _, addr := range addrs {
		idx.srv6SIDs[addr] = struct{}{}
	}

	if st == nil {
		return
	}

	structure := srv6Structure{
		blockBits: int(st.LocalBlock),
		nodeBits:  int(st.LocalNode),
		funcBits:  int(st.LocalFunc),
	}
	locBits := structure.locatorBits()
	structureBits := locBits + structure.funcBits + int(st.LocalArg)

	if locBits <= 0 || structureBits > SRv6SIDBitLength {
		return
	}

	for _, addr := range addrs {
		p, err := addr.Prefix(locBits)
		if err != nil {
			continue
		}

		idx.mergeSRv6Locator(p, owner, structure)
	}
}

// mergeSRv6Locator merges a locator advertisement for prefix p.
// Owner and structure conflicts are tracked independently.
func (idx *SIDIndex) mergeSRv6Locator(p netip.Prefix, owner string, structure srv6Structure) {
	existing, ok := idx.srv6Locators[p]
	if !ok {
		idx.srv6Locators[p] = srv6LocatorInfo{owner: owner, structure: structure, structureKnown: true}
		return
	}

	if existing.owner != owner {
		existing.owner = ownerUnknown
	}

	existing.structureKnown = existing.structureKnown && existing.structure == structure

	idx.srv6Locators[p] = existing
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
	if _, ok := idx.srv6SIDs[s.Sid]; ok {
		return true
	}

	if !s.USid {
		return false
	}

	declaredLocBits := -1
	if len(s.Structure) == 4 {
		declaredLocBits = int(s.Structure[0]) + int(s.Structure[1])
	}

	_, found := idx.lookupSRv6Locator(s.Sid, declaredLocBits)

	return found
}

// maxBits < 0 means unrestricted; maxBits == 0 only matches /0 locators.
func (idx *SIDIndex) lookupSRv6Locator(addr netip.Addr, maxBits int) (srv6LocatorInfo, bool) {
	var (
		best  netip.Prefix
		info  srv6LocatorInfo
		found bool
	)

	for p, i := range idx.srv6Locators {
		if !p.Contains(addr) {
			continue
		}

		if maxBits >= 0 && p.Bits() > maxBits {
			continue
		}

		if !found || p.Bits() > best.Bits() {
			best, info, found = p, i, true
		}
	}

	return info, found
}

// NextHop returns the next-hop router ID after traversing seg from owner.
// Node SIDs resolve to their owning router; adjacency SIDs must belong to owner.
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

// Multiple owners for the same SID make ownership ambiguous.
func mergeSIDOwner[K comparable](owners map[K]string, sid K, owner string) {
	if existing, ok := owners[sid]; ok && existing != owner {
		owners[sid] = ownerUnknown
		return
	}

	owners[sid] = owner
}

func (idx *SIDIndex) nextHopMPLS(owner string, s SegmentSRMPLS) (string, error) {
	if next, ok := idx.mplsNodeSIDOwner[s.Sid]; ok {
		return next, nil
	}

	if owner == ownerUnknown {
		if _, exists := idx.mplsSIDs[s.Sid]; exists {
			return ownerUnknown, nil
		}

		return "", fmt.Errorf("SID %s not found in TED", s.SidString())
	}

	if next, ok := idx.mplsAdjSIDNextHop[adjKeyMPLS{owner, s.Sid}]; ok {
		return next, nil
	}

	if _, exists := idx.mplsSIDs[s.Sid]; exists {
		return "", fmt.Errorf("%s does not have adjacency SID %s", owner, s.SidString())
	}

	return "", fmt.Errorf("SID %s not found in TED", s.SidString())
}

func (idx *SIDIndex) nextHopSRv6(owner string, s SegmentSRv6) (string, error) {
	if next, ok := idx.srv6NodeSIDOwner[s.Sid]; ok {
		return next, nil
	}

	if owner == ownerUnknown {
		if idx.hasSRv6(s) {
			return ownerUnknown, nil
		}

		return "", fmt.Errorf("SID %s not found in TED", s.SidString())
	}

	if next, ok := idx.srv6AdjSIDNextHop[adjKeySRv6{owner, s.Sid}]; ok {
		return next, nil
	}

	// uSID containers are matched by their micro-segments against TED locators.
	if s.USid {
		if next, matched := idx.usidContainerOwner(s); matched {
			return next, nil
		}
	}

	if _, ok := idx.srv6SIDs[s.Sid]; ok {
		return "", fmt.Errorf("%s does not have adjacency SID %s", owner, s.SidString())
	}

	return "", fmt.Errorf("SID %s not found in TED", s.SidString())
}

// uSIDMicroSegmentPrefixes returns the locator prefix for each micro-segment.
// Each slot is stride() bits wide, but only its nodeBits identify the node.
func uSIDMicroSegmentPrefixes(sid netip.Addr, s srv6Structure) []netip.Prefix {
	if s.nodeBits <= 0 || s.blockBits < 0 || s.funcBits < 0 || s.locatorBits() > SRv6SIDBitLength {
		return nil
	}

	stride := s.stride()
	src := sid.As16()

	var prefixes []netip.Prefix

	for start := s.blockBits; start+stride <= SRv6SIDBitLength; start += stride {
		if usidBitsAllZero(&src, start, stride) {
			break
		}

		var dst [16]byte
		usidCopyBits(&dst, &src, 0, 0, s.blockBits)
		usidCopyBits(&dst, &src, start, s.blockBits, s.nodeBits)

		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(dst), s.locatorBits()))
	}

	return prefixes
}

func usidBitsAllZero(b *[16]byte, offset, length int) bool {
	for i := range length {
		if usidGetBit(b, offset+i) {
			return false
		}
	}

	return true
}

func usidCopyBits(dst, src *[16]byte, srcOffset, dstOffset, length int) {
	for i := range length {
		usidSetBit(dst, dstOffset+i, usidGetBit(src, srcOffset+i))
	}
}

func usidGetBit(b *[16]byte, pos int) bool {
	return b[pos/8]&(1<<(7-pos%8)) != 0
}

func usidSetBit(b *[16]byte, pos int, v bool) {
	mask := byte(1 << (7 - pos%8))
	if v {
		b[pos/8] |= mask
	} else {
		b[pos/8] &^= mask
	}
}

// usidContainerOwner resolves the owner of a uSID/C-SID container.
//
// matched is false when the SID has no compatible known locator.
// When matched is true, ownerUnknown means the container is known but its
// terminating owner cannot be determined unambiguously.
func (idx *SIDIndex) usidContainerOwner(s SegmentSRv6) (owner string, matched bool) {
	declaredLocBits := -1
	hasDeclared := len(s.Structure) == 4

	if hasDeclared {
		declaredLocBits = int(s.Structure[0]) + int(s.Structure[1])
	}

	locInfo, found := idx.lookupSRv6Locator(s.Sid, declaredLocBits)
	if !found {
		return ownerUnknown, false
	}

	structure := locInfo.structure

	switch {
	case hasDeclared:
		// The SID's declared structure takes precedence over the locator's.
		structure = srv6Structure{
			blockBits: int(s.Structure[0]),
			nodeBits:  int(s.Structure[1]),
			funcBits:  int(s.Structure[2]),
		}
	case !locInfo.structureKnown:
		return ownerUnknown, true
	}

	if structure.nodeBits <= 0 {
		return ownerUnknown, false
	}

	segments := uSIDMicroSegmentPrefixes(s.Sid, structure)
	if len(segments) == 0 {
		return ownerUnknown, true
	}

	resolved := ownerUnknown

	for _, seg := range segments {
		segInfo, ok := idx.srv6Locators[seg]
		if !ok {
			return ownerUnknown, true
		}

		if !hasDeclared && (!segInfo.structureKnown || segInfo.structure != structure) {
			return ownerUnknown, true
		}

		resolved = segInfo.owner
	}

	return resolved, true
}

// ValidateExplicitPath validates an explicit segment list from srcRouterID.
// Each segment must be a valid next hop from the current owner.
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
