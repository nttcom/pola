// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// LsTED represents a Traffic Engineering Database built from BGP-LS data.
type LsTED struct {
	Nodes map[string]*LsNode // {"NodeID1": node1, "NodeID2": node2}
}

// Update updates the TED with the given elements for the specified ASN.
func (ted *LsTED) Update(tedElems []TEDElem, asn uint32) {
	for _, tedElem := range tedElems {
		tedElem.UpdateTED(ted, asn)
	}
}

// RouterIDIndex builds a loopback-address-to-router-ID index from the TED.
func (ted *LsTED) RouterIDIndex() map[netip.Addr]string {
	if ted == nil {
		return nil
	}

	index := make(map[netip.Addr]string, len(ted.Nodes))
	for _, node := range ted.Nodes {
		if node == nil {
			continue
		}

		for _, prefix := range node.Prefixes {
			if prefix.Prefix.Bits() == prefix.Prefix.Addr().BitLen() {
				index[prefix.Prefix.Addr()] = node.RouterID
			}
		}
	}

	return index
}

// AddressRouterIDIndex marks addresses advertised by multiple routers as ambiguous.
func (ted *LsTED) AddressRouterIDIndex() map[netip.Addr]string {
	if ted == nil {
		return nil
	}

	index := make(map[netip.Addr]string)

	for routerID, node := range ted.Nodes {
		if node == nil {
			continue
		}

		for _, prefix := range node.Prefixes {
			mergeSIDOwner(index, prefix.Prefix.Addr(), routerID)
		}
	}

	return index
}

// FindRouterIDByLoopback returns the router ID of the node whose loopback address matches addr.
func (ted *LsTED) FindRouterIDByLoopback(addr netip.Addr) (string, bool) {
	routerID, ok := ted.RouterIDIndex()[addr]
	return routerID, ok
}

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}

	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func (ew *errWriter) println(args ...any) {
	if ew.err != nil {
		return
	}

	_, ew.err = fmt.Fprintln(ew.w, args...)
}

// Print writes the TED to w, listing each node with its prefixes, links and SRv6 SIDs.
func (ted *LsTED) Print(w io.Writer) error {
	ew := &errWriter{w: w}

	if ted == nil || ted.Nodes == nil {
		ew.println("TED is empty")
		return ew.err
	}

	printNodes(ew, ted.Nodes)

	return ew.err
}

// printNodes iterates over each node in the map and prints its details.
func printNodes(ew *errWriter, nodes map[string]*LsNode) {
	nodeCnt := 1

	for nodeID, node := range nodes {
		if node == nil {
			continue
		}

		ew.printf("Node: %d\n", nodeCnt)
		printNodeBasic(ew, nodeID, node)
		printNodePrefixes(ew, node)
		printNodeLinks(ew, node)
		printNodeSRv6SIDs(ew, node)
		ew.println()

		nodeCnt++
	}
}

// printNodeBasic prints the basic information of a node.
func printNodeBasic(ew *errWriter, nodeID string, node *LsNode) {
	ew.printf("  %s\n", nodeID)
	ew.printf("  Hostname: %s\n", node.Hostname)
	ew.printf("  ISIS Area ID: %s\n", node.IsisAreaID)
	ew.printf("  SRGB: %d - %d\n", node.SrgbBegin, node.SrgbEnd)
}

// printNodePrefixes prints the prefixes associated with a node.
func printNodePrefixes(ew *errWriter, node *LsNode) {
	ew.println("  Prefixes:")

	if node.Prefixes == nil {
		return
	}

	for _, prefix := range node.Prefixes {
		if prefix == nil {
			continue
		}

		ew.printf("    %s\n", prefix.Prefix.String())

		if prefix.HasPrefixSID() {
			ew.printf("      index: %d\n", prefix.SidIndex)
		}
	}
}

// printNodeLinks prints the links associated with a node.
func printNodeLinks(ew *errWriter, node *LsNode) {
	ew.println("  Links:")

	if node.Links == nil {
		return
	}

	for _, link := range node.Links {
		if link == nil {
			continue
		}

		printLink(ew, link)
	}
}

const displayNone = "None"

// printLink prints the details of a single link to w.
func printLink(ew *errWriter, link *LsLink) {
	localIP := displayNone
	remoteIP := displayNone

	if link.Local.IPv4.IsValid() {
		localIP = link.Local.IPv4.String()
	} else if link.Local.IPv6.IsValid() {
		localIP = link.Local.IPv6.String()
	}

	if link.Remote.IPv4.IsValid() {
		remoteIP = link.Remote.IPv4.String()
	} else if link.Remote.IPv6.IsValid() {
		remoteIP = link.Remote.IPv6.String()
	}

	ew.printf("    Local: %s Remote: %s\n", localIP, remoteIP)

	remoteNodeID := displayNone
	if link.Remote.Node != nil {
		remoteNodeID = link.Remote.Node.RouterID
	}

	ew.printf("      RemoteNode: %s\n", remoteNodeID)

	ew.println("      Metrics:")

	if link.Metrics != nil {
		for _, metric := range link.Metrics {
			if metric == nil {
				continue
			}

			ew.printf("        %s: %d\n", metric.Type.DisplayString(), metric.Value)
		}
	}

	for _, adjSID := range link.AdjSids {
		ew.printf("      Adj-SID: %d\n", adjSID.Sid)
	}

	for _, endXSID := range link.Srv6EndXSIDs {
		if endXSID == nil {
			continue
		}

		ew.println("      SRv6 End.X SID:")
		ew.printf("        EndpointBehavior: %s, Flags: %d, Algorithm: %d, Weight: %d\n",
			BehaviorToString(endXSID.EndpointBehavior.Behavior),
			endXSID.EndpointBehavior.Flags,
			endXSID.EndpointBehavior.Algorithm,
			endXSID.Weight)
		ew.printf("        SIDs: %v\n", endXSID.Sids)
		printSIDStructure(ew, "        ", endXSID.Srv6SIDStructure)
	}
}

// printSIDStructure prints an SID Structure or "(not advertised)".
func printSIDStructure(ew *errWriter, indent string, s *SIDStructure) {
	if s == nil {
		ew.printf("%sSID Structure: (not advertised)\n", indent)
		return
	}

	ew.printf("%sSID Structure: Block: %d, Node: %d, Func: %d, Arg: %d\n",
		indent, s.LocalBlock, s.LocalNode, s.LocalFunc, s.LocalArg)
}

// printNodeSRv6SIDs prints the SRv6 SIDs associated with a node.
func printNodeSRv6SIDs(ew *errWriter, node *LsNode) {
	ew.println("  SRv6 SIDs:")

	if node.SRv6SIDs == nil {
		return
	}

	for _, srv6SID := range node.SRv6SIDs {
		if srv6SID == nil {
			continue
		}

		ew.printf("    SIDs: %v\n", srv6SID.Sids)

		if srv6SID.SIDStructure == nil {
			ew.println("    SID Structure: (not advertised)")
		} else {
			ew.printf("    Block: %d, Node: %d, Func: %d, Arg: %d\n",
				srv6SID.SIDStructure.LocalBlock,
				srv6SID.SIDStructure.LocalNode,
				srv6SID.SIDStructure.LocalFunc,
				srv6SID.SIDStructure.LocalArg)
		}

		ew.printf("    EndpointBehavior: %s, Flags: %d, Algorithm: %d\n",
			BehaviorToString(srv6SID.EndpointBehavior.Behavior),
			srv6SID.EndpointBehavior.Flags,
			srv6SID.EndpointBehavior.Algorithm)
		ew.printf("    MultiTopoIDs: %v\n", srv6SID.MultiTopoIDs)
	}
}

// TEDElem is an interface for elements that can update the TED.
type TEDElem interface {
	UpdateTED(ted *LsTED, cfgASN uint32)
}

// LsNode represents a node in the BGP-LS TED.
type LsNode struct {
	ASN        uint32
	RouterID   string
	IsisAreaID string
	Hostname   string
	SrgbBegin  uint32
	SrgbEnd    uint32
	Links      []*LsLink
	Prefixes   []*LsPrefix
	SRv6SIDs   []*LsSrv6SID
}

// NewLsNode creates a new BGP-LS node with the given ASN and router ID.
func NewLsNode(asn uint32, nodeID string) *LsNode {
	return &LsNode{
		ASN:      asn,
		RouterID: nodeID,
	}
}

// NodeSegment returns a Segment for the given Plane.
// The Plane must be fully specified; no implicit defaults are used.
func (n *LsNode) NodeSegment(plane Plane) (Segment, error) {
	if err := plane.Validate(); err != nil {
		return nil, fmt.Errorf("invalid plane: %w", err)
	}

	switch plane.DataPlane {
	case DPSRMPLS:
		return n.nodeSegmentSRMPLS(plane.Family)
	case DPSRv6:
		return n.nodeSegmentSRv6()
	default:
		return nil, errors.New("data plane must be specified")
	}
}

func (n *LsNode) nodeSegmentSRMPLS(af AddressFamily) (Segment, error) {
	for _, prefix := range n.Prefixes {
		if !prefix.HasPrefixSID() || FamilyOfAddr(prefix.Prefix.Addr()) != af {
			continue
		}

		if n.SrgbBegin == 0 {
			return nil, fmt.Errorf("cannot resolve prefix-SID index %d without an SRGB", prefix.SidIndex)
		}

		label, ok := srgbLabel(n, prefix.SidIndex)
		if !ok {
			return nil, fmt.Errorf("prefix-SID index %d is out of range for SRGB [%d, %d)", prefix.SidIndex, n.SrgbBegin, n.SrgbEnd)
		}

		return NewSegmentSRMPLS(label), nil
	}

	return nil, fmt.Errorf("node doesn't have a %s Prefix-SID", af)
}

func (n *LsNode) nodeSegmentSRv6() (Segment, error) {
	for _, srv6SID := range n.SRv6SIDs {
		if len(srv6SID.Sids) <= FirstSIDIndex {
			continue
		}

		sid, err := ParseSRv6SID(srv6SID.Sids[FirstSIDIndex])
		if err != nil {
			return nil, fmt.Errorf("SRv6 SID %q is invalid: %w", srv6SID.Sids[FirstSIDIndex], err)
		}

		return NewSegmentSRv6WithNodeInfo(sid, n)
	}

	return nil, errors.New("node doesn't have a Node SID")
}

// candidatePlanes lists the valid (family, data plane) combinations.
// The order is not significant; DefaultPlane requires exactly one to be viable.
var candidatePlanes = []Plane{
	{Family: AFIPv4, DataPlane: DPSRMPLS},
	{Family: AFIPv6, DataPlane: DPSRMPLS},
	{Family: AFIPv6, DataPlane: DPSRv6},
}

// DefaultPlane returns the node's unique viable Plane.
// An explicit plane is required when the node supports multiple planes.
func (n *LsNode) DefaultPlane() (Plane, error) {
	var candidates []Plane

	for _, p := range candidatePlanes {
		if _, err := n.NodeSegment(p); err == nil {
			candidates = append(candidates, p)
		}
	}

	switch len(candidates) {
	case 0:
		return Plane{}, errors.New("node doesn't have a Node SID")
	case 1:
		return candidates[0], nil
	default:
		return Plane{}, fmt.Errorf("node advertises multiple planes %v; an explicit plane is required", candidates)
	}
}

// DefaultLoopbackFamily returns the node's unique viable address family.
// An explicit family is required when the node has loopbacks in multiple families.
func (n *LsNode) DefaultLoopbackFamily() (AddressFamily, error) {
	var candidates []AddressFamily

	for _, af := range []AddressFamily{AFIPv4, AFIPv6} {
		if _, err := n.LoopbackAddr(af); err == nil {
			candidates = append(candidates, af)
		}
	}

	switch len(candidates) {
	case 0:
		return AFUnspecified, errors.New("node doesn't have a loopback address")
	case 1:
		return candidates[0], nil
	default:
		return AFUnspecified, fmt.Errorf("node has loopback addresses in multiple families %v; an explicit family is required", candidates)
	}
}

// LoopbackAddr returns the node's loopback address in the given address family.
// An explicit family is required; there is no implicit default.
func (n *LsNode) LoopbackAddr(af AddressFamily) (netip.Addr, error) {
	if !af.IsValid() {
		return netip.Addr{}, errors.New("address family must be specified")
	}

	for _, prefix := range n.Prefixes {
		addr := prefix.Prefix.Addr()
		if prefix.Prefix.Bits() != addr.BitLen() {
			continue
		}

		if FamilyOfAddr(addr) == af {
			return addr, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("node doesn't have a %s loopback address", af)
}

// HasLoopback reports whether the node has a loopback address in af.
func (n *LsNode) HasLoopback(af AddressFamily) bool {
	_, err := n.LoopbackAddr(af)
	return err == nil
}

// UpdateTED updates the TED with this node's information.
func (n *LsNode) UpdateTED(ted *LsTED, cfgASN uint32) {
	nodes := ted.Nodes

	if n.ASN != cfgASN {
		return
	}

	if node, ok := nodes[n.RouterID]; ok {
		node.Hostname = n.Hostname
		node.IsisAreaID = n.IsisAreaID
		node.SrgbBegin = n.SrgbBegin
		node.SrgbEnd = n.SrgbEnd
	} else {
		nodes[n.RouterID] = n
	}
}

// AddLink replaces an existing link with the same Key() instead of
// creating a duplicate.
func (n *LsNode) AddLink(link *LsLink) {
	key := link.Key()

	for i, existing := range n.Links {
		if existing != nil && existing.Key() == key {
			n.Links[i] = link
			return
		}
	}

	n.Links = append(n.Links, link)
}

// LinkEndpoint contains the node, addresses, and interface ID for one side of an LsLink.
// InterfaceID scopes a link-local IPv6 address; nil means not advertised and differs from 0.
type LinkEndpoint struct {
	Node        *LsNode
	InterfaceID *uint32
	IPv4        netip.Addr
	IPv6        netip.Addr
}

// Addr returns the endpoint's address in the given family, or the zero address if none was advertised.
func (e LinkEndpoint) Addr(af AddressFamily) netip.Addr {
	switch af {
	case AFIPv4:
		return e.IPv4
	case AFIPv6:
		return e.IPv6
	default:
		return netip.Addr{}
	}
}

// AdjSID is a link Adjacency-SID tagged with its address family.
// Family is AFUnspecified when GoBGP cannot distinguish IPv4 and IPv6 Adj-SIDs.
type AdjSID struct {
	Family AddressFamily
	Sid    uint32
}

// endpointKey defines the endpoint identity used by LinkKey.
// Interface ID takes precedence; otherwise the address is used.
// An endpoint with neither has no identity of its own.
type endpointKey struct {
	hasIfaceID bool
	ifaceID    uint32
	addr       netip.Addr
}

func newEndpointKey(e LinkEndpoint) endpointKey {
	if e.InterfaceID != nil {
		return endpointKey{hasIfaceID: true, ifaceID: *e.InterfaceID}
	}

	switch {
	case e.IPv4.IsValid():
		return endpointKey{addr: e.IPv4}
	case e.IPv6.IsValid():
		return endpointKey{addr: e.IPv6}
	default:
		return endpointKey{}
	}
}

// LinkKey identifies an LsLink across TED updates and re-advertisements.
type LinkKey struct {
	LocalRouterID  string
	RemoteRouterID string
	local          endpointKey
	remote         endpointKey
	multiTopoIDs   string
}

// LsLink represents a link in the BGP-LS TED.
type LsLink struct {
	Local, Remote LinkEndpoint
	Metrics       []*Metric
	AdjSids       []AdjSID
	Srv6EndXSIDs  []*Srv6EndXSID
	MultiTopoIDs  map[uint16]struct{}
}

// NewLsLink creates a new BGP-LS link between two nodes.
func NewLsLink(localNode, remoteNode *LsNode) *LsLink {
	return &LsLink{
		Local:  LinkEndpoint{Node: localNode},
		Remote: LinkEndpoint{Node: remoteNode},
	}
}

// Families reports the address families for which both endpoints have an address.
func (l *LsLink) Families() AddressFamilySet {
	var s AddressFamilySet

	if l.Local.IPv4.IsValid() && l.Remote.IPv4.IsValid() {
		s |= AddressFamilySetIPv4
	}

	if l.Local.IPv6.IsValid() && l.Remote.IPv6.IsValid() {
		s |= AddressFamilySetIPv6
	}

	return s
}

// mtIDFamily returns the address family for an IS-IS Multi-Topology ID.
func mtIDFamily(id uint16) AddressFamily {
	switch id {
	case 0: // Standard topology: IPv4 unicast (and IPv6 when topology 2 is absent).
		return AFIPv4
	case 2: // IPv6 routing topology.
		return AFIPv6
	default:
		return AFUnspecified
	}
}

// UsableForFamily reports whether l is usable for CSPF in address family af.
// Links with a Multi-Topology ID are usable only for the family it identifies.
func (l *LsLink) UsableForFamily(af AddressFamily) bool {
	if len(l.MultiTopoIDs) == 0 {
		return l.Families().Has(af)
	}

	for id := range l.MultiTopoIDs {
		if mtIDFamily(id) == af {
			return true
		}
	}

	return false
}

func multiTopoIDsKey(ids map[uint16]struct{}) string {
	if len(ids) == 0 {
		return ""
	}

	sorted := make([]int, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, int(id))
	}

	slices.Sort(sorted)

	parts := make([]string, len(sorted))
	for i, id := range sorted {
		parts[i] = strconv.Itoa(id)
	}

	return strings.Join(parts, ",")
}

// Key returns l's link identity for TED update dedup/merge.
func (l *LsLink) Key() LinkKey {
	return LinkKey{
		LocalRouterID:  nodeRouterID(l.Local.Node),
		RemoteRouterID: nodeRouterID(l.Remote.Node),
		local:          newEndpointKey(l.Local),
		remote:         newEndpointKey(l.Remote),
		multiTopoIDs:   multiTopoIDsKey(l.MultiTopoIDs),
	}
}

func nodeRouterID(n *LsNode) string {
	if n == nil {
		return ""
	}

	return n.RouterID
}

// Validate reports an error if a link-local IPv6 address lacks the
// interface ID required to scope it in NAI type 6 (RFC 8664/9603).
func (l *LsLink) Validate() error {
	if l.Local.IPv6.IsValid() && l.Local.IPv6.IsLinkLocalUnicast() && l.Local.InterfaceID == nil {
		return errors.New("local link-local IPv6 address requires an interface ID")
	}

	if l.Remote.IPv6.IsValid() && l.Remote.IPv6.IsLinkLocalUnicast() && l.Remote.InterfaceID == nil {
		return errors.New("remote link-local IPv6 address requires an interface ID")
	}

	return nil
}

// Metric returns the metric value of the given type for this link.
func (l *LsLink) Metric(metricType MetricType) (uint32, error) {
	// Hop count is implicit: each link counts as one hop.
	if metricType == HopcountMetric {
		return 1, nil
	}

	for _, metric := range l.Metrics {
		if metric.Type == metricType {
			return metric.Value, nil
		}
	}

	return 0, fmt.Errorf("metric %s not defined", metricType)
}

// UpdateTED updates the TED with this link's information.
func (l *LsLink) UpdateTED(ted *LsTED, cfgASN uint32) {
	nodes := ted.Nodes

	if l.Local.Node.ASN != cfgASN || l.Remote.Node.ASN != cfgASN {
		return
	}

	if _, ok := nodes[l.Local.Node.RouterID]; !ok {
		nodes[l.Local.Node.RouterID] = NewLsNode(l.Local.Node.ASN, l.Local.Node.RouterID)
	}

	if _, ok := nodes[l.Remote.Node.RouterID]; !ok {
		nodes[l.Remote.Node.RouterID] = NewLsNode(l.Remote.Node.ASN, l.Remote.Node.RouterID)
	}

	l.Local.Node, l.Remote.Node = nodes[l.Local.Node.RouterID], nodes[l.Remote.Node.RouterID]

	l.Local.Node.AddLink(l)
}

// LsPrefix represents a prefix in the BGP-LS TED.
type LsPrefix struct {
	LocalNode *LsNode
	Prefix    netip.Prefix
	SidIndex  uint32
	// HasSidIndex reports whether a Prefix-SID TLV is present.
	HasSidIndex bool
}

// HasPrefixSID reports whether this prefix has a Prefix-SID.
func (lp *LsPrefix) HasPrefixSID() bool {
	return lp != nil && lp.HasSidIndex
}

// NewLsPrefix creates a new BGP-LS prefix for the given node.
func NewLsPrefix(localNode *LsNode) *LsPrefix {
	return &LsPrefix{
		LocalNode: localNode,
	}
}

// UpdateTED updates the TED with this prefix's information.
func (lp *LsPrefix) UpdateTED(ted *LsTED, cfgASN uint32) {
	nodes := ted.Nodes

	if lp.LocalNode.ASN != cfgASN {
		return
	}

	if _, ok := nodes[lp.LocalNode.RouterID]; !ok {
		nodes[lp.LocalNode.RouterID] = NewLsNode(lp.LocalNode.ASN, lp.LocalNode.RouterID)
	}

	localNode := nodes[lp.LocalNode.RouterID]
	for _, pref := range localNode.Prefixes {
		if pref.Prefix == lp.Prefix {
			return
		}
	}

	localNode.Prefixes = append(localNode.Prefixes, lp)
}

// SIDStructure is the length split of an SRv6 SID (RFC 9603 §4.1).
//
// A nil value means no structure was advertised or declared; an all-zero
// value is a valid, explicitly declared structure.
type SIDStructure struct {
	LocalBlock uint8 `json:"localBlock"`
	LocalNode  uint8 `json:"localNode"`
	LocalFunc  uint8 `json:"localFunc"`
	LocalArg   uint8 `json:"localArg"`
}

// Validate checks that the structure fits within an SRv6 SID.
func (s *SIDStructure) Validate() error {
	if s == nil {
		return nil
	}

	if sum := int(s.LocalBlock) + int(s.LocalNode) + int(s.LocalFunc) + int(s.LocalArg); sum > SRv6SIDBitLength {
		return fmt.Errorf("SID structure sum %d exceeds %d bits", sum, SRv6SIDBitLength)
	}

	return nil
}

// Clone returns a copy of s.
func (s *SIDStructure) Clone() *SIDStructure {
	if s == nil {
		return nil
	}

	c := *s

	return &c
}

// Equal reports whether s and other represent the same SID structure.
// A nil value is distinct from a zero-valued structure.
func (s *SIDStructure) Equal(other *SIDStructure) bool {
	if s == nil || other == nil {
		return s == other
	}

	return *s == *other
}

// ParseSIDStructure parses a comma-separated SID structure
// (e.g. "32,16,0,80"). An empty string returns nil.
func ParseSIDStructure(s string) (*SIDStructure, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf("SID structure %q must have 4 comma-separated elements, got %d", s, len(parts))
	}

	var vals [4]uint8

	for i, p := range parts {
		v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid SID structure %q: %w", s, err)
		}

		vals[i] = uint8(v)
	}

	st := &SIDStructure{LocalBlock: vals[0], LocalNode: vals[1], LocalFunc: vals[2], LocalArg: vals[3]}
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SID structure %q: %w", s, err)
	}

	return st, nil
}

// EndpointBehavior represents the endpoint behavior attributes of an SRv6 SID.
//
// RFC 9514 defines the same Endpoint Behavior, Flags, and Algorithm fields for
// the SRv6 End.X SID and Endpoint Behavior TLVs. Flags are preserved as a raw
// octet because their semantics depend on the advertising protocol and TLV.
type EndpointBehavior struct {
	Behavior  uint16
	Flags     uint8
	Algorithm uint8
}

// LsSrv6SID represents an SRv6 SID in the BGP-LS TED.
type LsSrv6SID struct {
	LocalNode        *LsNode          // primary key, in MP_REACH_NLRI Attr
	Sids             []string         // in LsSrv6SID Attr
	EndpointBehavior EndpointBehavior // in BGP-LS Attr
	SIDStructure     *SIDStructure    // nil when the SID Structure TLV was not advertised
	MultiTopoIDs     []uint32         // in LsSrv6SID Attr
}

// NewLsSrv6SID creates a new SRv6 SID for the given node.
func NewLsSrv6SID(node *LsNode) *LsSrv6SID {
	return &LsSrv6SID{
		LocalNode: node,
	}
}

// UpdateTED updates the TED with this SRv6 SID's information.
func (s *LsSrv6SID) UpdateTED(ted *LsTED, cfgASN uint32) {
	nodes := ted.Nodes

	if s.LocalNode.ASN != cfgASN {
		return
	}

	if _, ok := nodes[s.LocalNode.RouterID]; !ok {
		nodes[s.LocalNode.RouterID] = NewLsNode(s.LocalNode.ASN, s.LocalNode.RouterID)
	}

	s.LocalNode = nodes[s.LocalNode.RouterID]

	s.LocalNode.AddSrv6SID(s)
}

// AddSrv6SID replaces a re-advertisement of the same SID.
// Entries without a SID have no dedup key and are always appended.
func (n *LsNode) AddSrv6SID(s *LsSrv6SID) {
	key, ok := srv6SIDKey(s)
	if !ok {
		n.SRv6SIDs = append(n.SRv6SIDs, s)
		return
	}

	for i, existing := range n.SRv6SIDs {
		if existingKey, ok := srv6SIDKey(existing); ok && existingKey == key {
			n.SRv6SIDs[i] = s
			return
		}
	}

	n.SRv6SIDs = append(n.SRv6SIDs, s)
}

// srv6SIDKey identifies an LsSrv6SID by its first SID value.
// It returns no key when the SID list is empty.
func srv6SIDKey(s *LsSrv6SID) (key string, ok bool) {
	if s == nil || len(s.Sids) <= FirstSIDIndex {
		return "", false
	}

	return s.Sids[FirstSIDIndex], true
}

// Metric represents a link metric with its type and value.
type Metric struct {
	Type  MetricType
	Value uint32
}

// NewMetric creates a new Metric with the given type and value.
func NewMetric(metricType MetricType, value uint32) *Metric {
	return &Metric{
		Type:  metricType,
		Value: value,
	}
}

// MetricType is an enumeration for link metric types.
type MetricType int

const (
	// UnspecifiedMetric is the zero value: no optimization metric applies (e.g. an
	// explicit SR Policy candidate path, which by definition has no objective function).
	UnspecifiedMetric MetricType = iota
	// IGPMetric is an IGP metric.
	IGPMetric
	// TEMetric is a TE metric.
	TEMetric
	// DelayMetric is a delay metric.
	DelayMetric
	// HopcountMetric is a hopcount metric.
	HopcountMetric
)

// IsValid reports whether m is a defined MetricType.
func (m MetricType) IsValid() bool {
	switch m {
	case UnspecifiedMetric, IGPMetric, TEMetric, DelayMetric, HopcountMetric:
		return true
	default:
		return false
	}
}

func (m MetricType) String() string {
	switch m {
	case IGPMetric:
		return "METRIC_TYPE_IGP"
	case TEMetric:
		return "METRIC_TYPE_TE"
	case DelayMetric:
		return "METRIC_TYPE_DELAY"
	case HopcountMetric:
		return "METRIC_TYPE_HOPCOUNT"
	default:
		return "METRIC_TYPE_UNSPECIFIED"
	}
}

// DisplayString returns the metric type as a lowercase string for display.
func (m MetricType) DisplayString() string {
	switch m {
	case IGPMetric:
		return "igp"
	case TEMetric:
		return "te"
	case DelayMetric:
		return "delay"
	case HopcountMetric:
		return "hopcount"
	default:
		return ""
	}
}

// MarshalJSON returns the metric type as a lowercase JSON string.
func (m MetricType) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.DisplayString())
}

// Srv6EndXSID represents an SRv6 End.X SID in the BGP-LS TED (RFC 9514 §4.1).
type Srv6EndXSID struct {
	EndpointBehavior EndpointBehavior
	Weight           uint8
	Sids             []string
	Srv6SIDStructure *SIDStructure // nil when the SID Structure TLV was not advertised
}
