// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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

// Print outputs the TED in a structured way with low cyclomatic complexity.
func (ted *LsTED) Print() {
	if ted == nil || ted.Nodes == nil {
		fmt.Println("TED is empty")
		return
	}

	printNodes(ted.Nodes)
}

// printNodes iterates over each node in the map and prints its details.
func printNodes(nodes map[string]*LsNode) {
	nodeCnt := 1
	for nodeID, node := range nodes {
		if node == nil {
			continue
		}
		fmt.Printf("Node: %d\n", nodeCnt)
		printNodeBasic(nodeID, node)
		printNodePrefixes(node)
		printNodeLinks(node)
		printNodeSRv6SIDs(node)
		fmt.Println()
		nodeCnt++
	}
}

// printNodeBasic prints the basic information of a node.
func printNodeBasic(nodeID string, node *LsNode) {
	fmt.Printf("  %s\n", nodeID)
	fmt.Printf("  Hostname: %s\n", node.Hostname)
	fmt.Printf("  ISIS Area ID: %s\n", node.IsisAreaID)
	fmt.Printf("  SRGB: %d - %d\n", node.SrgbBegin, node.SrgbEnd)
}

// printNodePrefixes prints the prefixes associated with a node.
func printNodePrefixes(node *LsNode) {
	fmt.Println("  Prefixes:")
	if node.Prefixes == nil {
		return
	}
	for _, prefix := range node.Prefixes {
		if prefix == nil {
			continue
		}
		fmt.Printf("    %s\n", prefix.Prefix.String())
		if prefix.HasPrefixSID() {
			fmt.Printf("      index: %d\n", prefix.SidIndex)
		}
	}
}

// printNodeLinks prints the links associated with a node.
func printNodeLinks(node *LsNode) {
	fmt.Println("  Links:")
	if node.Links == nil {
		return
	}
	for _, link := range node.Links {
		if link == nil {
			continue
		}
		printLink(link)
	}
}

// printLink prints the details of a single link.
func printLink(link *LsLink) {
	localIP := "None"
	remoteIP := "None"
	if link.LocalIP.IsValid() {
		localIP = link.LocalIP.String()
	}
	if link.RemoteIP.IsValid() {
		remoteIP = link.RemoteIP.String()
	}
	fmt.Printf("    Local: %s Remote: %s\n", localIP, remoteIP)

	remoteNodeID := "None"
	if link.RemoteNode != nil {
		remoteNodeID = link.RemoteNode.RouterID
	}
	fmt.Printf("      RemoteNode: %s\n", remoteNodeID)

	fmt.Println("      Metrics:")
	if link.Metrics != nil {
		for _, metric := range link.Metrics {
			if metric == nil {
				continue
			}
			fmt.Printf("        %s: %d\n", metric.Type.DisplayString(), metric.Value)
		}
	}

	fmt.Printf("      Adj-SID: %d\n", link.AdjSid)

	if link.Srv6EndXSID != nil {
		fmt.Println("      SRv6 End.X SID:")
		fmt.Printf("        EndpointBehavior: %s\n", BehaviorToString(link.Srv6EndXSID.EndpointBehavior))
		fmt.Printf("        SIDs: %v\n", link.Srv6EndXSID.Sids)
		fmt.Printf("        SID Structure: Block: %d, Node: %d, Func: %d, Arg: %d\n",
			link.Srv6EndXSID.Srv6SIDStructure.LocalBlock,
			link.Srv6EndXSID.Srv6SIDStructure.LocalNode,
			link.Srv6EndXSID.Srv6SIDStructure.LocalFunc,
			link.Srv6EndXSID.Srv6SIDStructure.LocalArg)
	}
}

// printNodeSRv6SIDs prints the SRv6 SIDs associated with a node.
func printNodeSRv6SIDs(node *LsNode) {
	fmt.Println("  SRv6 SIDs:")
	if node.SRv6SIDs == nil {
		return
	}
	for _, srv6SID := range node.SRv6SIDs {
		if srv6SID == nil {
			continue
		}
		fmt.Printf("    SIDs: %v\n", srv6SID.Sids)
		fmt.Printf("    Block: %d, Node: %d, Func: %d, Arg: %d\n",
			srv6SID.SIDStructure.LocalBlock,
			srv6SID.SIDStructure.LocalNode,
			srv6SID.SIDStructure.LocalFunc,
			srv6SID.SIDStructure.LocalArg)
		fmt.Printf("    EndpointBehavior: %s, Flags: %d, Algorithm: %d\n",
			BehaviorToString(srv6SID.EndpointBehavior.Behavior),
			srv6SID.EndpointBehavior.Flags,
			srv6SID.EndpointBehavior.Algorithm)
		fmt.Printf("    MultiTopoIDs: %v\n", srv6SID.MultiTopoIDs)
	}
}

// TEDElem is an interface for elements that can update the TED.
type TEDElem interface {
	UpdateTED(ted *LsTED, cfgASN uint32)
}

// LsNode represents a node in the BGP-LS TED.
type LsNode struct {
	ASN        uint32 // primary key, in MP_REACH_NLRI Attr
	RouterID   string // primary key, in MP_REACH_NLRI Attr
	IsisAreaID string // in BGP-LS Attr
	Hostname   string // in BGP-LS Attr
	SrgbBegin  uint32 // in BGP-LS Attr
	SrgbEnd    uint32 // in BGP-LS Attr
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

// NodeSegment returns a Segment for this node (either SR-MPLS or SRv6).
func (n *LsNode) NodeSegment() (Segment, error) {
	// for SR-MPLS Segment
	for _, prefix := range n.Prefixes {
		if prefix.HasPrefixSID() {
			if n.SrgbBegin == 0 {
				return nil, fmt.Errorf("cannot resolve prefix-SID index %d without an SRGB", prefix.SidIndex)
			}
			label, ok := srgbLabel(n, prefix.SidIndex)
			if !ok {
				return nil, fmt.Errorf("prefix-SID index %d is out of range for SRGB [%d, %d)", prefix.SidIndex, n.SrgbBegin, n.SrgbEnd)
			}
			return NewSegmentSRMPLS(label), nil
		}
	}
	// for SRv6 Segment
	for _, srv6SID := range n.SRv6SIDs {
		if len(srv6SID.Sids) > FirstSIDIndex {
			addr, err := netip.ParseAddr(srv6SID.Sids[FirstSIDIndex])
			if err != nil {
				return nil, err
			}
			if !addr.Is6() || addr.Is4In6() {
				return nil, fmt.Errorf("SRv6 SID %q is not a valid IPv6 address", srv6SID.Sids[FirstSIDIndex])
			}
			return NewSegmentSRv6WithNodeInfo(addr, n)
		}
	}

	return nil, errors.New("node doesn't have a Node SID")
}

// LoopbackAddr returns the loopback address of the node.
func (n *LsNode) LoopbackAddr() (netip.Addr, error) {
	for _, prefix := range n.Prefixes {
		if prefix.Prefix.Addr().Is4() {
			if prefix.Prefix.Bits() == 32 {
				return prefix.Prefix.Addr(), nil
			}
		} else if prefix.Prefix.Addr().Is6() {
			if prefix.Prefix.Bits() == 128 {
				return prefix.Prefix.Addr(), nil
			}
		}
	}

	return netip.Addr{}, errors.New("node doesn't have a loopback address")
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

// AddLink adds a link to this node.
func (n *LsNode) AddLink(link *LsLink) {
	n.Links = append(n.Links, link)
}

// LsLink represents a link in the BGP-LS TED.
type LsLink struct {
	LocalNode   *LsNode      // Primary key, in MP_REACH_NLRI Attr
	RemoteNode  *LsNode      // Primary key, in MP_REACH_NLRI Attr
	LocalIP     netip.Addr   // In MP_REACH_NLRI Attr
	RemoteIP    netip.Addr   // In MP_REACH_NLRI Attr
	Metrics     []*Metric    // In BGP-LS Attr
	AdjSid      uint32       // In BGP-LS Attr
	Srv6EndXSID *Srv6EndXSID // In BGP-LS Attr
}

// NewLsLink creates a new BGP-LS link between two nodes.
func NewLsLink(localNode *LsNode, remoteNode *LsNode) *LsLink {
	return &LsLink{
		LocalNode:  localNode,
		RemoteNode: remoteNode,
	}
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

	if l.LocalNode.ASN != cfgASN || l.RemoteNode.ASN != cfgASN {
		return
	}

	if _, ok := nodes[l.LocalNode.RouterID]; !ok {
		nodes[l.LocalNode.RouterID] = NewLsNode(l.LocalNode.ASN, l.LocalNode.RouterID)
	}

	if _, ok := nodes[l.RemoteNode.RouterID]; !ok {
		nodes[l.RemoteNode.RouterID] = NewLsNode(l.RemoteNode.ASN, l.RemoteNode.RouterID)
	}

	l.LocalNode, l.RemoteNode = nodes[l.LocalNode.RouterID], nodes[l.RemoteNode.RouterID]

	l.LocalNode.AddLink(l)
}

// LsPrefix represents a prefix in the BGP-LS TED.
type LsPrefix struct {
	LocalNode *LsNode      // primary key, in MP_REACH_NLRI Attr
	Prefix    netip.Prefix // in MP_REACH_NLRI Attr
	SidIndex  uint32       // in BGP-LS Attr (only for Lo Address Prefix)
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
		if pref.Prefix.String() == lp.Prefix.String() {
			return
		}
	}

	localNode.Prefixes = append(localNode.Prefixes, lp)
}

// SIDStructure represents the structure breakdown of an SRv6 SID.
type SIDStructure struct {
	LocalBlock uint8
	LocalNode  uint8
	LocalFunc  uint8
	LocalArg   uint8
}

// EndpointBehavior represents the endpoint behavior attributes of an SRv6 SID.
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
	SIDStructure     SIDStructure     // in BGP-LS Attr
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

// AddSrv6SID adds an SRv6 SID to this node.
func (n *LsNode) AddSrv6SID(s *LsSrv6SID) {
	n.SRv6SIDs = append(n.SRv6SIDs, s)
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

// DisplayString renders the metric as a short lowercase token (e.g. "igp"), used
// for human-facing CLI output (unlike String()'s "METRIC_TYPE_..." form).
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

// MarshalJSON renders the metric as a short lowercase token (e.g. "igp"), consistent
// with the other lowercase enum-like fields on SRPolicy (e.g. State).
func (m MetricType) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.DisplayString())
}

// Srv6EndXSID represents an SRv6 End.X SID in the BGP-LS TED.
type Srv6EndXSID struct {
	EndpointBehavior uint16
	Sids             []string
	Srv6SIDStructure SIDStructure
}
