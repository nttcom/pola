// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

type LsTED struct {
	ID    int
	Nodes map[uint32]map[string]*LsNode // { ASN1: {"NodeID1": node1, "NodeID2": node2}, ASN2: {"NodeID3": node3, "NodeID4": node4}}
}

func (ted *LsTED) Update(tedElems []TEDElem) {
	for _, tedElem := range tedElems {
		tedElem.UpdateTED(ted)
	}
}

func (ted *LsTED) Print() {
	for _, nodes := range ted.Nodes {
		nodeCnt := 1
		for nodeID, node := range nodes {
			fmt.Printf("Node: %d\n", nodeCnt)
			fmt.Printf("  %s\n", nodeID)
			fmt.Printf("  Hostname: %s\n", node.Hostname)
			fmt.Printf("  ISIS Area ID: %s\n", node.IsisAreaID)
			fmt.Printf("  SRGB: %d - %d\n", node.SrgbBegin, node.SrgbEnd)
			fmt.Printf("  Prefixes:\n")
			for _, prefix := range node.Prefixes {
				fmt.Printf("    %s\n", prefix.Prefix.String())
				if prefix.SidIndex != 0 {
					fmt.Printf("      index: %d\n", prefix.SidIndex)
				}
			}
			fmt.Printf("  Links:\n")
			for _, link := range node.Links {
				fmt.Printf("    Local: %s Remote: %s\n", link.LocalIP.String(), link.RemoteIP.String())
				fmt.Printf("      RemoteNode: %s\n", link.RemoteNode.RouterID)
				fmt.Printf("      Metrics:\n")
				for _, metric := range link.Metrics {
					fmt.Printf("        %s: %d\n", metric.Type.String(), metric.Value)
				}
				fmt.Printf("      Adj-SID: %d\n", link.AdjSid)
				fmt.Printf("      SRv6 End.X SID:\n")
				fmt.Printf("        EndpointBehavior: %x\n", link.Srv6EndXSID.EndpointBehavior)
				fmt.Printf("        SIDs: %v\n", link.Srv6EndXSID.Sids)
				fmt.Printf("        SID Structure: Block: %d, Node: %d, Func: %d, Arg: %d\n",
					link.Srv6EndXSID.Srv6SIDStructure.LocalBlock,
					link.Srv6EndXSID.Srv6SIDStructure.LocalNode,
					link.Srv6EndXSID.Srv6SIDStructure.LocalFunc,
					link.Srv6EndXSID.Srv6SIDStructure.LocalArg)
			}
			fmt.Printf("  SRv6 SIDs:\n")
			for _, srv6SID := range node.SRv6SIDs {
				fmt.Printf("    SIDs: %v\n", srv6SID.Sids)
				fmt.Printf("    Block: %d, Node: %d, Func: %d, Arg: %d\n", srv6SID.SIDStructure.LocalBlock,
					srv6SID.SIDStructure.LocalNode, srv6SID.SIDStructure.LocalFunc, srv6SID.SIDStructure.LocalArg)
				fmt.Printf("    EndpointBehavior: %x, Flags: %d, Algorithm: %d\n", srv6SID.EndpointBehavior.Behavior,
					srv6SID.EndpointBehavior.Flags, srv6SID.EndpointBehavior.Algorithm)
				fmt.Printf("    MultiTopoIDs: %v\n", srv6SID.MultiTopoIDs)
			}

			nodeCnt++
			fmt.Printf("\n")
		}
	}
}

type TEDElem interface {
	UpdateTED(ted *LsTED)
}

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

func NewLsNode(asn uint32, nodeID string) *LsNode {
	return &LsNode{
		ASN:      asn,
		RouterID: nodeID,
	}
}

func (n *LsNode) NodeSegment() (Segment, error) {
	// for SR-MPLS Segment
	for _, prefix := range n.Prefixes {
		if prefix.SidIndex != 0 {
			sid := strconv.Itoa(int(n.SrgbBegin + prefix.SidIndex))
			seg, err := NewSegment(sid)
			if err != nil {
				return nil, err
			}
			return seg, nil
		}
	}
	// TODO: for SRv6 Segment

	return nil, errors.New("node doesn't have a Node SID")
}

func (n *LsNode) LoopbackAddr() (netip.Addr, error) {
	for _, prefix := range n.Prefixes {
		if prefix.SidIndex != 0 {
			return prefix.Prefix.Addr(), nil
		}
	}

	return netip.Addr{}, errors.New("node doesn't have a loopback address")
}

func (n *LsNode) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, n.ASN

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if node, ok := nodes[asn][n.RouterID]; ok {
		node.Hostname = n.Hostname
		node.IsisAreaID = n.IsisAreaID
		node.SrgbBegin = n.SrgbBegin
		node.SrgbEnd = n.SrgbEnd
	} else {
		nodes[asn][n.RouterID] = n
	}
}

func (n *LsNode) AddLink(link *LsLink) {
	n.Links = append(n.Links, link)
}

type LsLink struct {
	LocalNode   *LsNode      // Primary key, in MP_REACH_NLRI Attr
	RemoteNode  *LsNode      // Primary key, in MP_REACH_NLRI Attr
	LocalIP     netip.Addr   // In MP_REACH_NLRI Attr
	RemoteIP    netip.Addr   // In MP_REACH_NLRI Attr
	Metrics     []*Metric    // In BGP-LS Attr
	AdjSid      uint32       // In BGP-LS Attr
	Srv6EndXSID *Srv6EndXSID // In BGP-LS Attr
}

func NewLsLink(localNode *LsNode, remoteNode *LsNode) *LsLink {
	return &LsLink{
		LocalNode:  localNode,
		RemoteNode: remoteNode,
	}
}

func (l *LsLink) Metric(metricType MetricType) (uint32, error) {
	for _, metric := range l.Metrics {
		if metric.Type == metricType {
			return metric.Value, nil
		}
	}

	return 0, fmt.Errorf("metric %s not defined", metricType)
}

func (l *LsLink) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, l.LocalNode.ASN

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][l.LocalNode.RouterID]; !ok {
		nodes[asn][l.LocalNode.RouterID] = NewLsNode(l.LocalNode.ASN, l.LocalNode.RouterID)
	}

	if _, ok := nodes[l.RemoteNode.ASN][l.RemoteNode.RouterID]; !ok {
		nodes[l.RemoteNode.ASN][l.RemoteNode.RouterID] = NewLsNode(l.RemoteNode.ASN, l.RemoteNode.RouterID)
	}

	l.LocalNode, l.RemoteNode = nodes[asn][l.LocalNode.RouterID], nodes[l.RemoteNode.ASN][l.RemoteNode.RouterID]

	l.LocalNode.AddLink(l)
}

type LsPrefix struct {
	LocalNode *LsNode      // primary key, in MP_REACH_NLRI Attr
	Prefix    netip.Prefix // in MP_REACH_NLRI Attr
	SidIndex  uint32       // in BGP-LS Attr (only for Lo Address Prefix)
}

func NewLsPrefix(localNode *LsNode) *LsPrefix {
	return &LsPrefix{
		LocalNode: localNode,
	}
}

func (lp *LsPrefix) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, lp.LocalNode.ASN

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][lp.LocalNode.RouterID]; !ok {
		nodes[asn][lp.LocalNode.RouterID] = NewLsNode(lp.LocalNode.ASN, lp.LocalNode.RouterID)
	}

	localNode := nodes[asn][lp.LocalNode.RouterID]
	for _, pref := range localNode.Prefixes {
		if pref.Prefix.String() == lp.Prefix.String() {
			return
		}
	}

	localNode.Prefixes = append(localNode.Prefixes, lp)
}

type SIDStructure struct {
	LocalBlock uint8
	LocalNode  uint8
	LocalFunc  uint8
	LocalArg   uint8
}

type EndpointBehavior struct {
	Behavior  uint16
	Flags     uint8
	Algorithm uint8
}

type LsSrv6SID struct {
	LocalNode        *LsNode          // primary key, in MP_REACH_NLRI Attr
	Sids             []string         // in LsSrv6SID Attr
	EndpointBehavior EndpointBehavior // in BGP-LS Attr
	SIDStructure     SIDStructure     // in BGP-LS Attr
	MultiTopoIDs     []uint32         // in LsSrv6SID Attr
}

func NewLsSrv6SID(node *LsNode) *LsSrv6SID {
	return &LsSrv6SID{
		LocalNode: node,
	}
}

func (s *LsSrv6SID) UpdateTED(ted *LsTED) {
	nodes, asn := ted.Nodes, s.LocalNode.ASN

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][s.LocalNode.RouterID]; !ok {
		nodes[asn][s.LocalNode.RouterID] = NewLsNode(s.LocalNode.ASN, s.LocalNode.RouterID)
	}

	s.LocalNode = nodes[asn][s.LocalNode.RouterID]

	s.LocalNode.AddSrv6SID(s)
}

func (n *LsNode) AddSrv6SID(s *LsSrv6SID) {
	n.SRv6SIDs = append(n.SRv6SIDs, s)
}

type Metric struct {
	Type  MetricType
	Value uint32
}

func NewMetric(metricType MetricType, value uint32) *Metric {
	return &Metric{
		Type:  metricType,
		Value: value,
	}
}

type MetricType int

const (
	IGPMetric MetricType = iota
	TEMetric
	DelayMetric
	HopcountMetric
)

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

type Srv6EndXSID struct {
	EndpointBehavior uint16
	Sids             []string
	Srv6SIDStructure SIDStructure
}
