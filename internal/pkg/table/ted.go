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

type LsTed struct {
	Id    int
	Nodes map[uint32]map[string]*LsNode // { ASN1: {"NodeID1": node1, "NodeID2": node2}, ASN2: {"NodeID3": node3, "NodeID4": node4}}
}

func (ted *LsTed) Update(tedElems []TedElem) {
	for _, tedElem := range tedElems {
		tedElem.UpdateTed(ted)
	}
}

func (ted *LsTed) Print() {
	for _, nodes := range ted.Nodes {
		nodeCnt := 1
		for nodeId, node := range nodes {
			fmt.Printf("Node: %d\n", nodeCnt)
			fmt.Printf("  %s\n", nodeId)
			fmt.Printf("  Hostname: %s\n", node.Hostname)
			fmt.Printf("  ISIS Area ID: %s\n", node.IsisAreaId)
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
				fmt.Printf("      RemoteNode: %s\n", link.RemoteNode.RouterId)
				fmt.Printf("      Metrics:\n")
				for _, metric := range link.Metrics {
					fmt.Printf("        %s: %d\n", metric.Type.String(), metric.Value)
				}
				fmt.Printf("      Adj-SID: %d\n", link.AdjSid)
			}
			nodeCnt++
			fmt.Printf("\n")
		}
	}
}

type TedElem interface {
	UpdateTed(ted *LsTed)
}

type LsNode struct {
	Asn        uint32 // primary key, in MP_REACH_NLRI Attr
	RouterId   string // primary key, in MP_REACH_NLRI Attr
	IsisAreaId string // in BGP-LS Attr
	Hostname   string // in BGP-LS Attr
	SrgbBegin  uint32 // in BGP-LS Attr
	SrgbEnd    uint32 // in BGP-LS Attr
	Links      []*LsLink
	Prefixes   []*LsPrefixV4
}

func NewLsNode(asn uint32, nodeId string) *LsNode {
	return &LsNode{
		Asn:      asn,
		RouterId: nodeId,
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

func (n *LsNode) UpdateTed(ted *LsTed) {
	nodes, asn := ted.Nodes, n.Asn

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if node, ok := nodes[asn][n.RouterId]; ok {
		node.Hostname = n.Hostname
		node.IsisAreaId = n.IsisAreaId
		node.SrgbBegin = n.SrgbBegin
		node.SrgbEnd = n.SrgbEnd
	} else {
		nodes[asn][n.RouterId] = n
	}
}

func (n *LsNode) AddLink(link *LsLink) {
	n.Links = append(n.Links, link)
}

type LsLink struct {
	LocalNode  *LsNode    // Primary key, in MP_REACH_NLRI Attr
	RemoteNode *LsNode    // Primary key, in MP_REACH_NLRI Attr
	LocalIP    netip.Addr // In MP_REACH_NLRI Attr
	RemoteIP   netip.Addr // In MP_REACH_NLRI Attr
	Metrics    []*Metric  // In BGP-LS Attr
	AdjSid     uint32     // In BGP-LS Attr
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

func (l *LsLink) UpdateTed(ted *LsTed) {
	nodes, asn := ted.Nodes, l.LocalNode.Asn

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][l.LocalNode.RouterId]; !ok {
		nodes[asn][l.LocalNode.RouterId] = NewLsNode(l.LocalNode.Asn, l.LocalNode.RouterId)
	}

	if _, ok := nodes[l.RemoteNode.Asn][l.RemoteNode.RouterId]; !ok {
		nodes[l.RemoteNode.Asn][l.RemoteNode.RouterId] = NewLsNode(l.RemoteNode.Asn, l.RemoteNode.RouterId)
	}

	l.LocalNode, l.RemoteNode = nodes[asn][l.LocalNode.RouterId], nodes[l.RemoteNode.Asn][l.RemoteNode.RouterId]

	l.LocalNode.AddLink(l)
}

type LsPrefixV4 struct {
	LocalNode *LsNode      // primary key, in MP_REACH_NLRI Attr
	Prefix    netip.Prefix // in MP_REACH_NLRI Attr
	SidIndex  uint32       // in BGP-LS Attr (only for Lo Address Prefix)
}

func NewLsPrefixV4(localNode *LsNode) *LsPrefixV4 {
	return &LsPrefixV4{
		LocalNode: localNode,
	}
}

func (lp *LsPrefixV4) UpdateTed(ted *LsTed) {
	nodes, asn := ted.Nodes, lp.LocalNode.Asn

	if _, ok := nodes[asn]; !ok {
		nodes[asn] = make(map[string]*LsNode)
	}

	if _, ok := nodes[asn][lp.LocalNode.RouterId]; !ok {
		nodes[asn][lp.LocalNode.RouterId] = NewLsNode(lp.LocalNode.Asn, lp.LocalNode.RouterId)
	}

	localNode := nodes[asn][lp.LocalNode.RouterId]
	for _, pref := range localNode.Prefixes {
		if pref.Prefix.String() == lp.Prefix.String() {
			return
		}
	}

	localNode.Prefixes = append(localNode.Prefixes, lp)
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
	IGP_METRIC MetricType = iota
	TE_METRIC
	DELAY_METRIC
	HOPCOUNT_METRIC
)

func (m MetricType) String() string {
	switch m {
	case IGP_METRIC:
		return "IGP"
	case TE_METRIC:
		return "TE"
	case DELAY_METRIC:
		return "DELAY"
	case HOPCOUNT_METRIC:
		return "HOPCOUNT"
	default:
		return "Unknown"
	}
}
