package table

import (
	"fmt"
	"net"
)

type LsTed struct {
	Id    int
	Nodes map[uint32]map[string]*LsNode // { ASN1: {"NodeID1": node1, "NodeID2": node2}, ASN2: {"NodeID3": node3, "NodeID4": node4}}
}

func NewLsTed() {

}

func (ted LsTed) ShowTed() {
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
				for _, metric := range link.Metrics {
					fmt.Printf("      Metrics: %s %d\n", metric.Type.String(), metric.Value)
				}
				fmt.Printf("      Adj-SID: %d\n", link.AdjSid)
			}
			nodeCnt++
			fmt.Printf("\n")
		}

	}
}

type TedElem interface {
	UpdateTed(*LsTed)
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
	lsnode := &LsNode{
		Asn:      asn,
		RouterId: nodeId,
	}

	return lsnode
}

func (lsNode *LsNode) UpdateTed(ted *LsTed) {
	if _, ok := ted.Nodes[lsNode.Asn]; !ok {
		ted.Nodes[lsNode.Asn] = map[string]*LsNode{}
	}
	if node, ok := ted.Nodes[lsNode.Asn][lsNode.RouterId]; ok {
		node.Hostname = lsNode.Hostname
		node.IsisAreaId = lsNode.IsisAreaId
		node.SrgbBegin = lsNode.SrgbBegin
		node.SrgbEnd = lsNode.SrgbEnd
	} else {
		ted.Nodes[lsNode.Asn][lsNode.RouterId] = lsNode
	}

}

type LsLink struct {
	LocalNode  *LsNode   // primary key, in MP_REACH_NLRI Attr
	RemoteNode *LsNode   // primary key, in MP_REACH_NLRI Attr
	LocalIP    net.IP    // in MP_REACH_NLRI Attr
	RemoteIP   net.IP    // in MP_REACH_NLRI Attr
	Metrics    []*Metric // in BGP-LS Attr
	AdjSid     uint32    // in BGP-LS Attr
}

func NewLsLink(localNode *LsNode, remoteNode *LsNode) *LsLink {
	lsLink := &LsLink{
		LocalNode:  localNode,
		RemoteNode: remoteNode,
	}
	return lsLink
}

func (lsLink *LsLink) UpdateTed(ted *LsTed) {
	if _, ok := ted.Nodes[lsLink.LocalNode.Asn]; !ok {
		ted.Nodes[lsLink.LocalNode.Asn] = map[string]*LsNode{}
	}
	if _, ok := ted.Nodes[lsLink.LocalNode.Asn][lsLink.LocalNode.RouterId]; !ok {
		ted.Nodes[lsLink.LocalNode.Asn][lsLink.LocalNode.RouterId] = NewLsNode(lsLink.LocalNode.Asn, lsLink.LocalNode.RouterId)
	}
	if _, ok := ted.Nodes[lsLink.RemoteNode.Asn][lsLink.RemoteNode.RouterId]; !ok {
		ted.Nodes[lsLink.RemoteNode.Asn][lsLink.RemoteNode.RouterId] = NewLsNode(lsLink.RemoteNode.Asn, lsLink.RemoteNode.RouterId)
	}
	lsLink.LocalNode = ted.Nodes[lsLink.LocalNode.Asn][lsLink.LocalNode.RouterId]
	lsLink.RemoteNode = ted.Nodes[lsLink.RemoteNode.Asn][lsLink.RemoteNode.RouterId]
	ted.Nodes[lsLink.LocalNode.Asn][lsLink.LocalNode.RouterId].Links = append(ted.Nodes[lsLink.LocalNode.Asn][lsLink.LocalNode.RouterId].Links, lsLink)

}

type LsPrefixV4 struct {
	LocalNode *LsNode    // primary key, in MP_REACH_NLRI Attr
	Prefix    *net.IPNet // in MP_REACH_NLRI Attr
	SidIndex  uint32     // in BGP-LS Attr (only for Lo Address Prefix)
}

func NewLsPrefixV4(localNode *LsNode) *LsPrefixV4 {
	lsPrefixV4 := &LsPrefixV4{
		LocalNode: localNode,
	}
	return lsPrefixV4
}

func (lsPrefix *LsPrefixV4) UpdateTed(ted *LsTed) {
	if _, ok := ted.Nodes[lsPrefix.LocalNode.Asn]; !ok {
		ted.Nodes[lsPrefix.LocalNode.Asn] = map[string]*LsNode{}
	}
	if _, ok := ted.Nodes[lsPrefix.LocalNode.Asn][lsPrefix.LocalNode.RouterId]; !ok {
		ted.Nodes[lsPrefix.LocalNode.Asn][lsPrefix.LocalNode.RouterId] = NewLsNode(lsPrefix.LocalNode.Asn, lsPrefix.LocalNode.RouterId)
	}
	flag := true
	for _, pref := range ted.Nodes[lsPrefix.LocalNode.Asn][lsPrefix.LocalNode.RouterId].Prefixes {
		if pref.Prefix.String() == lsPrefix.Prefix.String() {
			flag = false
		}
	}
	if flag {
		lsPrefix.LocalNode = ted.Nodes[lsPrefix.LocalNode.Asn][lsPrefix.LocalNode.RouterId]
		ted.Nodes[lsPrefix.LocalNode.Asn][lsPrefix.LocalNode.RouterId].Prefixes = append(ted.Nodes[lsPrefix.LocalNode.Asn][lsPrefix.LocalNode.RouterId].Prefixes, lsPrefix)
	}

}

type Metric struct {
	Type  MetricType
	Value uint32
}

func NewMetric(metricType MetricType, value uint32) *Metric {
	metric := &Metric{
		Type:  metricType,
		Value: value,
	}
	return metric
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
