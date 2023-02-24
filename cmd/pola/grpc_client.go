// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/internal/pkg/table"
)

func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second)
}

func getSessionAddrList(client pb.PceServiceClient) ([]netip.Addr, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetPeerAddrList(ctx, &empty.Empty{})
	if err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	for _, addr := range ret.GetPeerAddrs() {
		a, _ := netip.AddrFromSlice(addr)
		addrs = append(addrs, a)
	}

	return addrs, nil
}

func getSRPolicyList(client pb.PceServiceClient) (map[netip.Addr][]table.SRPolicy, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetSRPolicyList(ctx, &empty.Empty{})
	if err != nil {
		return nil, err
	}

	policies := make(map[netip.Addr][]table.SRPolicy, len(ret.GetSRPolicies()))

	for _, p := range ret.GetSRPolicies() {
		peerAddr, _ := netip.AddrFromSlice(p.PcepSessionAddr)
		srcAddr, _ := netip.AddrFromSlice(p.SrcAddr)
		dstAddr, _ := netip.AddrFromSlice(p.DstAddr)
		var segmentList []table.Segment
		for _, s := range p.SegmentList {
			seg, err := table.NewSegment(s.Sid)
			if err != nil {
				return nil, err
			}
			segmentList = append(segmentList, seg)
		}

		policies[peerAddr] = append(policies[peerAddr], table.SRPolicy{
			Name:        p.PolicyName,
			SegmentList: segmentList,
			SrcAddr:     srcAddr,
			DstAddr:     dstAddr,
			Color:       p.Color,
			Preference:  p.Preference,
		})
	}

	return policies, nil
}

func createSRPolicy(client pb.PceServiceClient, input *pb.CreateSRPolicyInput) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.CreateSRPolicy(ctx, input)
	return err
}

func createSRPolicyWithoutLinkState(client pb.PceServiceClient, input *pb.CreateSRPolicyInput) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.CreateSRPolicyWithoutLinkState(ctx, input)
	return err
}

func getTed(client pb.PceServiceClient) (*table.LsTed, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetTed(ctx, &empty.Empty{})
	if err != nil {
		return nil, err
	}

	if !ret.GetEnable() {
		return nil, errors.New("ted is disabled")
	}

	ted := &table.LsTed{
		Id:    1,
		Nodes: make(map[uint32]map[string]*table.LsNode),
	}

	initializeLsNodes(ted, ret.GetLsNodes())

	for _, node := range ret.GetLsNodes() {
		if err := addLsNode(ted, node); err != nil {
			return nil, err
		}
	}

	return ted, nil
}

// initializeLsNodes initializes LsNodes in the LsTed table using the given array of nodes
func initializeLsNodes(ted *table.LsTed, nodes []*pb.LsNode) {
	for _, node := range nodes {
		lsNode := table.NewLsNode(node.GetAsn(), node.GetRouterId())
		lsNode.Hostname = node.GetHostname()
		lsNode.IsisAreaId = node.GetIsisAreaId()
		lsNode.SrgbBegin = node.GetSrgbBegin()
		lsNode.SrgbEnd = node.GetSrgbEnd()

		if _, ok := ted.Nodes[lsNode.Asn]; !ok {
			ted.Nodes[lsNode.Asn] = map[string]*table.LsNode{}
		}
		ted.Nodes[lsNode.Asn][lsNode.RouterId] = lsNode
	}
}

func addLsNode(ted *table.LsTed, node *pb.LsNode) error {
	for _, link := range node.GetLsLinks() {
		localNode := ted.Nodes[link.LocalAsn][link.LocalRouterId]
		remoteNode := ted.Nodes[link.RemoteAsn][link.RemoteRouterId]
		lsLink, err := createLsLink(localNode, remoteNode, link)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetAsn()][node.GetRouterId()].Links = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].Links, lsLink)
	}

	for _, prefix := range node.LsPrefixes {
		lsPrefix, err := createLsPrefix(ted.Nodes[node.GetAsn()][node.GetRouterId()], prefix)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes, lsPrefix)
	}

	return nil
}

func createLsPrefix(lsNode *table.LsNode, prefix *pb.LsPrefix) (*table.LsPrefixV4, error) {
	lsPrefix := table.NewLsPrefixV4(lsNode)
	var err error
	lsPrefix.Prefix, err = netip.ParsePrefix(prefix.GetPrefix())
	if err != nil {
		return nil, err
	}
	lsPrefix.SidIndex = prefix.GetSidIndex()

	return lsPrefix, nil
}

func createLsLink(localNode, remoteNode *table.LsNode, link *pb.LsLink) (*table.LsLink, error) {
	lsLink := &table.LsLink{
		LocalNode:  localNode,
		RemoteNode: remoteNode,
		AdjSid:     link.GetAdjSid(),
	}
	var err error
	lsLink.LocalIP, err = netip.ParseAddr(link.GetLocalIp())
	if err != nil {
		return nil, err
	}
	lsLink.RemoteIP, err = netip.ParseAddr(link.GetRemoteIp())
	if err != nil {
		return nil, err
	}
	for _, metricInfo := range link.GetMetrics() {
		metric, err := createMetric(metricInfo)
		if err != nil {
			return nil, err
		}
		lsLink.Metrics = append(lsLink.Metrics, metric)
	}
	return lsLink, nil
}

func createMetric(metricInfo *pb.Metric) (*table.Metric, error) {
	switch metricInfo.GetType() {
	case pb.MetricType_IGP:
		return table.NewMetric(table.IGP_METRIC, metricInfo.GetValue()), nil
	case pb.MetricType_TE:
		return table.NewMetric(table.TE_METRIC, metricInfo.GetValue()), nil
	case pb.MetricType_DELAY:
		return table.NewMetric(table.DELAY_METRIC, metricInfo.GetValue()), nil
	case pb.MetricType_HOPCOUNT:
		return table.NewMetric(table.HOPCOUNT_METRIC, metricInfo.GetValue()), nil
	default:
		return nil, errors.New("unknown metric type")
	}
}
