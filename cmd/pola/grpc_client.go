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

func getSessionAddrList(client pb.PceServiceClient) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ret, err := client.GetPeerAddrList(ctx, &empty.Empty{})
	if err != nil {
		return nil, err
	}

	addrs := make([]netip.Addr, 0, len(ret.PeerAddrs))
	for _, addr := range ret.PeerAddrs {
		a, _ := netip.AddrFromSlice(addr)
		addrs = append(addrs, a)
	}

	return addrs, nil
}

func getSRPolicyList(client pb.PceServiceClient) (map[netip.Addr][]table.SRPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ret, err := client.GetSRPolicyList(ctx, &empty.Empty{})
	if err != nil {
		return nil, err
	}

	policies := make(map[netip.Addr][]table.SRPolicy, len(ret.SRPolicies))

	for _, p := range ret.SRPolicies {
		peerAddr, _ := netip.AddrFromSlice(p.PcepSessionAddr)
		srcAddr, _ := netip.AddrFromSlice(p.SrcAddr)
		dstAddr, _ := netip.AddrFromSlice(p.DstAddr)
		segmentList := make([]table.Segment, len(p.SegmentList))
		for i, s := range p.SegmentList {
			seg, err := table.NewSegment(s.Sid)
			if err != nil {
				return nil, err
			}
			segmentList[i] = seg
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.CreateSRPolicy(ctx, input)
	return err
}

func createSRPolicyWithoutLinkState(client pb.PceServiceClient, input *pb.CreateSRPolicyInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.CreateSRPolicyWithoutLinkState(ctx, input)
	return err
}

func getTed(client pb.PceServiceClient) (*table.LsTed, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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

	for _, node := range ret.GetLsNodes() {
		lsNode := table.NewLsNode(node.GetAsn(), node.GetRouterId())
		lsNode.Hostname = node.GetHostname()
		lsNode.IsisAreaId = node.GetIsisAreaId()
		lsNode.SrgbBegin = node.GetSrgbBegin()
		lsNode.SrgbEnd = node.GetSrgbEnd()

		if _, ok := ted.Nodes[lsNode.Asn]; !ok {
			ted.Nodes[lsNode.Asn] = make(map[string]*table.LsNode)
		}
		ted.Nodes[lsNode.Asn][lsNode.RouterId] = lsNode

		for _, link := range node.LsLinks {
			lsLink := table.NewLsLink(ted.Nodes[link.LocalAsn][link.LocalRouterId], ted.Nodes[link.RemoteAsn][link.RemoteRouterId])
			lsLink.AdjSid = link.GetAdjSid()

			if lsLink.LocalIP, err = netip.ParseAddr(link.GetLocalIp()); err != nil {
				return nil, err
			}
			if lsLink.RemoteIP, err = netip.ParseAddr(link.GetRemoteIp()); err != nil {
				return nil, err
			}

			for _, metricInfo := range link.GetMetrics() {
				var metric *table.Metric
				switch metricInfo.GetType() {
				case pb.MetricType_IGP:
					metric = table.NewMetric(table.IGP_METRIC, metricInfo.GetValue())
				case pb.MetricType_TE:
					metric = table.NewMetric(table.TE_METRIC, metricInfo.GetValue())
				case pb.MetricType_DELAY:
					metric = table.NewMetric(table.DELAY_METRIC, metricInfo.GetValue())
				case pb.MetricType_HOPCOUNT:
					metric = table.NewMetric(table.HOPCOUNT_METRIC, metricInfo.GetValue())
				default:
					return nil, errors.New("unknown metric type")
				}
				lsLink.Metrics = append(lsLink.Metrics, metric)
			}
			ted.Nodes[node.GetAsn()][node.GetRouterId()].Links = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].Links, lsLink)
		}

		for _, prefix := range node.LsPrefixes {
			lsPrefix := table.NewLsPrefixV4(ted.Nodes[node.GetAsn()][node.GetRouterId()])
			if lsPrefix.Prefix, err = netip.ParsePrefix(prefix.GetPrefix()); err != nil {
				return nil, err
			}
			lsPrefix.SidIndex = prefix.GetSidIndex()
			ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes, lsPrefix)
		}
	}
	return ted, nil
}
