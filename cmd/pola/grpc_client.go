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
	var empty empty.Empty
	ret, err := client.GetPeerAddrList(ctx, &empty)
	if err != nil {
		return nil, err
	}
	var peerAddrList []netip.Addr
	for _, peerAddr := range ret.GetPeerAddrs() {
		peer, _ := netip.AddrFromSlice(peerAddr)
		peerAddrList = append(peerAddrList, peer)
	}
	return peerAddrList, nil
}

func getSRPolicyList(client pb.PceServiceClient) (map[netip.Addr][]table.SRPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := client.GetSRPolicyList(ctx, &empty)
	if err != nil {
		return nil, err
	}
	srPolicies := map[netip.Addr][]table.SRPolicy{}
	for _, pbPol := range ret.GetSRPolicies() {
		peerAddr, _ := netip.AddrFromSlice(pbPol.GetPcepSessionAddr())
		srcAddr, _ := netip.AddrFromSlice(pbPol.GetSrcAddr())
		dstAddr, _ := netip.AddrFromSlice(pbPol.GetDstAddr())
		pol := table.SRPolicy{
			Name:        pbPol.PolicyName,
			SegmentList: []table.Segment{},
			SrcAddr:     srcAddr,
			DstAddr:     dstAddr,
			Color:       pbPol.Color,
			Preference:  pbPol.Preference,
		}
		if len(pbPol.GetSegmentList()) != 0 {
			for _, pbSeg := range pbPol.GetSegmentList() {
				seg, err := table.NewSegment(pbSeg.GetSid())
				if err != nil {
					return nil, err
				}
				pol.SegmentList = append(pol.SegmentList, seg)
			}
		}
		srPolicies[peerAddr] = append(srPolicies[peerAddr], pol)
	}
	return srPolicies, nil
}

func createSRPolicy(client pb.PceServiceClient, createSrPolicyInput *pb.CreateSRPolicyInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateSRPolicy(ctx, createSrPolicyInput)
	if err != nil {
		return err
	}
	return nil
}

func createSrPolicyWithoutLinkState(client pb.PceServiceClient, createSrPolicyInput *pb.CreateSRPolicyInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateSRPolicyWithoutLinkState(ctx, createSrPolicyInput)
	if err != nil {
		return err
	}
	return nil
}

func getTed(client pb.PceServiceClient) (*table.LsTed, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := client.GetTed(ctx, &empty)
	if err != nil {
		return nil, err
	}

	if !ret.GetEnable() {
		return nil, errors.New("ted is disable")
	}
	ted := &table.LsTed{
		Id:    1,
		Nodes: map[uint32]map[string]*table.LsNode{},
	}

	for _, node := range ret.GetLsNodes() {
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

	for _, node := range ret.GetLsNodes() {
		for _, link := range node.LsLinks {
			lsLink := table.NewLsLink(ted.Nodes[link.LocalAsn][link.LocalRouterId], ted.Nodes[link.RemoteAsn][link.RemoteRouterId])
			lsLink.AdjSid = link.GetAdjSid()
			lsLink.LocalIP, err = netip.ParseAddr(link.GetLocalIp())
			if err != nil {
				return nil, err
			}
			lsLink.RemoteIP, err = netip.ParseAddr(link.GetRemoteIp())
			if err != nil {
				return nil, err
			}
			for _, metricInfo := range link.GetMetrics() {
				var metric *table.Metric
				switch metricInfo.GetType().String() {
				case "IGP":
					metric = table.NewMetric(table.IGP_METRIC, metricInfo.GetValue())
				case "TE":
					metric = table.NewMetric(table.TE_METRIC, metricInfo.GetValue())
				case "DELAY":
					metric = table.NewMetric(table.DELAY_METRIC, metricInfo.GetValue())
				case "HOPCOUNT":
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
			lsPrefix.Prefix, err = netip.ParsePrefix(prefix.GetPrefix())
			if err != nil {
				return nil, err
			}
			lsPrefix.SidIndex = prefix.GetSidIndex()
			ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes, lsPrefix)
		}
	}
	return ted, nil
}
