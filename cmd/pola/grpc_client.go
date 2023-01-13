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

type srPolicyInfo struct {
	peerAddr   netip.Addr //TODO: Change to ("loopback addr" or "router name")
	name       string
	path       []uint32
	srcAddr    netip.Addr
	dstAddr    netip.Addr
	color      uint32
	preference uint32
}

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

func getSrPolicyList(client pb.PceServiceClient) ([]srPolicyInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := client.GetSrPolicyList(ctx, &empty)
	if err != nil {
		return nil, err
	}
	srPolicyList := []srPolicyInfo{}
	for _, lsp := range ret.GetSrPolicies() {
		peerAddr, _ := netip.AddrFromSlice(lsp.GetPcepSessionAddr())
		srcAddr, _ := netip.AddrFromSlice(lsp.GetSrcAddr())
		dstAddr, _ := netip.AddrFromSlice(lsp.GetDstAddr())
		tmp := srPolicyInfo{
			name:       lsp.PolicyName,
			peerAddr:   peerAddr,
			srcAddr:    srcAddr,
			dstAddr:    dstAddr,
			color:      lsp.Color,
			preference: lsp.Preference,
		}
		if len(lsp.GetSegmentList()) != 0 {
			for _, label := range lsp.GetSegmentList() {
				tmp.path = append(tmp.path, label.GetSid())
			}
		}
		srPolicyList = append(srPolicyList, tmp)
	}
	return srPolicyList, nil
}

func createSrPolicy(client pb.PceServiceClient, createSrPolicyInput *pb.CreateSrPolicyInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateSrPolicy(ctx, createSrPolicyInput)
	if err != nil {
		return err
	}
	return nil
}

func createSrPolicyWithoutLinkState(client pb.PceServiceClient, createSrPolicyInput *pb.CreateSrPolicyInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateSrPolicyWithoutLinkState(ctx, createSrPolicyInput)
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
