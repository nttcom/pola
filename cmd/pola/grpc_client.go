// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/internal/pkg/table"
)

type lspInfo struct {
	peerAddr net.IP //TODO: Change to ("loopback addr" or "router name")
	name     string
	path     []uint32
	srcAddr  net.IP
	dstAddr  net.IP
}

func getPeerAddrList(client pb.PceServiceClient) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := client.GetPeerAddrList(ctx, &empty)
	if err != nil {
		return nil, errors.New("could not get Peer Address")
	}
	var peerAddrList []net.IP
	for _, peerAddr := range ret.GetPeerAddrs() {
		peerAddrList = append(peerAddrList, net.IP(peerAddr))
	}
	return peerAddrList, nil
}

func getlspList(client pb.PceServiceClient) ([]lspInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := client.GetLspList(ctx, &empty)
	if err != nil {
		return nil, errors.New("could not get Lsp List")
	}
	lspList := []lspInfo{}
	for _, lsp := range ret.GetLsps() {
		tmp := lspInfo{
			name:     lsp.PolicyName,
			peerAddr: net.IP(lsp.GetPcepSessionAddr()),
			srcAddr:  net.IP(lsp.GetSrcAddr()),
			dstAddr:  net.IP(lsp.GetDstAddr()),
		}
		if len(lsp.GetLabels()) != 0 {
			for _, label := range lsp.GetLabels() {
				tmp.path = append(tmp.path, label.GetSid())
			}
		}
		lspList = append(lspList, tmp)
	}
	return lspList, nil
}

func createLsp(client pb.PceServiceClient, lspData *pb.LspData) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.CreateLsp(ctx, lspData)
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
		return nil, errors.New("could not get Peer Address")
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
			lsLink.LocalIP = net.ParseIP(link.GetLocalIp())
			lsLink.RemoteIP = net.ParseIP(link.GetRemoteIp())
			for _, metricInfo := range link.GetMetrics() {
				var metric *table.Metric
				switch metricInfo.GetType().String() {
				case "IGP":
					metric = table.NewMetric(table.IGP_METRIC, metricInfo.GetValue())
				case "TE":
					metric = table.NewMetric(table.IGP_METRIC, metricInfo.GetValue())
				case "DELAY":
					metric = table.NewMetric(table.IGP_METRIC, metricInfo.GetValue())
				case "HOPCOUNT":
					metric = table.NewMetric(table.IGP_METRIC, metricInfo.GetValue())
				default:
					return nil, errors.New("unknown metric type")
				}
				lsLink.Metrics = append(lsLink.Metrics, metric)
			}
			ted.Nodes[node.GetAsn()][node.GetRouterId()].Links = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].Links, lsLink)
		}

		for _, prefix := range node.LsPrefixes {
			lsPrefix := table.NewLsPrefixV4(ted.Nodes[node.GetAsn()][node.GetRouterId()])
			_, lsPrefix.Prefix, _ = net.ParseCIDR(prefix.GetPrefix())
			lsPrefix.SidIndex = prefix.GetSidIndex()
			ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].Prefixes, lsPrefix)
		}
	}
	return ted, nil
}
