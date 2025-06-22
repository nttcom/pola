// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package grpc

import (
	"context"
	"errors"
	"net/netip"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/internal/pkg/table"
)

func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second)
}

type Session struct {
	Addr     netip.Addr
	State    string
	Caps     []string
	IsSynced bool
}

func GetSessions(client pb.PCEServiceClient) ([]Session, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetSessionList(ctx, &pb.GetSessionListRequest{})
	if err != nil {
		return nil, err
	}

	var sessions []Session
	for _, pbss := range ret.GetSessions() {
		addr, _ := netip.AddrFromSlice(pbss.GetAddr())
		ss := Session{
			Addr:     addr,
			State:    pbss.State.String(),
			Caps:     []string{},
			IsSynced: pbss.GetIsSynced(),
		}
		ss.Caps = append(ss.Caps, pbss.GetCaps()...)
		sessions = append(sessions, ss)
	}

	return sessions, nil
}

func DeleteSession(client pb.PCEServiceClient, req *pb.DeleteSessionRequest) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.DeleteSession(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func GetSRPolicyList(client pb.PCEServiceClient) (map[netip.Addr][]table.SRPolicy, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetSRPolicyList(ctx, &pb.GetSRPolicyListRequest{})
	if err != nil {
		return nil, err
	}

	policies := make(map[netip.Addr][]table.SRPolicy, len(ret.GetSrPolicies()))

	for _, p := range ret.GetSrPolicies() {
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

func CreateSRPolicy(client pb.PCEServiceClient, req *pb.CreateSRPolicyRequest) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.CreateSRPolicy(ctx, req)
	return err
}

func DeleteSRPolicy(client pb.PCEServiceClient, req *pb.DeleteSRPolicyRequest) error {
	ctx, cancel := withTimeout()
	defer cancel()

	_, err := client.DeleteSRPolicy(ctx, req)
	return err
}

func GetTED(client pb.PCEServiceClient) (*table.LsTED, error) {
	ctx, cancel := withTimeout()
	defer cancel()

	ret, err := client.GetTED(ctx, &pb.GetTEDRequest{})
	if err != nil {
		return nil, err
	}

	if !ret.GetEnable() {
		return nil, errors.New("ted is disabled")
	}

	ted := &table.LsTED{
		ID:    1,
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

// initializeLsNodes initializes LsNodes in the LsTED table using the given array of nodes
func initializeLsNodes(ted *table.LsTED, nodes []*pb.LsNode) {
	for _, node := range nodes {
		lsNode := table.NewLsNode(node.GetAsn(), node.GetRouterId())
		lsNode.Hostname = node.GetHostname()
		lsNode.IsisAreaID = node.GetIsisAreaId()
		lsNode.SrgbBegin = node.GetSrgbBegin()
		lsNode.SrgbEnd = node.GetSrgbEnd()

		if _, ok := ted.Nodes[lsNode.ASN]; !ok {
			ted.Nodes[lsNode.ASN] = map[string]*table.LsNode{}
		}
		ted.Nodes[lsNode.ASN][lsNode.RouterID] = lsNode
	}
}

func addLsNode(ted *table.LsTED, node *pb.LsNode) error {
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

	for _, srv6SID := range node.LsSrv6Sids {
		lsSrv6SID, err := createSrv6SID(ted.Nodes[node.GetAsn()][node.GetRouterId()], srv6SID)
		if err != nil {
			return err
		}
		ted.Nodes[node.GetAsn()][node.GetRouterId()].SRv6SIDs = append(ted.Nodes[node.GetAsn()][node.GetRouterId()].SRv6SIDs, lsSrv6SID)
	}

	return nil
}

func createLsPrefix(lsNode *table.LsNode, prefix *pb.LsPrefix) (*table.LsPrefix, error) {
	lsPrefix := table.NewLsPrefix(lsNode)
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
	case pb.MetricType_METRIC_TYPE_IGP:
		return table.NewMetric(table.IGPMetric, metricInfo.GetValue()), nil
	case pb.MetricType_METRIC_TYPE_TE:
		return table.NewMetric(table.TEMetric, metricInfo.GetValue()), nil
	case pb.MetricType_METRIC_TYPE_DELAY:
		return table.NewMetric(table.DelayMetric, metricInfo.GetValue()), nil
	case pb.MetricType_METRIC_TYPE_HOPCOUNT:
		return table.NewMetric(table.HopcountMetric, metricInfo.GetValue()), nil
	default:
		return nil, errors.New("unknown metric type")
	}
}

func createSrv6SID(lsNode *table.LsNode, srv6SID *pb.LsSrv6SID) (*table.LsSrv6SID, error) {
	lsSrv6SID := table.NewLsSrv6SID(lsNode)

	lsSrv6SID.EndpointBehavior = srv6SID.GetEndpointBehavior()
	for _, sid := range srv6SID.GetSids() {
		lsSrv6SID.Sids = append(lsSrv6SID.Sids, sid.GetSid())
	}
	for _, topoID := range srv6SID.GetMultiTopoIds() {
		lsSrv6SID.MultiTopoIDs = append(lsSrv6SID.MultiTopoIDs, topoID.GetMultiTopoId())
	}

	return lsSrv6SID, nil
}
