// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/internal/pkg/cspf"
	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"go.uber.org/zap"
	grpc "google.golang.org/grpc"
)

type APIServer struct {
	pce        *Server
	grpcServer *grpc.Server
	pb.UnimplementedPceServiceServer
}

func NewAPIServer(pce *Server, grpcServer *grpc.Server) *APIServer {
	s := &APIServer{
		pce:        pce,
		grpcServer: grpcServer,
	}
	pb.RegisterPceServiceServer(grpcServer, s)
	return s
}

func (s *APIServer) Serve(address string, port string) error {
	listenInfo := net.JoinHostPort(address, port)
	s.pce.logger.Info("gRPC listen", zap.String("listenInfo", listenInfo), zap.String("server", "grpc"))
	grpcListener, err := net.Listen("tcp", listenInfo)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	return s.grpcServer.Serve(grpcListener)
}

func (s *APIServer) CreateSRPolicy(ctx context.Context, input *pb.CreateSRPolicyInput) (*pb.RequestStatus, error) {
	return s.createSRPolicy(ctx, input, true)
}

func (s *APIServer) CreateSRPolicyWithoutLinkState(ctx context.Context, input *pb.CreateSRPolicyInput) (*pb.RequestStatus, error) {
	return s.createSRPolicy(ctx, input, false)
}

func (s *APIServer) createSRPolicy(ctx context.Context, input *pb.CreateSRPolicyInput, withLinkState bool) (*pb.RequestStatus, error) {
	err := validate(input.GetSRPolicy(), input.GetAsn(), withLinkState)
	if err != nil {
		return &pb.RequestStatus{IsSuccess: false}, err
	}

	inputSRPolicy := input.GetSRPolicy()
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment

	if withLinkState {
		if s.pce.ted == nil {
			return &pb.RequestStatus{IsSuccess: false}, errors.New("ted is disabled")
		}

		srcAddr, err = getLoopbackAddr(s.pce, input.GetAsn(), inputSRPolicy.GetSrcRouterID())
		if err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}

		dstAddr, err = getLoopbackAddr(s.pce, input.GetAsn(), inputSRPolicy.GetDstRouterID())
		if err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}

		segmentList, err = getSegmentList(inputSRPolicy, input.GetAsn(), s.pce.ted)
		if err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	} else {
		srcAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
		dstAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetDstAddr())

		for _, segment := range inputSRPolicy.GetSegmentList() {
			seg, err := table.NewSegment(segment.GetSid())
			if err != nil {
				return &pb.RequestStatus{IsSuccess: false}, err
			}
			segmentList = append(segmentList, seg)
		}
	}

	inputJson, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	s.pce.logger.Info("received CreateSRPolicy API request", zap.String("input", string(inputJson)), zap.String("server", "grpc"))

	pcepSession, err := getPcepSession(s.pce, inputSRPolicy.GetPcepSessionAddr())
	if err != nil {
		return &pb.RequestStatus{IsSuccess: false}, err
	}

	srPolicy := table.SRPolicy{
		Name:        inputSRPolicy.GetPolicyName(),
		SegmentList: segmentList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       inputSRPolicy.GetColor(),
		Preference:  100,
	}

	if id, exists := pcepSession.SearchSRPolicyPlspID(inputSRPolicy.GetColor(), dstAddr); exists {
		// Update SR Policy
		s.pce.logger.Info("plspID check", zap.Uint32("plspID", id), zap.String("server", "grpc"))
		srPolicy.PlspID = id

		if err := pcepSession.SendPCUpdate(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	} else {
		// Initiate SR Policy
		if err := pcepSession.SendCreateLsp(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	}

	return &pb.RequestStatus{IsSuccess: true}, nil
}

func validate(inputSRPolicy *pb.SRPolicy, asn uint32, withLinkState bool) error {
	var validator func(policy *pb.SRPolicy, asn uint32) bool

	if withLinkState {
		validator = validateInput
	} else {
		validator = validateInputWithoutLinkState
	}

	if !validator(inputSRPolicy, asn) {
		return errors.New("invalid input")
	}

	return nil
}

func validateInput(policy *pb.SRPolicy, asn uint32) bool {
	return asn != 0 &&
		policy.PcepSessionAddr != nil &&
		policy.Color != 0 &&
		policy.SrcRouterID != "" &&
		policy.DstRouterID != ""
}

func validateInputWithoutLinkState(policy *pb.SRPolicy, asn uint32) bool {
	return policy.PcepSessionAddr != nil &&
		len(policy.SrcAddr) > 0 &&
		len(policy.DstAddr) > 0 &&
		len(policy.SegmentList) > 0
}

func getPcepSession(pce *Server, addr []byte) (*Session, error) {
	pcepSessionAddr, _ := netip.AddrFromSlice(addr)
	pcepSession := pce.SearchSession(pcepSessionAddr)
	if pcepSession == nil {
		return nil, fmt.Errorf("no session with %s", pcepSessionAddr)
	}
	return pcepSession, nil
}

func getLoopbackAddr(pce *Server, asn uint32, routerID string) (netip.Addr, error) {
	node, ok := pce.ted.Nodes[asn][routerID]
	if !ok {
		return netip.Addr{}, fmt.Errorf("no node with AS %d and router ID %s", asn, routerID)
	}
	return node.LoopbackAddr()
}

func getSegmentList(inputSRPolicy *pb.SRPolicy, asn uint32, ted *table.LsTed) ([]table.Segment, error) {
	var segments []table.Segment

	switch inputSRPolicy.GetType() {
	case pb.SRPolicyType_EXPLICIT:
		if len(inputSRPolicy.GetSegmentList()) == 0 {
			return nil, errors.New("no segments in SRPolicy input")
		}
		for _, segment := range inputSRPolicy.GetSegmentList() {
			seg, err := table.NewSegment(segment.GetSid())
			if err != nil {
				return nil, err
			}
			segments = append(segments, seg)
		}
	case pb.SRPolicyType_DYNAMIC:
		metricType, err := getMetricType(inputSRPolicy.GetMetric())
		if err != nil {
			return nil, err
		}
		segments, err = cspf.Cspf(inputSRPolicy.GetSrcRouterID(), inputSRPolicy.GetDstRouterID(), asn, metricType, ted)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("undefined SR Policy type")
	}

	return segments, nil
}

func getMetricType(metricType pb.MetricType) (table.MetricType, error) {
	switch metricType {
	case pb.MetricType_IGP:
		return table.IGP_METRIC, nil
	case pb.MetricType_TE:
		return table.TE_METRIC, nil
	case pb.MetricType_DELAY:
		return table.DELAY_METRIC, nil
	case pb.MetricType_HOPCOUNT:
		return table.HOPCOUNT_METRIC, nil
	default:
		return 0, fmt.Errorf("unknown metric type: %v", metricType)
	}
}

func (s *APIServer) GetSessionList(context.Context, *empty.Empty) (*pb.SessionList, error) {
	s.pce.logger.Info("Receive GetPeerAddrList API request", zap.String("server", "grpc"))

	var ret pb.SessionList
	for _, pcepSession := range s.pce.sessionList {
		ss := &pb.Session{
			Addr: pcepSession.peerAddr.AsSlice(),
		}
		ret.Sessions = append(ret.Sessions, ss)
	}

	s.pce.logger.Info("Send GetPeerAddrList API reply", zap.String("server", "grpc"))
	return &ret, nil
}

func (s *APIServer) GetSRPolicyList(context.Context, *empty.Empty) (*pb.SRPolicyList, error) {
	s.pce.logger.Info("Receive GetSRPolicyList API request", zap.String("server", "grpc"))

	var ret pb.SRPolicyList
	for ssAddr, pols := range s.pce.SRPolicies() {
		for _, pol := range pols {
			srPolicyData := &pb.SRPolicy{
				PcepSessionAddr: ssAddr.AsSlice(),
				SegmentList:     make([]*pb.Segment, 0),
				Color:           pol.Color,
				Preference:      pol.Preference,
				PolicyName:      pol.Name,
				SrcAddr:         pol.SrcAddr.AsSlice(),
				DstAddr:         pol.DstAddr.AsSlice(),
			}

			for _, seg := range pol.SegmentList {
				srPolicyData.SegmentList = append(srPolicyData.SegmentList, &pb.Segment{
					Sid: seg.SidString(),
				})
			}

			ret.SRPolicies = append(ret.SRPolicies, srPolicyData)
		}
	}

	s.pce.logger.Info("Send SRPolicyList API reply", zap.String("server", "grpc"))
	return &ret, nil
}

func (s *APIServer) GetTed(context.Context, *empty.Empty) (*pb.Ted, error) {
	s.pce.logger.Info("Receive GetTed API request", zap.String("server", "grpc"))

	ret := &pb.Ted{
		Enable: true,
	}

	if s.pce.ted == nil {
		ret.Enable = false
		return ret, nil
	}

	ret.LsNodes = make([]*pb.LsNode, 0, len(s.pce.ted.Nodes))

	for _, lsNodes := range s.pce.ted.Nodes {
		for _, lsNode := range lsNodes {
			node := &pb.LsNode{
				Asn:        lsNode.Asn,
				RouterID:   lsNode.RouterID,
				IsisAreaID: lsNode.IsisAreaID,
				Hostname:   lsNode.Hostname,
				SrgbBegin:  lsNode.SrgbBegin,
				SrgbEnd:    lsNode.SrgbEnd,
				LsLinks:    make([]*pb.LsLink, 0, len(lsNode.Links)),
				LsPrefixes: make([]*pb.LsPrefix, 0, len(lsNode.Prefixes)),
			}

			for _, lsLink := range lsNode.Links {
				link := &pb.LsLink{
					LocalRouterID:  lsLink.LocalNode.RouterID,
					LocalAsn:       lsLink.LocalNode.Asn,
					LocalIP:        lsLink.LocalIP.String(),
					RemoteRouterID: lsLink.RemoteNode.RouterID,
					RemoteAsn:      lsLink.RemoteNode.Asn,
					RemoteIP:       lsLink.RemoteIP.String(),
					Metrics:        make([]*pb.Metric, 0, len(lsLink.Metrics)),
					AdjSid:         lsLink.AdjSid,
				}

				for _, lsMetric := range lsLink.Metrics {
					metricType, ok := pb.MetricType_value[lsMetric.Type.String()]

					if !ok {
						return nil, fmt.Errorf("invalid metric type: %s", lsMetric.Type.String())
					}

					metric := &pb.Metric{
						Type:  pb.MetricType(metricType),
						Value: lsMetric.Value,
					}

					link.Metrics = append(link.Metrics, metric)
				}

				node.LsLinks = append(node.LsLinks, link)
			}

			for _, lsPrefix := range lsNode.Prefixes {
				prefix := &pb.LsPrefix{
					Prefix:   lsPrefix.Prefix.String(),
					SidIndex: lsPrefix.SidIndex,
				}

				node.LsPrefixes = append(node.LsPrefixes, prefix)
			}

			ret.LsNodes = append(ret.LsNodes, node)
		}
	}

	s.pce.logger.Info("Send GetTed API reply", zap.String("server", "grpc"))
	return ret, nil
}

func (c *APIServer) DeleteSession(ctx context.Context, input *pb.Session) (*pb.RequestStatus, error) {
	ssAddr, _ := netip.AddrFromSlice(input.GetAddr())

	s := c.pce
	ss := s.SearchSession(ssAddr)
	if err := ss.SendClose(pcep.R_NO_EXPLANATION_PROVIDED); err != nil {
		return &pb.RequestStatus{IsSuccess: false}, err
	}
	// Remove session info from PCE server
	s.closeSession(ss)

	return &pb.RequestStatus{IsSuccess: true}, nil
}
