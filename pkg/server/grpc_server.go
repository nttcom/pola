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
	"strings"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/internal/pkg/cspf"
	"github.com/nttcom/pola/internal/pkg/table"
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
	var listenInfo strings.Builder
	listenInfo.WriteString(address)
	listenInfo.WriteString(":")
	listenInfo.WriteString(port)
	s.pce.logger.Info("gRPC listen", zap.String("listenInfo", listenInfo.String()), zap.String("server", "grpc"))
	grpcListener, err := net.Listen("tcp", listenInfo.String())
	if err != nil {
		return err
	}

	if err := s.grpcServer.Serve(grpcListener); err != nil {
		return err
	}
	return nil
}

func (s *APIServer) CreateSRPolicy(ctx context.Context, input *pb.CreateSRPolicyInput) (*pb.SRPolicyStatus, error) {
	if s.pce.ted == nil {
		return &pb.SRPolicyStatus{IsSuccess: false}, errors.New("ted is disable")
	}
	inputSRPolicy := input.GetSRPolicy()
	// Validate input
	if inputSRPolicy.GetPcepSessionAddr() == nil || input.GetAsn() == 0 || inputSRPolicy.GetColor() == 0 || inputSRPolicy.GetSrcRouterId() == "" || inputSRPolicy.GetDstRouterId() == "" {
		return &pb.SRPolicyStatus{IsSuccess: false}, errors.New("input is invalid")
	}

	inputJson, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	s.pce.logger.Info("Receive CreateSRPolicy API request", zap.String("input", string(inputJson)), zap.String("server", "grpc"))

	pcepSessionAddr, _ := netip.AddrFromSlice(inputSRPolicy.GetPcepSessionAddr())
	pcepSession := s.pce.SearchSession(pcepSessionAddr)
	if pcepSession == nil {
		return &pb.SRPolicyStatus{IsSuccess: false}, fmt.Errorf("no session with %s", pcepSessionAddr)
	}

	srcAddr, err := s.pce.ted.Nodes[input.GetAsn()][inputSRPolicy.GetSrcRouterId()].LoopbackAddr()
	if err != nil {
		return &pb.SRPolicyStatus{IsSuccess: false}, err
	}
	dstAddr, err := s.pce.ted.Nodes[input.GetAsn()][inputSRPolicy.GetDstRouterId()].LoopbackAddr()
	if err != nil {
		return &pb.SRPolicyStatus{IsSuccess: false}, err
	}

	// create PCE format Segment List
	segmentList := []table.Segment{}
	if inputSRPolicy.GetType().String() == "EXPLICIT" {

		// Validate input
		if len(inputSRPolicy.GetSegmentList()) == 0 {
			return &pb.SRPolicyStatus{IsSuccess: false}, errors.New("input is invalid")
		}
		for _, segment := range inputSRPolicy.GetSegmentList() {

			seg, err := table.NewSegment(segment.GetSid())
			if err != nil {
				return &pb.SRPolicyStatus{IsSuccess: false}, err
			}
			segmentList = append(segmentList, seg)
		}
	} else if inputSRPolicy.GetType().String() == "DYNAMIC" {

		var mt table.MetricType
		switch inputSRPolicy.GetMetric().String() {
		case "IGP":
			mt = table.IGP_METRIC
		case "TE":
			mt = table.TE_METRIC
		case "DELAY":
			mt = table.DELAY_METRIC
		case "HOPCOUNT":
			mt = table.HOPCOUNT_METRIC
		default:
			return nil, errors.New("unknown metric type")
		}
		segmentList, err = cspf.Cspf(inputSRPolicy.SrcRouterId, inputSRPolicy.DstRouterId, input.GetAsn(), mt, s.pce.ted)
		if err != nil {
			return &pb.SRPolicyStatus{IsSuccess: false}, err
		}
	} else {
		return &pb.SRPolicyStatus{IsSuccess: false}, errors.New("undefined SR Policy type")
	}

	srPolicy := table.SRPolicy{
		Name:        inputSRPolicy.GetPolicyName(),
		SegmentList: segmentList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       inputSRPolicy.GetColor(),
		Preference:  uint32(100),
	}
	if id, exists := pcepSession.SearchSRPolicyPlspId(inputSRPolicy.GetColor(), dstAddr); exists {
		// Update SR Policy
		s.pce.logger.Info("plspId check", zap.Uint32("plspId", id), zap.String("server", "grpc"))
		srPolicy.PlspId = id

		if err := pcepSession.SendPCUpdate(srPolicy); err != nil {
			return &pb.SRPolicyStatus{IsSuccess: false}, err
		}
	} else {
		// Initiate SR Policy
		if err := pcepSession.SendPCInitiate(srPolicy); err != nil {
			return &pb.SRPolicyStatus{IsSuccess: false}, err
		}
	}
	return &pb.SRPolicyStatus{IsSuccess: true}, nil

}

func (s *APIServer) CreateSRPolicyWithoutLinkState(ctx context.Context, input *pb.CreateSRPolicyInput) (*pb.SRPolicyStatus, error) {
	inputSRPolicy := input.GetSRPolicy()

	// Validate input
	if inputSRPolicy.GetPcepSessionAddr() == nil || len(inputSRPolicy.GetSrcAddr()) == 0 || len(inputSRPolicy.GetDstAddr()) == 0 || len(inputSRPolicy.GetSegmentList()) == 0 {
		return &pb.SRPolicyStatus{IsSuccess: false}, errors.New("input is invalid")
	}

	s.pce.logger.Info("Receive CreateSRPolicyWithoutLinkState API request", zap.Object("input", inputSRPolicy), zap.String("server", "grpc"))

	pcepSessionAddr, _ := netip.AddrFromSlice(inputSRPolicy.GetPcepSessionAddr())
	pcepSession := s.pce.SearchSession(pcepSessionAddr)
	if pcepSession == nil {
		return &pb.SRPolicyStatus{IsSuccess: false}, fmt.Errorf("no session with %s", pcepSessionAddr)
	}

	srcAddr, _ := netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
	dstAddr, _ := netip.AddrFromSlice(inputSRPolicy.GetDstAddr())

	// create PCE format Segment List
	segmentList := []table.Segment{}
	for _, segment := range inputSRPolicy.GetSegmentList() {

		seg, err := table.NewSegment(segment.GetSid())
		if err != nil {
			return &pb.SRPolicyStatus{IsSuccess: false}, err
		}
		segmentList = append(segmentList, seg)
	}

	srPolicy := table.SRPolicy{
		Name:        inputSRPolicy.GetPolicyName(),
		SegmentList: segmentList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       inputSRPolicy.GetColor(),
		Preference:  uint32(100),
	}

	if id, exists := pcepSession.SearchSRPolicyPlspId(inputSRPolicy.GetColor(), dstAddr); exists {
		// Update SR Policy
		s.pce.logger.Info("plspId check", zap.Uint32("plspId", id), zap.String("server", "grpc"))
		srPolicy.PlspId = id

		if err := pcepSession.SendPCUpdate(srPolicy); err != nil {
			return &pb.SRPolicyStatus{IsSuccess: false}, err
		}
	} else {
		// Initiate SR Policy
		if err := pcepSession.SendPCInitiate(srPolicy); err != nil {
			return &pb.SRPolicyStatus{IsSuccess: false}, err
		}
	}
	return &pb.SRPolicyStatus{IsSuccess: true}, nil
}

func (s *APIServer) GetPeerAddrList(context.Context, *empty.Empty) (*pb.PeerAddrList, error) {
	s.pce.logger.Info("Receive GetPeerAddrList API request", zap.String("server", "grpc"))
	var ret pb.PeerAddrList
	for _, pcepSession := range s.pce.sessionList {
		ret.PeerAddrs = append(ret.PeerAddrs, pcepSession.peerAddr.AsSlice())
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
				SegmentList:     []*pb.Segment{},
				Color:           pol.Color,
				Preference:      pol.Preference,
				PolicyName:      pol.Name,
				SrcAddr:         pol.SrcAddr.AsSlice(),
				DstAddr:         pol.DstAddr.AsSlice(),
			}
			for _, seg := range pol.SegmentList {
				segment := &pb.Segment{
					Sid: seg.SidString(),
				}
				srPolicyData.SegmentList = append(srPolicyData.SegmentList, segment)
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

	for _, lsNodes := range s.pce.ted.Nodes {
		for _, lsNode := range lsNodes {
			node := &pb.LsNode{
				Asn:        lsNode.Asn,
				RouterId:   lsNode.RouterId,
				IsisAreaId: lsNode.IsisAreaId,
				Hostname:   lsNode.Hostname,
				SrgbBegin:  lsNode.SrgbBegin,
				SrgbEnd:    lsNode.SrgbEnd,
				LsLinks:    []*pb.LsLink{},
				LsPrefixes: []*pb.LsPrefix{},
			}
			for _, lsLink := range lsNode.Links {
				link := &pb.LsLink{
					LocalRouterId:  lsLink.LocalNode.RouterId,
					LocalAsn:       lsLink.LocalNode.Asn,
					LocalIp:        lsLink.LocalIP.String(),
					RemoteRouterId: lsLink.RemoteNode.RouterId,
					RemoteAsn:      lsLink.RemoteNode.Asn,
					RemoteIp:       lsLink.RemoteIP.String(),
					Metrics:        []*pb.Metric{},
					AdjSid:         lsLink.AdjSid,
				}
				for _, lsMetric := range lsLink.Metrics {
					metric := &pb.Metric{
						Type:  pb.MetricType(pb.MetricType_value[lsMetric.Type.String()]),
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
