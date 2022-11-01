// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

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

func (s *APIServer) CreateSrPolicy(ctx context.Context, input *pb.CreateSrPolicyInput) (*pb.SrPolicyStatus, error) {
	if s.pce.ted == nil {
		return &pb.SrPolicyStatus{IsSuccess: false}, errors.New("ted is disable")
	}

	// Validate input
	if input.GetSrPolicy().GetPcepSessionAddr() == nil || input.GetAsn() == 0 || input.GetSrPolicy().GetColor() == 0 || input.GetSrPolicy().GetSrcRouterId() == "" || input.GetSrPolicy().GetDstRouterId() == "" {
		return &pb.SrPolicyStatus{IsSuccess: false}, errors.New("input is invalid")
	}

	inputJson := map[string]interface{}{
		"asn": fmt.Sprint(input.GetAsn()),
		"srPolicy": map[string]interface{}{
			"pcepSessionAddr": net.IP(input.GetSrPolicy().GetPcepSessionAddr()).String(),
			"color":           input.GetSrPolicy().GetColor(),
			"dstRouterId":     input.GetSrPolicy().GetDstRouterId(),
			"srcRouterId":     input.GetSrPolicy().GetSrcRouterId(),
			"type":            input.GetSrPolicy().GetType().String(),
			"segmentList":     input.GetSrPolicy().GetSegmentList(),
			"metric":          input.GetSrPolicy().GetMetric().String(),
		},
	}

	s.pce.logger.Info("Receive CreateSrPolicy API request", zap.Any("input", inputJson), zap.String("server", "grpc"))
	pcepSessionAddr := net.IP(input.GetSrPolicy().GetPcepSessionAddr())
	pcepSession := s.pce.getSession(pcepSessionAddr)
	if pcepSession == nil {
		return &pb.SrPolicyStatus{IsSuccess: false}, fmt.Errorf("no session with %s", pcepSessionAddr)
	}

	segmentList := []pcep.Label{}
	srcIPAddr, err := s.pce.ted.Nodes[input.GetAsn()][input.GetSrPolicy().SrcRouterId].LoopbackAddr()
	if err != nil {
		return &pb.SrPolicyStatus{IsSuccess: false}, err
	}
	dstIPAddr, err := s.pce.ted.Nodes[input.GetAsn()][input.GetSrPolicy().DstRouterId].LoopbackAddr()
	if err != nil {
		return &pb.SrPolicyStatus{IsSuccess: false}, err
	}

	if input.GetSrPolicy().GetType().String() == "EXPLICIT" {
		// Validate input
		if len(input.GetSrPolicy().GetSegmentList()) == 0 {
			return &pb.SrPolicyStatus{IsSuccess: false}, errors.New("input is invalid")
		}
		for _, segment := range input.GetSrPolicy().GetSegmentList() {
			routerId, err := s.pce.ted.GetRouterIdFromSid(input.GetAsn(), segment.GetSid())
			if err != nil {
				return &pb.SrPolicyStatus{IsSuccess: false}, err
			}
			loAddr, err := s.pce.ted.Nodes[input.GetAsn()][routerId].LoopbackAddr()
			if err != nil {
				return &pb.SrPolicyStatus{IsSuccess: false}, err
			}
			pcepSegment := pcep.Label{
				Sid:    segment.GetSid(),
				LoAddr: loAddr.To4(),
			}
			segmentList = append(segmentList, pcepSegment)
		}
	} else if input.GetSrPolicy().GetType().String() == "DYNAMIC" {

		var metric table.MetricType
		switch input.GetSrPolicy().GetMetric().String() {
		case "IGP":
			metric = table.IGP_METRIC
		case "TE":
			metric = table.TE_METRIC
		case "DELAY":
			metric = table.DELAY_METRIC
		case "HOPCOUNT":
			metric = table.HOPCOUNT_METRIC
		default:
			return nil, errors.New("unknown metric type")
		}
		var err error
		segmentList, err = cspf.Cspf(input.GetSrPolicy().SrcRouterId, input.GetSrPolicy().DstRouterId, input.GetAsn(), metric, s.pce.ted)
		if err != nil {
			return &pb.SrPolicyStatus{IsSuccess: false}, err
		}
	} else {
		return &pb.SrPolicyStatus{IsSuccess: false}, errors.New("undefined SR Policy type")
	}

	if plspId := s.pce.getPlspId(input.GetSrPolicy()); plspId != 0 {
		s.pce.logger.Info("plspId check", zap.Uint32("plspId", plspId), zap.String("server", "grpc"))
		if err := pcepSession.SendPCUpdate(input.GetSrPolicy().GetPolicyName(), plspId, segmentList); err != nil {
			return &pb.SrPolicyStatus{IsSuccess: false}, err
		}
	} else {
		if err := pcepSession.SendPCInitiate(input.GetSrPolicy().GetPolicyName(), segmentList, input.GetSrPolicy().GetColor(), uint32(100), srcIPAddr.To4(), dstIPAddr.To4()); err != nil {
			return &pb.SrPolicyStatus{IsSuccess: false}, err
		}
	}
	return &pb.SrPolicyStatus{IsSuccess: true}, nil

}

func (s *APIServer) CreateSrPolicyWithoutLinkState(ctx context.Context, input *pb.CreateSrPolicyInput) (*pb.SrPolicyStatus, error) {
	// Validate input
	if len(input.GetSrPolicy().SrcAddr) == 0 || len(input.GetSrPolicy().DstAddr) == 0 {
		return &pb.SrPolicyStatus{IsSuccess: false}, errors.New("input is invalid")
	}

	s.pce.logger.Info("Receive CreateSrPolicyWithoutLinkState API request", zap.Any("SR Policy", input.GetSrPolicy()), zap.String("server", "grpc"))
	pcepSessionAddr := net.IP(input.GetSrPolicy().GetPcepSessionAddr())
	pcepSession := s.pce.getSession(pcepSessionAddr)
	if pcepSession == nil {
		return &pb.SrPolicyStatus{IsSuccess: false}, fmt.Errorf("no session with %s", pcepSessionAddr)
	}
	segmentList := []pcep.Label{}
	for _, receivedLsp := range input.GetSrPolicy().GetSegmentList() {
		pcepSegment := pcep.Label{
			Sid:    receivedLsp.GetSid(),
			LoAddr: receivedLsp.GetLoAddr(),
		}
		segmentList = append(segmentList, pcepSegment)
	}

	if plspId := s.pce.getPlspId(input.GetSrPolicy()); plspId != 0 {
		s.pce.logger.Info("plspId check", zap.Uint32("plspId", plspId), zap.String("server", "grpc"))
		if err := pcepSession.SendPCUpdate(input.GetSrPolicy().GetPolicyName(), plspId, segmentList); err != nil {
			return &pb.SrPolicyStatus{IsSuccess: false}, err
		}
	} else {
		if err := pcepSession.SendPCInitiate(input.GetSrPolicy().GetPolicyName(), segmentList, input.GetSrPolicy().GetColor(), uint32(100), input.GetSrPolicy().GetSrcAddr(), input.GetSrPolicy().GetDstAddr()); err != nil {
			return &pb.SrPolicyStatus{IsSuccess: false}, err
		}
	}
	return &pb.SrPolicyStatus{IsSuccess: true}, nil
}

func (s *APIServer) GetPeerAddrList(context.Context, *empty.Empty) (*pb.PeerAddrList, error) {
	s.pce.logger.Info("Receive GetPeerAddrList API request", zap.String("server", "grpc"))
	var ret pb.PeerAddrList
	for _, pcepSession := range s.pce.sessionList {
		ret.PeerAddrs = append(ret.PeerAddrs, []byte(pcepSession.peerAddr))
	}
	s.pce.logger.Info("Send GetPeerAddrList API reply", zap.String("server", "grpc"))
	return &ret, nil
}

func (s *APIServer) GetSrPolicyList(context.Context, *empty.Empty) (*pb.SrPolicyList, error) {
	s.pce.logger.Info("Receive GetSrPolicyList API request", zap.String("server", "grpc"))
	var ret pb.SrPolicyList
	for _, lsp := range s.pce.lspList {
		srPolicyData := &pb.SrPolicy{
			PcepSessionAddr: []byte(lsp.peerAddr),
			SegmentList:     []*pb.Segment{},
			Color:           lsp.color,
			Preference:      lsp.preference,
			PolicyName:      lsp.name,
			SrcAddr:         []byte(lsp.srcAddr),
			DstAddr:         []byte(lsp.dstAddr),
		}
		for _, sid := range lsp.path {
			segment := pb.Segment{
				Sid: sid,
			}
			srPolicyData.SegmentList = append(srPolicyData.SegmentList, &segment)
		}
		ret.SrPolicies = append(ret.SrPolicies, srPolicyData)
	}
	s.pce.logger.Info("Send SrPolicyList API reply", zap.String("server", "grpc"))
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
