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
	"slices"

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
	usidMode   bool
	logger     *zap.Logger
	pb.UnimplementedPCEServiceServer
}

func NewAPIServer(pce *Server, grpcServer *grpc.Server, usidMode bool, logger *zap.Logger) *APIServer {
	s := &APIServer{
		pce:        pce,
		grpcServer: grpcServer,
		usidMode:   usidMode,
		logger:     logger.With(zap.String("server", "grpc")),
	}
	pb.RegisterPCEServiceServer(grpcServer, s)
	return s
}

func (s *APIServer) Serve(address string, port string) error {
	listenInfo := net.JoinHostPort(address, port)
	s.logger.Info("Start listening on gRPC port", zap.String("listenInfo", listenInfo))
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

func validateCreateSRPolicy(input *pb.CreateSRPolicyInput, withLinkState bool) error {
	if withLinkState {
		return validate(input.GetSRPolicy(), input.GetAsn(), ValidationAdd)
	}
	return validate(input.GetSRPolicy(), input.GetAsn(), ValidationAddWithoutLinkState)
}

func buildSegmentList(s *APIServer, input *pb.CreateSRPolicyInput, withLinkState bool) ([]table.Segment, netip.Addr, netip.Addr, error) {
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment
	var err error

	inputSRPolicy := input.GetSRPolicy()

	if withLinkState {
		if s.pce.ted == nil {
			return nil, netip.Addr{}, netip.Addr{}, errors.New("ted is disabled")
		}

		srcAddr, err = getLoopbackAddr(s.pce, input.GetAsn(), inputSRPolicy.GetSrcRouterID())
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}

		dstAddr, err = getLoopbackAddr(s.pce, input.GetAsn(), inputSRPolicy.GetDstRouterID())
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}

		segmentList, err = getSegmentList(inputSRPolicy, input.GetAsn(), s.pce.ted)
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}
	} else {
		srcAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
		dstAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetDstAddr())

		for _, segment := range inputSRPolicy.GetSegmentList() {
			seg, err := table.NewSegment(segment.GetSid())
			if err != nil {
				return nil, netip.Addr{}, netip.Addr{}, err
			}
			segmentList = append(segmentList, seg)
		}
	}

	return segmentList, srcAddr, dstAddr, nil
}

func sendSRPolicyRequest(s *APIServer, input *pb.CreateSRPolicyInput, segmentList []table.Segment, srcAddr, dstAddr netip.Addr) (*pb.RequestStatus, error) {
	inputSRPolicy := input.GetSRPolicy()

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPCEPSessionAddr())
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

	if id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), dstAddr); exists {
		s.logger.Debug("Request to update SR Policy", zap.Uint32("plspID", id))
		srPolicy.PlspID = id

		if err := pcepSession.SendPCUpdate(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	} else {
		s.logger.Debug("Request to create SR Policy")
		if err := pcepSession.RequestSRPolicyCreated(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	}

	return &pb.RequestStatus{IsSuccess: true}, nil
}

func (s *APIServer) createSRPolicy(_ context.Context, input *pb.CreateSRPolicyInput, withLinkState bool) (*pb.RequestStatus, error) {
	if err := validateCreateSRPolicy(input, withLinkState); err != nil {
		return &pb.RequestStatus{IsSuccess: false}, err
	}

	segmentList, srcAddr, dstAddr, err := buildSegmentList(s, input, withLinkState)
	if err != nil {
		return &pb.RequestStatus{IsSuccess: false}, err
	}

	return sendSRPolicyRequest(s, input, segmentList, srcAddr, dstAddr)
}

func (s *APIServer) DeleteSRPolicy(ctx context.Context, input *pb.DeleteSRPolicyInput) (*pb.RequestStatus, error) {
	err := validate(input.GetSRPolicy(), input.GetAsn(), ValidationDelete)
	if err != nil {
		return &pb.RequestStatus{IsSuccess: false}, err
	}

	inputSRPolicy := input.GetSRPolicy()
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment

	srcAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
	dstAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetDstAddr())
	for _, segment := range inputSRPolicy.GetSegmentList() {
		seg, err := table.NewSegment(segment.GetSid())
		if err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
		segmentList = append(segmentList, seg)
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	s.logger.Info("Received DeleteSRPolicy API request")
	s.logger.Debug("Received paramater", zap.String("input", string(inputJSON)))

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPCEPSessionAddr())
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

	if id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), dstAddr); exists {
		// Delete SR Policy
		s.logger.Debug("Request to delete SR Policy", zap.Uint32("plspID", id))
		srPolicy.PlspID = id

		if err := pcepSession.RequestSRPolicyDeleted(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, nil
		}
	} else {
		// Invalid SR Policy
		return &pb.RequestStatus{IsSuccess: false}, fmt.Errorf("requested SR Policy not found")
	}

	return &pb.RequestStatus{IsSuccess: true}, nil
}

func validate(inputSRPolicy *pb.SRPolicy, asn uint32, validationKind ValidationKind) error {
	if !validator[validationKind](inputSRPolicy, asn) {
		return errors.New("validate error, invalid input")
	}

	return nil
}

type ValidationKind string

const (
	ValidationAdd                 ValidationKind = "Add"
	ValidationAddWithoutLinkState ValidationKind = "AddWithoutLinkState"
	ValidationDelete              ValidationKind = "Delete"
)

var validator = map[ValidationKind]func(policy *pb.SRPolicy, asn uint32) bool{
	ValidationKind("Add"): func(policy *pb.SRPolicy, asn uint32) bool {
		return asn != 0 &&
			policy.PCEPSessionAddr != nil &&
			policy.Color != 0 &&
			policy.SrcRouterID != "" &&
			policy.DstRouterID != ""
	},
	ValidationKind("AddWithoutLinkState"): func(policy *pb.SRPolicy, asn uint32) bool {
		return policy.PCEPSessionAddr != nil &&
			len(policy.SrcAddr) > 0 &&
			len(policy.DstAddr) > 0 &&
			len(policy.SegmentList) > 0
	},
	ValidationKind("Delete"): func(policy *pb.SRPolicy, asn uint32) bool {
		return policy.PCEPSessionAddr != nil &&
			policy.Color != 0 &&
			len(policy.DstAddr) > 0 &&
			policy.PolicyName != ""
	},
}

func getSyncedPCEPSession(pce *Server, addr []byte) (*Session, error) {
	pcepSessionAddr, _ := netip.AddrFromSlice(addr)
	pcepSession := pce.SearchSession(pcepSessionAddr, true)
	if pcepSession == nil {
		return nil, fmt.Errorf("no synced session with %s", pcepSessionAddr)
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

func getSegmentList(inputSRPolicy *pb.SRPolicy, asn uint32, ted *table.LsTED) ([]table.Segment, error) {
	var segmentList []table.Segment

	switch inputSRPolicy.GetType() {
	case pb.SRPolicyType_EXPLICIT:
		if len(inputSRPolicy.GetSegmentList()) == 0 {
			return nil, errors.New("no segments in SRPolicy input")
		}
		for _, segment := range inputSRPolicy.GetSegmentList() {
			sid, err := table.NewSegment(segment.GetSid())
			if err != nil {
				return nil, err
			}
			segmentList = append(segmentList, sid)
		}
	case pb.SRPolicyType_DYNAMIC:
		metricType, err := getMetricType(inputSRPolicy.GetMetric())
		if err != nil {
			return nil, err
		}
		segmentList, err = cspf.Cspf(inputSRPolicy.GetSrcRouterID(), inputSRPolicy.GetDstRouterID(), asn, metricType, ted)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("undefined SR Policy type")
	}

	return segmentList, nil
}

func getMetricType(metricType pb.MetricType) (table.MetricType, error) {
	switch metricType {
	case pb.MetricType_METRIC_TYPE_IGP:
		return table.IGPMetric, nil
	case pb.MetricType_METRIC_TYPE_TE:
		return table.TEMetric, nil
	case pb.MetricType_METRIC_TYPE_DELAY:
		return table.DelayMetric, nil
	case pb.MetricType_METRIC_TYPE_HOPCOUNT:
		return table.HopcountMetric, nil
	default:
		return 0, fmt.Errorf("unknown metric type: %v", metricType)
	}
}

func (s *APIServer) GetSessionList(context.Context, *empty.Empty) (*pb.SessionList, error) {
	s.logger.Info("Received GetSessionList API request")

	var ret pb.SessionList
	for _, pcepSession := range s.pce.sessionList {
		ss := &pb.Session{
			Addr:     pcepSession.peerAddr.AsSlice(),
			State:    pb.SessionState_UP, // Only the UP state in the current specification
			Caps:     []string{},
			IsSynced: pcepSession.isSynced,
		}
		for _, cap := range pcepSession.pccCapabilities {
			ss.Caps = append(ss.Caps, cap.CapStrings()...)
		}
		ss.Caps = slices.Compact(ss.Caps)
		ret.Sessions = append(ret.Sessions, ss)
	}

	s.logger.Debug("Send GetPeerAddrList API reply")
	return &ret, nil
}

func (s *APIServer) GetSRPolicyList(context.Context, *empty.Empty) (*pb.SRPolicyList, error) {
	s.logger.Info("Received GetSRPolicyList API request")

	var ret pb.SRPolicyList
	for ssAddr, policies := range s.pce.SRPolicies() {
		for _, policy := range policies {
			srPolicyData := &pb.SRPolicy{
				PCEPSessionAddr: ssAddr.AsSlice(),
				SegmentList:     make([]*pb.Segment, 0),
				Color:           policy.Color,
				Preference:      policy.Preference,
				PolicyName:      policy.Name,
				SrcAddr:         policy.SrcAddr.AsSlice(),
				DstAddr:         policy.DstAddr.AsSlice(),
			}

			for _, segment := range policy.SegmentList {
				srPolicyData.SegmentList = append(srPolicyData.SegmentList, &pb.Segment{
					Sid: segment.SidString(),
				})
			}

			ret.SRPolicies = append(ret.SRPolicies, srPolicyData)
		}
	}

	s.logger.Debug("Send SRPolicyList API reply")
	return &ret, nil
}

func (s *APIServer) GetTED(context.Context, *empty.Empty) (*pb.TED, error) {
	s.logger.Info("Received GetTED API request")

	ret := &pb.TED{
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
				Asn:        lsNode.ASN,
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
					LocalASN:       lsLink.LocalNode.ASN,
					LocalIP:        lsLink.LocalIP.String(),
					RemoteRouterID: lsLink.RemoteNode.RouterID,
					RemoteASN:      lsLink.RemoteNode.ASN,
					RemoteIP:       lsLink.RemoteIP.String(),
					Metrics:        make([]*pb.Metric, 0, len(lsLink.Metrics)),
					AdjSID:         lsLink.AdjSid,
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

	s.logger.Debug("Send GetTED API reply")
	return ret, nil
}

func (c *APIServer) DeleteSession(ctx context.Context, input *pb.Session) (*pb.RequestStatus, error) {
	ssAddr, ok := netip.AddrFromSlice(input.GetAddr())
	if !ok {
		return nil, fmt.Errorf("invalid address: %v", input.GetAddr())
	}

	s := c.pce
	ss := s.SearchSession(ssAddr, false)
	if ss == nil {
		return nil, fmt.Errorf("no session with address %s found", ssAddr)
	}

	if err := ss.SendClose(pcep.CloseReasonNoExplanationProvided); err != nil {
		return &pb.RequestStatus{IsSuccess: false}, fmt.Errorf("failed to send close message: %v", err)
	}

	// Remove session info from PCE server
	s.closeSession(ss)

	return &pb.RequestStatus{IsSuccess: true}, nil
}
