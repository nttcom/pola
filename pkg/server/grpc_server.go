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

	pb "github.com/nttcom/pola/api/pola/v1"
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

func validateCreateSRPolicy(req *pb.CreateSRPolicyRequest, disablePathCompute bool) error {
	if disablePathCompute {
		return validate(req.GetSrPolicy(), req.GetAsn(), ValidationAddDisablePathCompute)
	}
	return validate(req.GetSrPolicy(), req.GetAsn(), ValidationAdd)
}

func buildSegmentList(s *APIServer, input *pb.CreateSRPolicyRequest, disablePathCompute bool) ([]table.Segment, netip.Addr, netip.Addr, error) {
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment
	var err error

	inputSRPolicy := input.GetSrPolicy()

	if !disablePathCompute {
		if s.pce.ted == nil {
			return nil, netip.Addr{}, netip.Addr{}, errors.New("ted is disabled")
		}

		srcAddr, err = getLoopbackAddr(s.pce, input.GetAsn(), inputSRPolicy.GetSrcRouterId())
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}

		dstAddr, err = getLoopbackAddr(s.pce, input.GetAsn(), inputSRPolicy.GetDstRouterId())
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

func sendSRPolicyRequest(s *APIServer, input *pb.CreateSRPolicyRequest, segmentList []table.Segment, srcAddr, dstAddr netip.Addr) error {
	inputSRPolicy := input.GetSrPolicy()

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPcepSessionAddr())
	if err != nil {
		return fmt.Errorf("failed to get synchronized PCEP session: %w", err)
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
			return fmt.Errorf("failed to send PC update: %w", err)
		}
	} else {
		s.logger.Debug("Request to create SR Policy")
		if err := pcepSession.RequestSRPolicyCreated(srPolicy); err != nil {
			return fmt.Errorf("failed to request SR policy creation: %w", err)
		}
	}

	return nil
}

func (s *APIServer) CreateSRPolicy(ctx context.Context, req *pb.CreateSRPolicyRequest) (*pb.CreateSRPolicyResponse, error) {
	sidvalidate := req.GetSidValidate()
	if err := validateCreateSRPolicy(req, sidvalidate); err != nil {
		return nil, fmt.Errorf("failed to validate SR policy creation: %w", err)
	}

	segmentList, srcAddr, dstAddr, err := buildSegmentList(s, req, sidvalidate)
	if err != nil {
		return nil, fmt.Errorf("failed to build segment list: %w", err)
	}

	if err := sendSRPolicyRequest(s, req, segmentList, srcAddr, dstAddr); err != nil {
		return nil, fmt.Errorf("failed to send SR policy request: %w", err)
	}

	return &pb.CreateSRPolicyResponse{IsSuccess: true}, nil
}

func (s *APIServer) DeleteSRPolicy(ctx context.Context, input *pb.DeleteSRPolicyRequest) (*pb.DeleteSRPolicyResponse, error) {
	err := validate(input.GetSrPolicy(), input.GetAsn(), ValidationDelete)
	if err != nil {
		return &pb.DeleteSRPolicyResponse{IsSuccess: false}, err
	}

	inputSRPolicy := input.GetSrPolicy()
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment

	srcAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
	dstAddr, _ = netip.AddrFromSlice(inputSRPolicy.GetDstAddr())
	for _, segment := range inputSRPolicy.GetSegmentList() {
		seg, err := table.NewSegment(segment.GetSid())
		if err != nil {
			return &pb.DeleteSRPolicyResponse{IsSuccess: false}, err
		}
		segmentList = append(segmentList, seg)
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	s.logger.Info("Received DeleteSRPolicy API request")
	s.logger.Debug("Received paramater", zap.String("input", string(inputJSON)))

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPcepSessionAddr())
	if err != nil {
		return &pb.DeleteSRPolicyResponse{IsSuccess: false}, err
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
		s.logger.Debug("Request to delete SR Policy", zap.Uint32("plspID", id))
		srPolicy.PlspID = id

		if err := pcepSession.RequestSRPolicyDeleted(srPolicy); err != nil {
			return &pb.DeleteSRPolicyResponse{IsSuccess: false}, err
		}
	} else {
		// Invalid SR Policy
		return &pb.DeleteSRPolicyResponse{IsSuccess: false}, fmt.Errorf("requested SR Policy not found")
	}

	return &pb.DeleteSRPolicyResponse{IsSuccess: true}, nil
}

func validate(inputSRPolicy *pb.SRPolicy, asn uint32, validationKind ValidationKind) error {
	if inputSRPolicy == nil {
		return errors.New("validate error, input is nil")
	}
	if asn == 0 {
		return errors.New("validate error, ASN is nil")
	}
	if validateFunc, ok := validator[validationKind]; ok {
		if err := validateFunc(inputSRPolicy, asn); err != nil {
			return fmt.Errorf("validate error: %w", err)
		}
	} else {
		return fmt.Errorf("validate error: unknown validation kind %q", validationKind)
	}

	return nil
}

type ValidationKind string

const (
	ValidationAdd                   ValidationKind = "Add"
	ValidationAddDisablePathCompute ValidationKind = "AddDisablePathCompute"
	ValidationDelete                ValidationKind = "Delete"
)

var validator = map[ValidationKind]func(policy *pb.SRPolicy, asn uint32) error{
	ValidationAdd: func(policy *pb.SRPolicy, asn uint32) error {
		if asn == 0 {
			return errors.New("policy.ASN must not be zero")
		}
		if policy.PcepSessionAddr == nil {
			return errors.New("policy.PCEP session address must not be nil")
		}
		if policy.Color == 0 {
			return errors.New("policy.Color must not be zero")
		}
		if policy.SrcRouterId == "" {
			return errors.New("policy.SrcRouterId must not be empty")
		}
		if policy.DstRouterId == "" {
			return errors.New("policy.DstRouterId must not be empty")
		}
		return nil
	},

	ValidationAddDisablePathCompute: func(policy *pb.SRPolicy, asn uint32) error {
		if policy.PcepSessionAddr == nil {
			return errors.New("policy.PCEP session address must not be nil")
		}
		if len(policy.SrcAddr) == 0 {
			return errors.New("policy.SrcAddr must not be empty")
		}
		if len(policy.DstAddr) == 0 {
			return errors.New("policy.DstAddr must not be empty")
		}
		if len(policy.SegmentList) == 0 {
			return errors.New("policy.SegmentList must not be empty")
		}
		return nil
	},

	ValidationDelete: func(policy *pb.SRPolicy, asn uint32) error {
		if policy.PcepSessionAddr == nil {
			return errors.New("policy.PCEP session address must not be nil")
		}
		if policy.Color == 0 {
			return errors.New("policy.Color must not be zero")
		}
		if len(policy.DstAddr) == 0 {
			return errors.New("policy.DstAddr must not be empty")
		}
		if policy.PolicyName == "" {
			return errors.New("policy.PolicyName must not be empty")
		}
		return nil
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
	case pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT:
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
	case pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC:
		metricType, err := getMetricType(inputSRPolicy.GetMetric())
		if err != nil {
			return nil, err
		}
		segmentList, err = cspf.Cspf(inputSRPolicy.GetSrcRouterId(), inputSRPolicy.GetDstRouterId(), asn, metricType, ted)
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

func (s *APIServer) GetSessionList(ctx context.Context, _ *pb.GetSessionListRequest) (*pb.GetSessionListResponse, error) {
	s.logger.Info("Received GetSessionList API request")

	var sessions []*pb.Session
	for _, pcepSession := range s.pce.sessionList {
		ss := &pb.Session{
			Addr:     pcepSession.peerAddr.AsSlice(),
			State:    pb.SessionState_SESSION_STATE_UP, // Only the UP state in the current specification
			Caps:     []string{},
			IsSynced: pcepSession.isSynced,
		}
		for _, cap := range pcepSession.pccCapabilities {
			ss.Caps = append(ss.Caps, cap.CapStrings()...)
		}
		ss.Caps = slices.Compact(ss.Caps)
		sessions = append(sessions, ss)
	}

	s.logger.Debug("Send GetSessionList API reply")
	return &pb.GetSessionListResponse{
		Sessions: sessions,
	}, nil
}

func (s *APIServer) GetSRPolicyList(ctx context.Context, _ *pb.GetSRPolicyListRequest) (*pb.GetSRPolicyListResponse, error) {
	s.logger.Info("Received GetSRPolicyList API request")

	var srPolicies []*pb.SRPolicy
	for ssAddr, policies := range s.pce.SRPolicies() {
		for _, policy := range policies {
			srPolicy := &pb.SRPolicy{
				PcepSessionAddr: ssAddr.AsSlice(),
				SegmentList:     make([]*pb.Segment, 0),
				Color:           policy.Color,
				Preference:      policy.Preference,
				PolicyName:      policy.Name,
				SrcAddr:         policy.SrcAddr.AsSlice(),
				DstAddr:         policy.DstAddr.AsSlice(),
			}

			for _, segment := range policy.SegmentList {
				srPolicy.SegmentList = append(srPolicy.SegmentList, &pb.Segment{
					Sid: segment.SidString(),
				})
			}

			srPolicies = append(srPolicies, srPolicy)
		}
	}

	s.logger.Debug("Send SRPolicyList API reply")
	return &pb.GetSRPolicyListResponse{
		SrPolicies: srPolicies,
	}, nil
}

func (s *APIServer) GetTED(ctx context.Context, req *pb.GetTEDRequest) (*pb.GetTEDResponse, error) {
	s.logger.Info("Received GetTED API request")

	ret := &pb.GetTEDResponse{
		Enable: true,
	}

	if s.pce == nil || s.pce.ted == nil {
		ret.Enable = false
		return ret, nil
	}

	ret.LsNodes = make([]*pb.LsNode, 0, len(s.pce.ted.Nodes))

	for _, lsNodes := range s.pce.ted.Nodes {
		for _, lsNode := range lsNodes {
			if lsNode == nil {
				continue
			}

			node := &pb.LsNode{
				Asn:        lsNode.ASN,
				RouterId:   lsNode.RouterID,
				IsisAreaId: lsNode.IsisAreaID,
				Hostname:   lsNode.Hostname,
				SrgbBegin:  lsNode.SrgbBegin,
				SrgbEnd:    lsNode.SrgbEnd,
				LsLinks:    make([]*pb.LsLink, 0, len(lsNode.Links)),
				LsPrefixes: make([]*pb.LsPrefix, 0, len(lsNode.Prefixes)),
				LsSrv6Sids: make([]*pb.LsSrv6SID, 0, len(lsNode.SRv6SIDs)),
			}

			for _, lsLink := range lsNode.Links {
				if lsLink == nil || lsLink.LocalNode == nil || lsLink.RemoteNode == nil {
					s.logger.Debug("skip link with nil node", zap.Any("link", lsLink))
					continue
				}

				localIP, _ := lsLink.LocalIP.MarshalText()
				remoteIP, _ := lsLink.RemoteIP.MarshalText()

				link := &pb.LsLink{
					LocalRouterId:  lsLink.LocalNode.RouterID,
					LocalAsn:       lsLink.LocalNode.ASN,
					LocalIp:        string(localIP),
					RemoteRouterId: lsLink.RemoteNode.RouterID,
					RemoteAsn:      lsLink.RemoteNode.ASN,
					RemoteIp:       string(remoteIP),
					Metrics:        make([]*pb.Metric, 0, len(lsLink.Metrics)),
					AdjSid:         lsLink.AdjSid,
				}

				for _, lsMetric := range lsLink.Metrics {
					if lsMetric == nil {
						continue
					}
					metricType, ok := pb.MetricType_value[lsMetric.Type.String()]
					if !ok {
						s.logger.Debug("invalid metric type", zap.String("type", lsMetric.Type.String()))
						continue
					}
					link.Metrics = append(link.Metrics, &pb.Metric{
						Type:  pb.MetricType(metricType),
						Value: lsMetric.Value,
					})
				}

				if lsLink.Srv6EndXSID != nil {
					srv6 := &pb.Srv6EndXSID{
						EndpointBehavior: uint32(lsLink.Srv6EndXSID.EndpointBehavior),
						Sids:             make([]*pb.SID, 0, len(lsLink.Srv6EndXSID.Sids)),
						SidStructure: &pb.SidStructure{
							LocalBlock: uint32(lsLink.Srv6EndXSID.Srv6SIDStructure.LocalBlock),
							LocalNode:  uint32(lsLink.Srv6EndXSID.Srv6SIDStructure.LocalNode),
							LocalFunc:  uint32(lsLink.Srv6EndXSID.Srv6SIDStructure.LocalFunc),
							LocalArg:   uint32(lsLink.Srv6EndXSID.Srv6SIDStructure.LocalArg),
						},
					}

					for _, sid := range lsLink.Srv6EndXSID.Sids {
						if sid == "" {
							continue
						}
						srv6.Sids = append(srv6.Sids, &pb.SID{Sid: sid})
					}

					link.Srv6EndXSid = srv6
				}

				node.LsLinks = append(node.LsLinks, link)
			}

			for _, lsPrefix := range lsNode.Prefixes {
				if lsPrefix == nil {
					continue
				}
				node.LsPrefixes = append(node.LsPrefixes, &pb.LsPrefix{
					Prefix:   lsPrefix.Prefix.String(),
					SidIndex: lsPrefix.SidIndex,
				})
			}

			for _, lsSrv6SID := range lsNode.SRv6SIDs {
				if lsSrv6SID == nil {
					continue
				}
				srv6SID := &pb.LsSrv6SID{
					Sids:         make([]*pb.SID, 0, len(lsSrv6SID.Sids)),
					MultiTopoIds: make([]*pb.MultiTopoID, 0, len(lsSrv6SID.MultiTopoIDs)),
				}

				for _, sid := range lsSrv6SID.Sids {
					if sid == "" {
						continue
					}
					srv6SID.Sids = append(srv6SID.Sids, &pb.SID{Sid: sid})
				}

				for _, topoID := range lsSrv6SID.MultiTopoIDs {
					srv6SID.MultiTopoIds = append(srv6SID.MultiTopoIds, &pb.MultiTopoID{
						MultiTopoId: topoID,
					})
				}

				if lsSrv6SID.EndpointBehavior != (table.EndpointBehavior{}) {
					srv6SID.EndpointBehavior = &pb.EndpointBehavior{
						Behavior:  uint32(lsSrv6SID.EndpointBehavior.Behavior),
						Flags:     uint32(lsSrv6SID.EndpointBehavior.Flags),
						Algorithm: uint32(lsSrv6SID.EndpointBehavior.Algorithm),
					}
				}

				srv6SID.SidStructure = &pb.SidStructure{
					LocalBlock: uint32(lsSrv6SID.SIDStructure.LocalBlock),
					LocalNode:  uint32(lsSrv6SID.SIDStructure.LocalNode),
					LocalFunc:  uint32(lsSrv6SID.SIDStructure.LocalFunc),
					LocalArg:   uint32(lsSrv6SID.SIDStructure.LocalArg),
				}

				node.LsSrv6Sids = append(node.LsSrv6Sids, srv6SID)
			}

			ret.LsNodes = append(ret.LsNodes, node)
		}
	}

	s.logger.Debug("Send GetTED API reply")
	return ret, nil
}

func (s *APIServer) DeleteSession(ctx context.Context, req *pb.DeleteSessionRequest) (*pb.DeleteSessionResponse, error) {
	ssAddr, ok := netip.AddrFromSlice(req.GetAddr())
	if !ok {
		return nil, fmt.Errorf("invalid address: %v", req.GetAddr())
	}

	pce := s.pce
	ss := pce.SearchSession(ssAddr, false)
	if ss == nil {
		return nil, fmt.Errorf("no session with address %s found", ssAddr)
	}

	if err := ss.SendClose(pcep.CloseReasonNoExplanationProvided); err != nil {
		return &pb.DeleteSessionResponse{IsSuccess: false}, fmt.Errorf("failed to send close message: %v", err)
	}

	// Remove session info from PCE server
	pce.closeSession(ss)

	return &pb.DeleteSessionResponse{IsSuccess: true}, nil
}
