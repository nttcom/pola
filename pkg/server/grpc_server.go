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
	s.logger.Debug("Received parameter", zap.String("input", string(inputJSON)))

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
		return errors.New("validate error, ASN must not be zero")
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

// GetTED returns the TED information in a structured way.
func (s *APIServer) GetTED(ctx context.Context, req *pb.GetTEDRequest) (*pb.GetTEDResponse, error) {
	s.logger.Info("Received GetTED API request")

	ret := &pb.GetTEDResponse{Enable: true}
	if s.pce == nil || s.pce.ted == nil {
		ret.Enable = false
		return ret, nil
	}

	for _, nodes := range s.pce.ted.Nodes {
		for _, node := range nodes {
			if n := convertLsNode(node, s.logger); n != nil {
				ret.LsNodes = append(ret.LsNodes, n)
			}
		}
	}

	s.logger.Debug("Send GetTED API reply")
	return ret, nil
}

// convertLsNode converts a table.LsNode to a protobuf LsNode.
func convertLsNode(lsNode *table.LsNode, logger *zap.Logger) *pb.LsNode {
	if lsNode == nil {
		return nil
	}

	return &pb.LsNode{
		Asn:        lsNode.ASN,
		RouterId:   lsNode.RouterID,
		IsisAreaId: lsNode.IsisAreaID,
		Hostname:   lsNode.Hostname,
		SrgbBegin:  lsNode.SrgbBegin,
		SrgbEnd:    lsNode.SrgbEnd,
		LsLinks:    convertLsLinks(lsNode.Links, logger),
		LsPrefixes: convertLsPrefixes(lsNode.Prefixes),
		LsSrv6Sids: convertLsSrv6SIDs(lsNode.SRv6SIDs),
	}
}

// convertLsLinks converts a slice of table.LsLink to protobuf LsLink.
func convertLsLinks(links []*table.LsLink, logger *zap.Logger) []*pb.LsLink {
	if links == nil {
		return nil
	}
	result := make([]*pb.LsLink, 0, len(links))
	for _, link := range links {
		if link == nil || link.LocalNode == nil || link.RemoteNode == nil {
			logger.Debug("skip link with nil node", zap.Any("link", link))
			continue
		}
		result = append(result, buildLsLink(link))
	}
	return result
}

// buildLsLink converts a single table.LsLink to protobuf LsLink.
func buildLsLink(link *table.LsLink) *pb.LsLink {
	localIP, _ := link.LocalIP.MarshalText()
	remoteIP, _ := link.RemoteIP.MarshalText()

	pbLink := &pb.LsLink{
		LocalRouterId:  link.LocalNode.RouterID,
		LocalAsn:       link.LocalNode.ASN,
		LocalIp:        string(localIP),
		RemoteRouterId: link.RemoteNode.RouterID,
		RemoteAsn:      link.RemoteNode.ASN,
		RemoteIp:       string(remoteIP),
		Metrics:        convertMetrics(link.Metrics),
		AdjSid:         link.AdjSid,
	}

	if link.Srv6EndXSID != nil {
		pbLink.Srv6EndXSid = convertSrv6EndXSID(link.Srv6EndXSID)
	}
	return pbLink
}

// convertMetrics converts a slice of table.Metric to protobuf Metric.
func convertMetrics(metrics []*table.Metric) []*pb.Metric {
	if metrics == nil {
		return nil
	}
	result := make([]*pb.Metric, 0, len(metrics))
	for _, m := range metrics {
		if m != nil {
			if mt, ok := pb.MetricType_value[m.Type.String()]; ok {
				result = append(result, &pb.Metric{Type: pb.MetricType(mt), Value: m.Value})
			}
		}
	}
	return result
}

// convertLsPrefixes converts a slice of table.LsPrefix to protobuf LsPrefix.
func convertLsPrefixes(prefixes []*table.LsPrefix) []*pb.LsPrefix {
	if prefixes == nil {
		return nil
	}
	result := make([]*pb.LsPrefix, 0, len(prefixes))
	for _, p := range prefixes {
		if p != nil {
			result = append(result, &pb.LsPrefix{Prefix: p.Prefix.String(), SidIndex: p.SidIndex})
		}
	}
	return result
}

// convertLsSrv6SIDs converts a slice of table.LsSrv6SID to protobuf LsSrv6SID.
func convertLsSrv6SIDs(sids []*table.LsSrv6SID) []*pb.LsSrv6SID {
	if sids == nil {
		return nil
	}
	result := make([]*pb.LsSrv6SID, 0, len(sids))
	for _, s := range sids {
		if s != nil {
			result = append(result, buildLsSrv6SID(s))
		}
	}
	return result
}

// buildLsSrv6SID converts a single table.LsSrv6SID to protobuf LsSrv6SID.
func buildLsSrv6SID(s *table.LsSrv6SID) *pb.LsSrv6SID {
	pbSID := &pb.LsSrv6SID{
		Sids:         make([]*pb.SID, 0, len(s.Sids)),
		MultiTopoIds: make([]*pb.MultiTopoID, 0, len(s.MultiTopoIDs)),
		SidStructure: &pb.SidStructure{
			LocalBlock: uint32(s.SIDStructure.LocalBlock),
			LocalNode:  uint32(s.SIDStructure.LocalNode),
			LocalFunc:  uint32(s.SIDStructure.LocalFunc),
			LocalArg:   uint32(s.SIDStructure.LocalArg),
		},
	}

	for _, sid := range s.Sids {
		if sid != "" {
			pbSID.Sids = append(pbSID.Sids, &pb.SID{Sid: sid})
		}
	}

	for _, topoID := range s.MultiTopoIDs {
		pbSID.MultiTopoIds = append(pbSID.MultiTopoIds, &pb.MultiTopoID{MultiTopoId: topoID})
	}

	if s.EndpointBehavior != (table.EndpointBehavior{}) {
		pbSID.EndpointBehavior = &pb.EndpointBehavior{
			Behavior:  uint32(s.EndpointBehavior.Behavior),
			Flags:     uint32(s.EndpointBehavior.Flags),
			Algorithm: uint32(s.EndpointBehavior.Algorithm),
		}
	}

	return pbSID
}

// convertSrv6EndXSID converts table.Srv6EndXSID to protobuf Srv6EndXSID.
func convertSrv6EndXSID(sid *table.Srv6EndXSID) *pb.Srv6EndXSID {
	pbSID := &pb.Srv6EndXSID{
		EndpointBehavior: uint32(sid.EndpointBehavior),
		Sids:             make([]*pb.SID, 0, len(sid.Sids)),
		SidStructure: &pb.SidStructure{
			LocalBlock: uint32(sid.Srv6SIDStructure.LocalBlock),
			LocalNode:  uint32(sid.Srv6SIDStructure.LocalNode),
			LocalFunc:  uint32(sid.Srv6SIDStructure.LocalFunc),
			LocalArg:   uint32(sid.Srv6SIDStructure.LocalArg),
		},
	}

	for _, s := range sid.Sids {
		if s != "" {
			pbSID.Sids = append(pbSID.Sids, &pb.SID{Sid: s})
		}
	}

	return pbSID
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
