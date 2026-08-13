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
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/cspf"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
	"go.uber.org/zap"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
	a, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("failed to parse gRPC address %q: %w", address, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("failed to convert gRPC port %q: %w", port, err)
	}
	if p < 0 || p > math.MaxUint16 {
		return errors.New("invalid gRPC listen port")
	}
	localAddr := netip.AddrPortFrom(a, uint16(p))

	grpcListener, err := net.Listen("tcp", localAddr.String())
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %s: %w", localAddr.String(), err)
	}
	s.logger.Info("Start listening on gRPC port", zap.String("listenInfo", grpcListener.Addr().String()))
	return s.grpcServer.Serve(grpcListener)
}

func validateCreateSRPolicy(req *pb.CreateSRPolicyRequest, disablePathCompute bool) error {
	if disablePathCompute {
		return validate(req.GetSrPolicy(), req.GetAsn(), ValidationAddDisablePathCompute)
	}
	return validate(req.GetSrPolicy(), req.GetAsn(), ValidationAdd)
}

// parseSidStructure parses a comma-separated SID structure string (e.g. "32,16,0,80")
// into a []uint8 slice suitable for table.SegmentSRv6.Structure.
// Returns nil for empty input.
func parseSidStructure(s string) ([]uint8, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid SID structure %q", s)
	}

	result := make([]uint8, 4)
	for i, p := range parts {
		v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid SID structure %q: %w", s, err)
		}
		result[i] = uint8(v)
	}
	return result, nil
}

// enrichSRv6Segment applies gRPC overrides to an SRv6 segment.
func enrichSRv6Segment(srv6Seg table.SegmentSRv6, segment *pb.Segment, usidMode bool) (table.SegmentSRv6, error) {
	if usidMode {
		srv6Seg.USid = true
	}
	if structure, err := parseSidStructure(segment.GetSidStructure()); err != nil {
		return srv6Seg, err
	} else if structure != nil {
		srv6Seg.Structure = table.SIDStructureBytes(structure)
	}
	if s := segment.GetLocalAddr(); s != "" {
		la, err := netip.ParseAddr(s)
		if err != nil {
			return srv6Seg, fmt.Errorf("invalid localAddr %q for SID %s: %w", s, segment.GetSid(), err)
		}
		srv6Seg.LocalAddr = la
	}
	if s := segment.GetRemoteAddr(); s != "" {
		ra, err := netip.ParseAddr(s)
		if err != nil {
			return srv6Seg, fmt.Errorf("invalid remoteAddr %q for SID %s: %w", s, segment.GetSid(), err)
		}
		srv6Seg.RemoteAddr = ra
	}
	return srv6Seg, nil
}

// enrichSRMPLSSegment applies gRPC NAI information to an SR-MPLS segment.
func enrichSRMPLSSegment(mplsSeg table.SegmentSRMPLS, segment *pb.Segment) (table.SegmentSRMPLS, error) {
	if s := segment.GetLocalAddr(); s != "" {
		la, err := netip.ParseAddr(s)
		if err != nil {
			return mplsSeg, fmt.Errorf("invalid localAddr %q for SID %s: %w", s, segment.GetSid(), err)
		}
		mplsSeg.LocalAddr = la
	}
	if s := segment.GetRemoteAddr(); s != "" {
		ra, err := netip.ParseAddr(s)
		if err != nil {
			return mplsSeg, fmt.Errorf("invalid remoteAddr %q for SID %s: %w", s, segment.GetSid(), err)
		}
		mplsSeg.RemoteAddr = ra
	}
	return mplsSeg, nil
}

// newEnrichedSegment converts a gRPC Segment to a table.Segment.
func newEnrichedSegment(segment *pb.Segment, usidMode bool) (table.Segment, error) {
	seg, err := table.NewSegment(segment.GetSid())
	if err != nil {
		return nil, err
	}
	if v, ok := seg.(table.SegmentSRv6); ok {
		return enrichSRv6Segment(v, segment, usidMode)
	}
	return enrichSRMPLSSegment(seg.(table.SegmentSRMPLS), segment)
}

func buildSegmentList(s *APIServer, input *pb.CreateSRPolicyRequest, disablePathCompute bool) ([]table.Segment, netip.Addr, netip.Addr, error) {
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment
	var err error

	inputSRPolicy := input.GetSrPolicy()

	if !disablePathCompute {
		ted := s.pce.TED()
		if ted == nil {
			return nil, netip.Addr{}, netip.Addr{}, errors.New("ted is disabled")
		}

		if len(ted.Nodes) == 0 {
			return nil, netip.Addr{}, netip.Addr{}, errors.New("no node in TED")
		}

		// Request ASN check
		for _, node := range ted.Nodes {
			if node.ASN != input.GetAsn() {
				return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf("request ASN %d does not match ted ASN %d", input.GetAsn(), node.ASN)
			}
			break // All nodes are expected to share the same ASN; check only the first
		}

		srcAddr, err = getLoopbackAddr(ted, inputSRPolicy.GetSrcRouterId())
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}

		dstAddr, err = getLoopbackAddr(ted, inputSRPolicy.GetDstRouterId())
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}

		segmentList, err = getSegmentList(inputSRPolicy, ted, s.usidMode)
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}
	} else {
		var ok bool
		srcAddr, ok = netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
		if !ok {
			return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf(
				"invalid source address %v",
				inputSRPolicy.GetSrcAddr(),
			)
		}

		dstAddr, ok = netip.AddrFromSlice(inputSRPolicy.GetDstAddr())
		if !ok {
			return nil, netip.Addr{}, netip.Addr{}, fmt.Errorf(
				"invalid destination address %v",
				inputSRPolicy.GetDstAddr(),
			)
		}

		for _, segment := range inputSRPolicy.GetSegmentList() {
			seg, err := newEnrichedSegment(segment, s.usidMode)
			if err != nil {
				return nil, netip.Addr{}, netip.Addr{}, err
			}
			segmentList = append(segmentList, seg)
		}
	}

	return segmentList, srcAddr, dstAddr, nil
}

// resolveSRPolicyIntent resolves the candidate-path type and metric per RFC 9256 §2.4.2.
func resolveSRPolicyIntent(inputSRPolicy *pb.SRPolicy, disablePathCompute bool) (table.PolicyType, table.MetricType, error) {
	if disablePathCompute {
		// disable_path_compute uses the given SegmentList as an explicit candidate path,
		// regardless of the requested policy type.
		return table.PolicyTypeExplicit, table.UnspecifiedMetric, nil
	}

	switch inputSRPolicy.GetType() {
	case pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT:
		return table.PolicyTypeExplicit, table.UnspecifiedMetric, nil
	case pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC:
		metricType, err := getMetricType(inputSRPolicy.GetMetric())
		if err != nil {
			return "", table.UnspecifiedMetric, err
		}
		return table.PolicyTypeDynamic, metricType, nil
	default:
		return "", table.UnspecifiedMetric, errors.New("undefined SR Policy type")
	}
}

func sendSRPolicyRequest(s *APIServer, input *pb.CreateSRPolicyRequest, segmentList []table.Segment, srcAddr, dstAddr netip.Addr, disablePathCompute bool) error {
	inputSRPolicy := input.GetSrPolicy()

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPcepSessionAddr())
	if err != nil {
		return fmt.Errorf("failed to get synchronized PCEP session: %w", err)
	}

	policyType, metricType, err := resolveSRPolicyIntent(inputSRPolicy, disablePathCompute)
	if err != nil {
		return fmt.Errorf("failed to resolve SR policy type: %w", err)
	}

	srPolicy := table.SRPolicy{
		Name:        inputSRPolicy.GetPolicyName(),
		SegmentList: segmentList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       inputSRPolicy.GetColor(),
		Preference:  100,
		Type:        policyType,
		Metric:      metricType,
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
	disablePathCompute := req.GetDisablePathCompute()
	if err := validateCreateSRPolicy(req, disablePathCompute); err != nil {
		return nil, fmt.Errorf("failed to validate SR policy creation: %w", err)
	}

	segmentList, srcAddr, dstAddr, err := buildSegmentList(s, req, disablePathCompute)
	if err != nil {
		return nil, fmt.Errorf("failed to build segment list: %w", err)
	}

	if err := s.validateSIDs(req, segmentList); err != nil {
		return nil, err
	}

	if err := sendSRPolicyRequest(s, req, segmentList, srcAddr, dstAddr, disablePathCompute); err != nil {
		return nil, fmt.Errorf("failed to send SR policy request: %w", err)
	}

	return &pb.CreateSRPolicyResponse{IsSuccess: true}, nil
}

func (s *APIServer) validateSIDs(req *pb.CreateSRPolicyRequest, segmentList []table.Segment) error {
	policy := req.GetSrPolicy()

	// Reject out-of-range labels before the validation skip paths.
	if invalid := table.OutOfRangeSRMPLSLabels(segmentList); len(invalid) > 0 {
		descriptions := make([]string, 0, len(invalid))
		for _, s := range invalid {
			descriptions = append(descriptions, s.String())
		}
		return status.Errorf(codes.InvalidArgument,
			"segment list contains SR-MPLS labels outside the valid range 0-%d: %s",
			table.MPLSLabelMax, strings.Join(descriptions, ", "))
	}

	if table.HasUnknownSegmentType(segmentList) {
		return status.Errorf(codes.InvalidArgument, "segment list contains a segment with an unrecognized SID family")
	}

	if table.HasMixedSegmentTypes(segmentList) {
		return status.Errorf(codes.InvalidArgument, "segment list contains mixed SR-MPLS and SRv6 SIDs")
	}

	// Skip TED lookup for dynamically computed paths.
	if policy.GetType() == pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC && !req.GetDisablePathCompute() {
		return nil
	}

	if req.GetNoSidValidate() {
		s.logger.Warn("skipping SID validation: no_sid_validate specified",
			zap.String("policyName", policy.GetPolicyName()),
			zap.Uint32("color", policy.GetColor()),
		)
		return nil
	}

	ted := s.pce.TED()
	if ted == nil {
		return status.Errorf(codes.FailedPrecondition,
			"TED is not enabled, SID validation cannot be performed")
	}
	if len(ted.Nodes) == 0 {
		return status.Errorf(codes.FailedPrecondition,
			"TED is enabled but empty (not yet synchronized), SID validation cannot be performed")
	}

	missingSegments := table.MissingSegments(ted, segmentList)
	if len(missingSegments) == 0 {
		return nil
	}

	descriptions := make([]string, 0, len(missingSegments))
	for _, m := range missingSegments {
		descriptions = append(descriptions, m.String())
	}
	return status.Errorf(codes.InvalidArgument,
		"SID validation failed, the following SIDs are not found in TED: %s", strings.Join(descriptions, ", "))
}

func (s *APIServer) DeleteSRPolicy(ctx context.Context, input *pb.DeleteSRPolicyRequest) (*pb.DeleteSRPolicyResponse, error) {
	err := validate(input.GetSrPolicy(), input.GetAsn(), ValidationDelete)
	if err != nil {
		return &pb.DeleteSRPolicyResponse{IsSuccess: false}, err
	}

	inputSRPolicy := input.GetSrPolicy()
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment

	if len(inputSRPolicy.GetSrcAddr()) > 0 {
		var ok bool
		srcAddr, ok = netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
		if !ok {
			return &pb.DeleteSRPolicyResponse{
				IsSuccess: false,
			}, errors.New("invalid source address")
		}
	}

	dstAddr, ok := netip.AddrFromSlice(inputSRPolicy.GetDstAddr())
	if !ok {
		return &pb.DeleteSRPolicyResponse{
			IsSuccess: false,
		}, errors.New("invalid destination address")
	}

	for _, segment := range inputSRPolicy.GetSegmentList() {
		seg, err := newEnrichedSegment(segment, s.usidMode)
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
	if validationKind == ValidationAdd && asn == 0 {
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
		if policy.Color == 0 {
			return errors.New("policy.Color must not be zero")
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
	pcepSessionAddr, ok := netip.AddrFromSlice(addr)
	if !ok {
		return nil, fmt.Errorf("invalid PCEP session address: %v", addr)
	}

	pcepSession := pce.SearchSession(pcepSessionAddr, true)
	if pcepSession == nil {
		return nil, fmt.Errorf("no synced session with %s", pcepSessionAddr)
	}
	return pcepSession, nil
}

func getLoopbackAddr(ted *table.LsTED, routerID string) (netip.Addr, error) {
	node, ok := ted.Nodes[routerID]
	if !ok {
		return netip.Addr{}, fmt.Errorf("no node with router ID %s", routerID)
	}
	return node.LoopbackAddr()
}

func getSegmentList(inputSRPolicy *pb.SRPolicy, ted *table.LsTED, usidMode bool) ([]table.Segment, error) {
	var segmentList []table.Segment

	switch inputSRPolicy.GetType() {
	case pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT:
		if len(inputSRPolicy.GetSegmentList()) == 0 {
			return nil, errors.New("no segments in SRPolicy input")
		}
		for _, segment := range inputSRPolicy.GetSegmentList() {
			sid, err := newEnrichedSegment(segment, usidMode)
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
		pbWPs := inputSRPolicy.GetWaypoints()
		if len(pbWPs) > 0 {
			// Convert to table.Waypoint
			waypoints := make([]table.Waypoint, 0, len(pbWPs))
			for _, w := range pbWPs {
				waypoints = append(waypoints, table.Waypoint{
					RouterID: w.GetRouterId(),
					SID:      w.GetSid(), // optional
				})
			}

			return cspf.CSPFWithLooseSourceRouting(
				inputSRPolicy.GetSrcRouterId(),
				inputSRPolicy.GetDstRouterId(),
				waypoints,
				metricType,
				ted,
			)
		} else {
			return cspf.CSPF(
				inputSRPolicy.GetSrcRouterId(),
				inputSRPolicy.GetDstRouterId(),
				metricType,
				ted,
			)
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

	pcepSessions := s.pce.Sessions()
	slices.SortFunc(pcepSessions, func(a, b *Session) int { return a.peerAddr.Compare(b.peerAddr) })

	var sessions []*pb.Session
	for _, pcepSession := range pcepSessions {
		ss := &pb.Session{
			Addr:     pcepSession.peerAddr.AsSlice(),
			State:    pb.SessionState_SESSION_STATE_UP, // Only the UP state in the current specification
			IsSynced: pcepSession.IsSynced(),
		}
		seenCapabilities := make(map[string]struct{})
		for _, cap := range pcepSession.AdvertisedCapabilities() {
			capabilityKey := fmt.Sprintf("%d:%s", cap.Type(), cap.Serialize())
			if _, ok := seenCapabilities[capabilityKey]; ok {
				continue
			}
			seenCapabilities[capabilityKey] = struct{}{}
			ss.Capabilities = append(ss.Capabilities, buildCapability(cap))
		}
		sessions = append(sessions, ss)
	}

	s.logger.Debug("Send GetSessionList API reply")
	return &pb.GetSessionListResponse{
		Sessions: sessions,
	}, nil
}

func buildCapability(cap pcep.CapabilityInterface) *pb.Capability {
	c := &pb.Capability{Type: capabilityType(cap.Type())}
	switch tlv := cap.(type) {
	case *pcep.StatefulPCECapability:
		c.Detail = &pb.Capability_Stateful{Stateful: &pb.StatefulCapability{
			LspUpdate:            tlv.LSPUpdateCapability,
			IncludeDbVersion:     tlv.IncludeDBVersion,
			LspInstantiation:     tlv.LSPInstantiationCapability,
			TriggeredResync:      tlv.TriggeredResync,
			DeltaLspSync:         tlv.DeltaLSPSyncCapability,
			TriggeredInitialSync: tlv.TriggeredInitialSync,
			Color:                tlv.ColorCapability,
		}}
	case *pcep.SRPCECapability:
		c.Detail = &pb.Capability_Sr{Sr: &pb.SrCapability{
			UnlimitedMsd: tlv.HasUnlimitedMaxSIDDepth,
			NaiSupported: tlv.IsNAISupported,
			Msd:          uint32(tlv.MaximumSidDepth),
		}}
	case *pcep.SRv6PCECapability:
		c.Detail = &pb.Capability_Srv6{Srv6: &pb.Srv6Capability{
			NaiSupported: tlv.IsNAISupported,
		}}
	case *pcep.PathSetupTypeCapability:
		psts := make([]uint32, len(tlv.PathSetupTypes))
		for i, pst := range tlv.PathSetupTypes {
			psts[i] = uint32(pst)
		}
		c.Detail = &pb.Capability_PathSetupType{PathSetupType: &pb.PathSetupTypeCapability{
			PathSetupTypes: psts,
		}}
	case *pcep.AssocTypeList:
		assocTypes := make([]uint32, len(tlv.AssocTypes))
		for i, at := range tlv.AssocTypes {
			assocTypes[i] = uint32(at)
		}
		c.Detail = &pb.Capability_AssocTypeList{AssocTypeList: &pb.AssocTypeListCapability{
			AssocTypes: assocTypes,
		}}
	case *pcep.LSPDBVersion:
		c.Detail = &pb.Capability_LspDbVersion{LspDbVersion: &pb.LspDbVersionCapability{
			VersionNumber: tlv.VersionNumber,
		}}
	case *pcep.MultipathCapability:
		c.Detail = &pb.Capability_Multipath{Multipath: &pb.MultipathCapability{
			MaxMultipaths: uint32(tlv.MaxMultipaths),
			Weighted:      tlv.IsWeightedSupported,
			OppositeDir:   tlv.IsOppositeDirSupported,
			ForwardClass:  tlv.IsForwardClassSupported,
			CompositePath: tlv.IsCompositePathSupported,
		}}
	case *pcep.VendorInformation:
		c.Detail = &pb.Capability_VendorInformation{VendorInformation: &pb.VendorInformationCapability{
			EnterpriseNumber: uint32(tlv.EnterpriseNumber),
		}}
	case *pcep.UnknownTLV:
		c.Detail = &pb.Capability_Unknown{Unknown: &pb.UnknownCapability{
			TlvType: uint32(tlv.Typ),
		}}
	}
	return c
}

func capabilityType(t pcep.TLVType) pb.CapabilityType {
	switch t {
	case pcep.TLVStatefulPCECapability:
		return pb.CapabilityType_CAPABILITY_TYPE_STATEFUL
	case pcep.TLVSRPCECapability:
		return pb.CapabilityType_CAPABILITY_TYPE_SR
	case pcep.TLVSRv6PCECapability:
		return pb.CapabilityType_CAPABILITY_TYPE_SRV6
	case pcep.TLVPathSetupTypeCapability:
		return pb.CapabilityType_CAPABILITY_TYPE_PATH_SETUP_TYPE
	case pcep.TLVAssocTypeList:
		return pb.CapabilityType_CAPABILITY_TYPE_ASSOC_TYPE_LIST
	case pcep.TLVLSPDBVersion:
		return pb.CapabilityType_CAPABILITY_TYPE_LSP_DB_VERSION
	case pcep.TLVMultipathCap:
		return pb.CapabilityType_CAPABILITY_TYPE_MULTIPATH
	case pcep.TLVVendorInformation:
		return pb.CapabilityType_CAPABILITY_TYPE_VENDOR_INFORMATION
	default:
		return pb.CapabilityType_CAPABILITY_TYPE_UNKNOWN
	}
}

func (s *APIServer) GetSRPolicyList(ctx context.Context, req *pb.GetSRPolicyListRequest) (*pb.GetSRPolicyListResponse, error) {
	s.logger.Info("Received GetSRPolicyList API request")

	var filterAddr netip.Addr
	if raw := req.GetSessionAddr(); len(raw) > 0 {
		var ok bool
		filterAddr, ok = netip.AddrFromSlice(raw)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid session filter address %v", raw)
		}
	}

	policiesByPeer := s.pce.SRPolicies()
	peerAddrs := make([]netip.Addr, 0, len(policiesByPeer))
	for peerAddr := range policiesByPeer {
		if filterAddr.IsValid() && peerAddr != filterAddr {
			continue
		}
		peerAddrs = append(peerAddrs, peerAddr)
	}
	slices.SortFunc(peerAddrs, func(a, b netip.Addr) int { return a.Compare(b) })

	routerIDIndex := buildRouterIDIndex(s.pce.TED())

	sessions := make([]*pb.Session, 0, len(peerAddrs))
	for _, peerAddr := range peerAddrs {
		pbPolicies := make([]*pb.SRPolicy, 0, len(policiesByPeer[peerAddr]))
		for _, policy := range policiesByPeer[peerAddr] {
			pbPolicies = append(pbPolicies, s.buildPBSRPolicy(peerAddr, policy, routerIDIndex))
		}
		slices.SortFunc(pbPolicies, func(a, b *pb.SRPolicy) int {
			if a.GetColor() < b.GetColor() {
				return -1
			}
			if a.GetColor() > b.GetColor() {
				return 1
			}
			if a.GetPlspId() < b.GetPlspId() {
				return -1
			}
			if a.GetPlspId() > b.GetPlspId() {
				return 1
			}
			return strings.Compare(a.GetPolicyName(), b.GetPolicyName())
		})

		sessions = append(sessions, &pb.Session{
			Addr:       peerAddr.AsSlice(),
			SrPolicies: pbPolicies,
		})
	}

	s.logger.Debug("Send SRPolicyList API reply")
	return &pb.GetSRPolicyListResponse{
		Sessions: sessions,
	}, nil
}

func (s *APIServer) buildPBSRPolicy(peerAddr netip.Addr, policy *table.SRPolicy, routerIDIndex map[netip.Addr]string) *pb.SRPolicy {
	srPolicy := &pb.SRPolicy{
		PcepSessionAddr: peerAddr.AsSlice(),
		SegmentList:     make([]*pb.Segment, 0, len(policy.SegmentList)),
		Color:           policy.Color,
		Preference:      policy.Preference,
		PolicyName:      policy.Name,
		SrcAddr:         policy.SrcAddr.AsSlice(),
		DstAddr:         policy.DstAddr.AsSlice(),
		PlspId:          policy.PlspID,
		LspId:           uint32(policy.LSPID),
		State:           toPBPolicyState(policy.State),
		Type:            toPBPolicyType(policy.Type),
		Metric:          toPBMetricType(policy.Metric),
	}

	srPolicy.SrcRouterId = routerIDIndex[policy.SrcAddr]
	srPolicy.DstRouterId = routerIDIndex[policy.DstAddr]

	for _, segment := range policy.SegmentList {
		srPolicy.SegmentList = append(srPolicy.SegmentList, convertSegment(segment))
	}

	return srPolicy
}

func toPBPolicyType(polType table.PolicyType) pb.SRPolicyType {
	switch polType {
	case table.PolicyTypeExplicit:
		return pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT
	case table.PolicyTypeDynamic:
		return pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC
	default:
		return pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED
	}
}

func toPBMetricType(metricType table.MetricType) pb.MetricType {
	switch metricType {
	case table.IGPMetric:
		return pb.MetricType_METRIC_TYPE_IGP
	case table.TEMetric:
		return pb.MetricType_METRIC_TYPE_TE
	case table.DelayMetric:
		return pb.MetricType_METRIC_TYPE_DELAY
	case table.HopcountMetric:
		return pb.MetricType_METRIC_TYPE_HOPCOUNT
	default:
		return pb.MetricType_METRIC_TYPE_UNSPECIFIED
	}
}

func toPBPolicyState(state table.PolicyState) pb.SRPolicyState {
	switch state {
	case table.PolicyDown:
		return pb.SRPolicyState_SR_POLICY_STATE_DOWN
	case table.PolicyUp:
		return pb.SRPolicyState_SR_POLICY_STATE_UP
	case table.PolicyActive:
		return pb.SRPolicyState_SR_POLICY_STATE_ACTIVE
	case table.PolicyUnknown:
		return pb.SRPolicyState_SR_POLICY_STATE_UNKNOWN
	default:
		return pb.SRPolicyState_SR_POLICY_STATE_UNSPECIFIED
	}
}

// buildRouterIDIndex builds a loopback-address-to-router-ID index from the TED.
func buildRouterIDIndex(ted *table.LsTED) map[netip.Addr]string {
	if ted == nil {
		return nil
	}

	index := make(map[netip.Addr]string, len(ted.Nodes))
	for _, node := range ted.Nodes {
		if node == nil {
			continue
		}
		for _, prefix := range node.Prefixes {
			if prefix.Prefix.Bits() == prefix.Prefix.Addr().BitLen() {
				index[prefix.Prefix.Addr()] = node.RouterID
			}
		}
	}
	return index
}

// buildAddressRouterIDIndex builds an index from prefix addresses to router IDs.
func buildAddressRouterIDIndex(ted *table.LsTED) map[netip.Addr]string {
	if ted == nil {
		return nil
	}
	index := make(map[netip.Addr]string)
	for routerID, node := range ted.Nodes {
		if node == nil {
			continue
		}
		for _, prefix := range node.Prefixes {
			index[prefix.Prefix.Addr()] = routerID
		}
	}
	return index
}

func convertSegment(seg table.Segment) *pb.Segment {
	pbSeg := &pb.Segment{Sid: seg.SidString()}
	switch v := seg.(type) {
	case table.SegmentSRv6:
		if v.LocalAddr.IsValid() {
			pbSeg.LocalAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			pbSeg.RemoteAddr = v.RemoteAddr.String()
		}
		if len(v.Structure) == 4 {
			pbSeg.SidStructure = fmt.Sprintf("%d,%d,%d,%d", v.Structure[0], v.Structure[1], v.Structure[2], v.Structure[3])
		}
	case table.SegmentSRMPLS:
		if v.LocalAddr.IsValid() {
			pbSeg.LocalAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			pbSeg.RemoteAddr = v.RemoteAddr.String()
		}
	}
	return pbSeg
}

// GetTED returns the TED information in a structured way.
func (s *APIServer) GetTED(ctx context.Context, req *pb.GetTEDRequest) (*pb.GetTEDResponse, error) {
	s.logger.Info("Received GetTED API request")

	ret := &pb.GetTEDResponse{Enable: true}
	if s.pce == nil {
		ret.Enable = false
		return ret, nil
	}
	ted := s.pce.TED()
	if ted == nil {
		ret.Enable = false
		return ret, nil
	}

	for _, node := range ted.Nodes {
		if n := convertLsNode(node, s.logger); n != nil {
			ret.LsNodes = append(ret.LsNodes, n)
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
			pbPrefix := &pb.LsPrefix{Prefix: p.Prefix.String()}
			// Preserve Prefix-SID presence, including index 0.
			if p.HasPrefixSID() {
				pbPrefix.SidIndex = proto.Uint32(p.SidIndex)
			}
			result = append(result, pbPrefix)
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
