// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
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
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
)

// wrapStatusError adds context while preserving gRPC status details.
func wrapStatusError(err error, format string, a ...any) error {
	if err == nil {
		return nil
	}
	prefix := fmt.Sprintf(format, a...)
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", prefix, err)
	}

	wrapped := status.New(st.Code(), prefix+": "+st.Message())
	details := st.Details()
	if len(details) == 0 {
		return wrapped.Err()
	}

	protoDetails := make([]protoadapt.MessageV1, 0, len(details))
	for _, d := range details {
		if m, ok := d.(proto.Message); ok {
			protoDetails = append(protoDetails, protoadapt.MessageV1Of(m))
		}
	}
	if len(protoDetails) == 0 {
		return wrapped.Err()
	}

	withDetails, derr := wrapped.WithDetails(protoDetails...)
	if derr != nil {
		return wrapped.Err()
	}
	return withDetails.Err()
}

// statusFromCSPFError maps CSPF errors to gRPC status codes and reasons.
func statusFromCSPFError(err error) error {
	if err == nil {
		return nil
	}
	if invalidInput, ok := errors.AsType[*cspf.InvalidInputError](err); ok {
		_ = invalidInput
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
	}
	if topoLimit, ok := errors.AsType[*cspf.TopologyLimitationError](err); ok {
		return newStatus(codes.FailedPrecondition, topoLimit.Reason, "%s", err.Error())
	}
	// Unexpected CSPF errors indicate an internal invariant break; keep ErrorInfo
	// attached rather than letting them surface as codes.Unknown.
	return newStatus(codes.Internal, ReasonPathComputationFailed, "%s", err.Error())
}

// APIServer serves gRPC requests for PCE operations.
type APIServer struct {
	pce        *Server
	grpcServer *grpc.Server
	usidMode   bool
	logger     *logger.Logger
	pb.UnimplementedPCEServiceServer
}

// NewAPIServer creates and registers a new gRPC API server for PCE operations.
func NewAPIServer(pce *Server, grpcServer *grpc.Server, usidMode bool, lg *logger.Logger) *APIServer {
	s := &APIServer{
		pce:        pce,
		grpcServer: grpcServer,
		usidMode:   usidMode,
		logger:     lg.With(logger.String("server", "grpc")),
	}
	pb.RegisterPCEServiceServer(grpcServer, s)
	return s
}

// Serve starts the gRPC server and stops listening if ctx is canceled.
func (s *APIServer) Serve(ctx context.Context, address, port string) error {
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

	var lc net.ListenConfig
	grpcListener, err := lc.Listen(ctx, "tcp", localAddr.String())
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %s: %w", localAddr.String(), err)
	}
	s.logger.Info("Start listening on gRPC port", logger.String("listenInfo", grpcListener.Addr().String()))
	if err := s.grpcServer.Serve(grpcListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

func validateCreateSRPolicy(req *pb.CreateSRPolicyRequest, disablePathCompute bool) error {
	if disablePathCompute {
		return validate(req.GetSrPolicy(), req.GetAsn(), ValidationAddDisablePathCompute)
	}
	return validate(req.GetSrPolicy(), req.GetAsn(), ValidationAdd)
}

// parseSidStructure parses a comma-separated SID structure (e.g. "32,16,0,80").
// It returns nil for empty input.
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

	if err := table.SIDStructureBytes(result).Validate(); err != nil {
		return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid SID structure %q: %s", s, err.Error())
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
	mplsSeg.SidAbsent = segment.GetSidAbsent()
	return mplsSeg, nil
}

// newEnrichedSegment converts a gRPC Segment to a table.Segment.
func newEnrichedSegment(segment *pb.Segment, usidMode bool) (table.Segment, error) {
	seg, err := table.NewSegment(segment.GetSid())
	if err != nil {
		return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid SID %q: %v", segment.GetSid(), err)
	}
	switch v := seg.(type) {
	case table.SegmentSRv6:
		enriched, err := enrichSRv6Segment(v, segment, usidMode)
		if err != nil {
			return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
		}
		if _, err := pcep.NewSRv6EroSubobject(enriched); err != nil {
			return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
		}
		return enriched, nil
	case table.SegmentSRMPLS:
		enriched, err := enrichSRMPLSSegment(v, segment)
		if err != nil {
			return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
		}
		if _, err := pcep.NewSREroSubobject(enriched); err != nil {
			return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
		}
		return enriched, nil
	default:
		return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "unsupported segment type for SID %q", segment.GetSid())
	}
}

type resolvedPath struct {
	SegmentList []table.Segment
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	Metric      table.MetricType
}

func resolvePath(s *APIServer, input *pb.CreateSRPolicyRequest, disablePathCompute bool) (resolvedPath, error) {
	if disablePathCompute {
		return resolvePathFromRequest(s, input)
	}
	return resolvePathViaTED(s, input)
}

func resolvePathViaTED(s *APIServer, input *pb.CreateSRPolicyRequest) (resolvedPath, error) {
	inputSRPolicy := input.GetSrPolicy()

	ted := s.pce.TED()
	if ted == nil {
		return resolvedPath{}, newStatus(codes.FailedPrecondition, ReasonTEDDisabled, "ted is disabled")
	}

	if len(ted.Nodes) == 0 {
		return resolvedPath{}, newStatus(codes.FailedPrecondition, ReasonTEDNotSynced, "no node in TED")
	}

	// All TED nodes are expected to share the same ASN.
	for _, node := range ted.Nodes {
		if node == nil {
			continue
		}
		if node.ASN != input.GetAsn() {
			return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "request ASN %d does not match ted ASN %d", input.GetAsn(), node.ASN)
		}
		break
	}

	srcAddr, err := getLoopbackAddr(ted, inputSRPolicy.GetSrcRouterId())
	if err != nil {
		return resolvedPath{}, err
	}

	dstAddr, err := getLoopbackAddr(ted, inputSRPolicy.GetDstRouterId())
	if err != nil {
		return resolvedPath{}, err
	}

	segmentList, metricType, err := getSegmentList(inputSRPolicy, ted, s.usidMode)
	if err != nil {
		return resolvedPath{}, err
	}

	return resolvedPath{SegmentList: segmentList, SrcAddr: srcAddr, DstAddr: dstAddr, Metric: metricType}, nil
}

// resolvePathFromRequest takes the SR Policy path directly from the request,
// without consulting the TED.
func resolvePathFromRequest(s *APIServer, input *pb.CreateSRPolicyRequest) (resolvedPath, error) {
	inputSRPolicy := input.GetSrPolicy()

	srcAddr, ok := netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
	if !ok {
		return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest,
			"invalid source address %v",
			inputSRPolicy.GetSrcAddr(),
		)
	}

	dstAddr, ok := netip.AddrFromSlice(inputSRPolicy.GetDstAddr())
	if !ok {
		return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest,
			"invalid destination address %v",
			inputSRPolicy.GetDstAddr(),
		)
	}

	var segmentList []table.Segment
	for _, segment := range inputSRPolicy.GetSegmentList() {
		seg, err := newEnrichedSegment(segment, s.usidMode)
		if err != nil {
			return resolvedPath{}, err
		}
		segmentList = append(segmentList, seg)
	}

	return resolvedPath{SegmentList: segmentList, SrcAddr: srcAddr, DstAddr: dstAddr, Metric: table.UnspecifiedMetric}, nil
}

// resolveSRPolicyIntent resolves the candidate-path type and metric per RFC 9256 §2.4.2.
func resolveSRPolicyIntent(inputSRPolicy *pb.SRPolicy, disablePathCompute bool, metricType table.MetricType) (table.PolicyType, table.MetricType, error) {
	if disablePathCompute {
		// disable_path_compute treats the given SegmentList as an explicit path.
		return table.PolicyTypeExplicit, table.UnspecifiedMetric, nil
	}

	switch inputSRPolicy.GetType() {
	case pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT:
		return table.PolicyTypeExplicit, table.UnspecifiedMetric, nil
	case pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC:
		return table.PolicyTypeDynamic, metricType, nil
	default:
		return "", table.UnspecifiedMetric, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "undefined SR Policy type")
	}
}

func sendSRPolicyRequest(s *APIServer, input *pb.CreateSRPolicyRequest, path resolvedPath, disablePathCompute bool) error {
	inputSRPolicy := input.GetSrPolicy()

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPeerAddr())
	if err != nil {
		return wrapStatusError(err, "failed to get synchronized PCEP session")
	}

	policyType, metricType, err := resolveSRPolicyIntent(inputSRPolicy, disablePathCompute, path.Metric)
	if err != nil {
		return wrapStatusError(err, "failed to resolve SR policy type")
	}

	srPolicy := table.SRPolicy{
		Name:        inputSRPolicy.GetPolicyName(),
		SegmentList: path.SegmentList,
		SrcAddr:     path.SrcAddr,
		DstAddr:     path.DstAddr,
		Color:       inputSRPolicy.GetColor(),
		Preference:  100,
		Type:        policyType,
		Metric:      metricType,
	}

	if id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), path.DstAddr); exists {
		s.logger.Debug("Request to update SR Policy", logger.Uint32("plspID", id))
		srPolicy.PlspID = id
		if err := pcepSession.SendPCUpdate(srPolicy); err != nil {
			return newStatus(codes.Internal, ReasonPCEPRequestFailed, "failed to send PC update: %v", err)
		}
	} else {
		s.logger.Debug("Request to create SR Policy")
		if err := pcepSession.RequestSRPolicyCreated(srPolicy); err != nil {
			return newStatus(codes.Internal, ReasonPCEPRequestFailed, "failed to request SR policy creation: %v", err)
		}
	}

	return nil
}

// CreateSRPolicy creates a new SR Policy.
func (s *APIServer) CreateSRPolicy(_ context.Context, req *pb.CreateSRPolicyRequest) (*pb.CreateSRPolicyResponse, error) {
	disablePathCompute := req.GetDisablePathCompute()
	if err := validateCreateSRPolicy(req, disablePathCompute); err != nil {
		return nil, wrapStatusError(err, "failed to validate SR policy creation")
	}

	path, err := resolvePath(s, req, disablePathCompute)
	if err != nil {
		return nil, wrapStatusError(err, "failed to resolve SR policy path")
	}

	if err := s.validateSIDs(req, path.SegmentList); err != nil {
		return nil, err
	}

	if err := sendSRPolicyRequest(s, req, path, disablePathCompute); err != nil {
		return nil, wrapStatusError(err, "failed to send SR policy request")
	}

	return &pb.CreateSRPolicyResponse{}, nil
}

func (s *APIServer) validateSIDs(req *pb.CreateSRPolicyRequest, segmentList []table.Segment) error {
	policy := req.GetSrPolicy()

	// Reject out-of-range labels before the validation skip paths.
	if invalid := table.OutOfRangeSRMPLSLabels(segmentList); len(invalid) > 0 {
		descriptions := make([]string, 0, len(invalid))
		for _, s := range invalid {
			descriptions = append(descriptions, s.String())
		}
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest,
			"segment list contains SR-MPLS labels outside the valid range 0-%d: %s",
			table.MPLSLabelMax, strings.Join(descriptions, ", "))
	}

	if table.HasUnknownSegmentType(segmentList) {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "segment list contains a segment with an unrecognized SID family")
	}

	if table.HasMixedSegmentTypes(segmentList) {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "segment list contains mixed SR-MPLS and SRv6 SIDs")
	}

	// Skip TED lookup for dynamically computed paths.
	if policy.GetType() == pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC && !req.GetDisablePathCompute() {
		return nil
	}

	if req.GetNoSidValidate() {
		s.logger.Warn("skipping SID validation: no_sid_validate specified",
			logger.String("policyName", policy.GetPolicyName()),
			logger.Uint32("color", policy.GetColor()),
		)
		return nil
	}

	ted := s.pce.TED()
	if ted == nil {
		return newStatus(codes.FailedPrecondition, ReasonTEDDisabled,
			"TED is not enabled, SID validation cannot be performed")
	}
	if len(ted.Nodes) == 0 {
		return newStatus(codes.FailedPrecondition, ReasonTEDNotSynced,
			"TED is enabled but empty (not yet synchronized), SID validation cannot be performed")
	}

	// Resolve source router ID for path traversal.
	var srcRouterID string
	if req.GetDisablePathCompute() {
		srcAddr, ok := netip.AddrFromSlice(req.GetSrPolicy().GetSrcAddr())
		if !ok {
			return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid source address in request")
		}
		srcRouterID, ok = ted.FindRouterIDByLoopback(srcAddr)
		if !ok {
			return newStatus(codes.InvalidArgument, ReasonInvalidRequest,
				"source address %s not found in TED", srcAddr)
		}
	} else {
		srcRouterID = req.GetSrPolicy().GetSrcRouterId()
	}

	if err := table.ValidateExplicitPath(ted, srcRouterID, segmentList); err != nil {
		return newStatus(codes.FailedPrecondition, ReasonSIDValidationFailed, "SID validation failed: %s", err)
	}
	return nil
}

// DeleteSRPolicy deletes an existing SR Policy.
func (s *APIServer) DeleteSRPolicy(_ context.Context, input *pb.DeleteSRPolicyRequest) (*pb.DeleteSRPolicyResponse, error) {
	err := validate(input.GetSrPolicy(), input.GetAsn(), ValidationDelete)
	if err != nil {
		return nil, err
	}

	inputSRPolicy := input.GetSrPolicy()
	var srcAddr, dstAddr netip.Addr
	var segmentList []table.Segment

	if len(inputSRPolicy.GetSrcAddr()) > 0 {
		var ok bool
		srcAddr, ok = netip.AddrFromSlice(inputSRPolicy.GetSrcAddr())
		if !ok {
			return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid source address")
		}
	}

	dstAddr, ok := netip.AddrFromSlice(inputSRPolicy.GetDstAddr())
	if !ok {
		return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid destination address")
	}

	for _, segment := range inputSRPolicy.GetSegmentList() {
		seg, err := newEnrichedSegment(segment, s.usidMode)
		if err != nil {
			return nil, err
		}
		segmentList = append(segmentList, seg)
	}

	s.logger.Info("Received DeleteSRPolicy API request")
	s.logger.Debug("Received parameter", logger.Any("input", input))

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPeerAddr())
	if err != nil {
		return nil, err
	}

	srPolicy := table.SRPolicy{
		Name:        inputSRPolicy.GetPolicyName(),
		SegmentList: segmentList,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Color:       inputSRPolicy.GetColor(),
		Preference:  100,
	}

	id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), dstAddr)
	if !exists {
		return nil, newStatus(codes.NotFound, ReasonSRPolicyNotFound, "requested SR Policy not found")
	}

	s.logger.Debug("Request to delete SR Policy", logger.Uint32("plspID", id))
	srPolicy.PlspID = id
	if err := pcepSession.RequestSRPolicyDeleted(srPolicy); err != nil {
		return nil, newStatus(codes.Internal, ReasonPCEPRequestFailed, "failed to send PC delete: %v", err)
	}

	return &pb.DeleteSRPolicyResponse{}, nil
}

// srPolicyListFilter validates and parses the session filter.
func srPolicyListFilter(req *pb.GetSRPolicyListRequest) (netip.Addr, error) {
	var filterAddr netip.Addr
	if raw := req.GetPeerAddr(); len(raw) > 0 {
		var ok bool
		filterAddr, ok = netip.AddrFromSlice(raw)
		if !ok {
			return netip.Addr{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid session filter address %v", raw)
		}
	}
	return filterAddr, nil
}

// GetSRPolicyList returns SR Policies grouped by PCEP session.
func (s *APIServer) GetSRPolicyList(_ context.Context, req *pb.GetSRPolicyListRequest) (*pb.GetSRPolicyListResponse, error) {
	s.logger.Info("Received GetSRPolicyList API request")

	filterAddr, err := srPolicyListFilter(req)
	if err != nil {
		return nil, err
	}

	pcepSessions := s.pce.Sessions()
	sortSessionsByAddr(pcepSessions)

	routerIDIndex := s.pce.TED().RouterIDIndex()

	sessions := make([]*pb.SRPolicySession, 0, len(pcepSessions))
	for _, pcepSession := range pcepSessions {
		if filterAddr.IsValid() && pcepSession.peerAddr != filterAddr {
			continue
		}

		policies := pcepSession.SRPolicies()
		pbPolicies := make([]*pb.SRPolicy, 0, len(policies))
		for _, policy := range policies {
			pbPolicies = append(pbPolicies, s.buildPBSRPolicy(pcepSession, policy, routerIDIndex))
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

		sessions = append(sessions, buildPBSRPolicySession(pcepSession, pbPolicies))
	}

	s.logger.Debug("Send SRPolicyList API reply")
	return &pb.GetSRPolicyListResponse{
		Sessions: sessions,
	}, nil
}

func validate(inputSRPolicy *pb.SRPolicy, asn uint32, validationKind ValidationKind) error {
	if inputSRPolicy == nil {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "validate error, input is nil")
	}
	if validationKind == ValidationAdd && asn == 0 {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "validate error, ASN must not be zero")
	}
	validateFunc, ok := validator[validationKind]
	if !ok {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "validate error: unknown validation kind %q", validationKind)
	}
	if err := validateFunc(inputSRPolicy, asn); err != nil {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "validate error: %s", err.Error())
	}

	return nil
}

// ValidationKind specifies the type of validation to perform on an SR Policy.
type ValidationKind string

const (
	// ValidationAdd validates an SR Policy for creation.
	ValidationAdd ValidationKind = "Add"
	// ValidationAddDisablePathCompute validates an SR Policy for creation with path computation disabled.
	ValidationAddDisablePathCompute ValidationKind = "AddDisablePathCompute"
	// ValidationDelete validates an SR Policy for deletion.
	ValidationDelete ValidationKind = "Delete"
)

var validator = map[ValidationKind]func(policy *pb.SRPolicy, asn uint32) error{
	ValidationAdd: func(policy *pb.SRPolicy, _ uint32) error {
		if policy.PeerAddr == nil {
			return errors.New("policy.PeerAddr must not be nil")
		}
		if policy.GetColor() == 0 {
			return errors.New("policy.Color must not be zero")
		}
		if policy.GetSrcRouterId() == "" {
			return errors.New("policy.SrcRouterId must not be empty")
		}
		if policy.GetDstRouterId() == "" {
			return errors.New("policy.DstRouterId must not be empty")
		}
		return nil
	},

	ValidationAddDisablePathCompute: func(policy *pb.SRPolicy, _ uint32) error {
		if policy.PeerAddr == nil {
			return errors.New("policy.PeerAddr must not be nil")
		}
		if policy.GetColor() == 0 {
			return errors.New("policy.Color must not be zero")
		}
		if len(policy.GetSrcAddr()) == 0 {
			return errors.New("policy.SrcAddr must not be empty")
		}
		if len(policy.GetDstAddr()) == 0 {
			return errors.New("policy.DstAddr must not be empty")
		}
		if len(policy.GetSegmentList()) == 0 {
			return errors.New("policy.SegmentList must not be empty")
		}
		return nil
	},

	ValidationDelete: func(policy *pb.SRPolicy, _ uint32) error {
		if policy.PeerAddr == nil {
			return errors.New("policy.PeerAddr must not be nil")
		}
		if policy.GetColor() == 0 {
			return errors.New("policy.Color must not be zero")
		}
		if len(policy.GetDstAddr()) == 0 {
			return errors.New("policy.DstAddr must not be empty")
		}
		if policy.GetPolicyName() == "" {
			return errors.New("policy.PolicyName must not be empty")
		}
		return nil
	},
}

// sortSessionsByAddr orders sessions by peer address.
func sortSessionsByAddr(sessions []*Session) {
	slices.SortFunc(sessions, func(a, b *Session) int {
		return a.peerAddr.Compare(b.peerAddr)
	})
}

// resolveSession resolves the PCEP session a request targets.
// RFC 5440 §7.15 allows at most one session per peer.
func resolveSession(pce *Server, addr []byte, requireSynced bool) (*Session, error) {
	peerAddr, ok := netip.AddrFromSlice(addr)
	if !ok {
		return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid PCEP session address: %v", addr)
	}

	pcepSession := pce.SearchSession(peerAddr)
	if pcepSession == nil {
		return nil, newStatus(codes.NotFound, ReasonPCEPSessionNotFound,
			"no session with address %s found", peerAddr)
	}
	if requireSynced && !pcepSession.IsSynced() {
		return nil, newStatus(codes.FailedPrecondition, ReasonPCEPSessionNotSynced,
			"no synced session with %s", peerAddr)
	}
	return pcepSession, nil
}

// getSyncedPCEPSession resolves the synced PCEP session a write request targets.
func getSyncedPCEPSession(pce *Server, addr []byte) (*Session, error) {
	return resolveSession(pce, addr, true)
}

// tedNode returns the non-nil node for routerID.
func tedNode(ted *table.LsTED, routerID string) (*table.LsNode, bool) {
	if ted == nil {
		return nil, false
	}
	node, ok := ted.Nodes[routerID]
	if !ok || node == nil {
		return nil, false
	}
	return node, true
}

func getLoopbackAddr(ted *table.LsTED, routerID string) (netip.Addr, error) {
	node, ok := tedNode(ted, routerID)
	if !ok {
		return netip.Addr{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "no node with router ID %s", routerID)
	}
	addr, err := node.LoopbackAddr()
	if err != nil {
		return netip.Addr{}, newStatus(codes.FailedPrecondition, ReasonTEDDataIncomplete, "%s", err.Error())
	}
	return addr, nil
}

// getSegmentList returns the segment list and resolved metric type.
func getSegmentList(inputSRPolicy *pb.SRPolicy, ted *table.LsTED, usidMode bool) ([]table.Segment, table.MetricType, error) {
	var segmentList []table.Segment

	switch inputSRPolicy.GetType() {
	case pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT:
		if len(inputSRPolicy.GetSegmentList()) == 0 {
			return nil, table.UnspecifiedMetric, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "no segments in SRPolicy input")
		}
		for _, segment := range inputSRPolicy.GetSegmentList() {
			sid, err := newEnrichedSegment(segment, usidMode)
			if err != nil {
				return nil, table.UnspecifiedMetric, err
			}
			segmentList = append(segmentList, sid)
		}
	case pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC:
		metricType, err := getMetricType(inputSRPolicy.GetMetric())
		if err != nil {
			return nil, table.UnspecifiedMetric, err
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

			segs, err := cspf.WithLooseSourceRouting(
				inputSRPolicy.GetSrcRouterId(),
				inputSRPolicy.GetDstRouterId(),
				waypoints,
				metricType,
				ted,
			)
			if err != nil {
				return nil, table.UnspecifiedMetric, statusFromCSPFError(err)
			}
			return segs, metricType, nil
		}

		segs, err := cspf.CSPF(
			inputSRPolicy.GetSrcRouterId(),
			inputSRPolicy.GetDstRouterId(),
			metricType,
			ted,
		)
		if err != nil {
			return nil, table.UnspecifiedMetric, statusFromCSPFError(err)
		}
		return segs, metricType, nil
	default:
		return nil, table.UnspecifiedMetric, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "undefined SR Policy type")
	}

	return segmentList, table.UnspecifiedMetric, nil
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
		return 0, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "unknown metric type: %v", metricType)
	}
}

// sessionListFilter validates and parses the peer address filter.
func sessionListFilter(req *pb.GetSessionListRequest) (netip.Addr, error) {
	var filterAddr netip.Addr
	if raw := req.GetPeerAddr(); len(raw) > 0 {
		var ok bool
		filterAddr, ok = netip.AddrFromSlice(raw)
		if !ok {
			return netip.Addr{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid session filter address %v", raw)
		}
	}
	return filterAddr, nil
}

// GetSessionList returns a list of PCEP sessions.
func (s *APIServer) GetSessionList(_ context.Context, req *pb.GetSessionListRequest) (*pb.GetSessionListResponse, error) {
	s.logger.Info("Received GetSessionList API request")

	filterAddr, err := sessionListFilter(req)
	if err != nil {
		return nil, err
	}

	pcepSessions := s.pce.Sessions()
	sortSessionsByAddr(pcepSessions)

	sessions := make([]*pb.Session, 0, len(pcepSessions))
	for _, pcepSession := range pcepSessions {
		if filterAddr.IsValid() && pcepSession.peerAddr != filterAddr {
			continue
		}
		sessions = append(sessions, s.buildPBSession(pcepSession, req.GetIncludeStats()))
	}

	s.logger.Debug("Send GetSessionList API reply")
	return &pb.GetSessionListResponse{
		Sessions: sessions,
	}, nil
}

// DeleteSession deletes a PCEP session.
func (s *APIServer) DeleteSession(_ context.Context, req *pb.DeleteSessionRequest) (*pb.DeleteSessionResponse, error) {
	pce := s.pce
	// A session being torn down need not be synced.
	ss, err := resolveSession(pce, req.GetPeerAddr(), false)
	if err != nil {
		return nil, err
	}

	if err := ss.SendClose(pcep.CloseReasonNoExplanationProvided); err != nil {
		return nil, newStatus(codes.Internal, ReasonPCEPRequestFailed, "failed to send close message: %v", err)
	}

	// A PCEP Close only notifies the peer; the TCP connection and the server-side
	// session state have to be torn down here as well.
	pce.closeSession(ss)

	return &pb.DeleteSessionResponse{}, nil
}

// GetTED returns the TED information in a structured way.
func (s *APIServer) GetTED(_ context.Context, _ *pb.GetTEDRequest) (*pb.GetTEDResponse, error) {
	s.logger.Info("Received GetTED API request")

	ret := &pb.GetTEDResponse{Enabled: true}
	if s.pce == nil {
		ret.Enabled = false
		return ret, nil
	}
	ted := s.pce.TED()
	if ted == nil {
		ret.Enabled = false
		return ret, nil
	}

	for _, node := range ted.Nodes {
		if n := convertLsNode(node, s.logger); n != nil {
			ret.Nodes = append(ret.Nodes, n)
		}
	}

	s.logger.Debug("Send GetTED API reply")
	return ret, nil
}
