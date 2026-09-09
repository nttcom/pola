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
func wrapStatusError(err error, prefix string) error {
	if err == nil {
		return nil
	}

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

	return serveGRPC(s.grpcServer, grpcListener)
}

// serveGRPC serves gRPC and treats ErrServerStopped as a normal shutdown.
func serveGRPC(grpcServer *grpc.Server, lis net.Listener) error {
	if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("failed to serve gRPC: %w", err)
	}

	return nil
}

func parseSidStructure(s string) (*table.SIDStructure, error) {
	structure, err := table.ParseSIDStructure(s)
	if err != nil {
		return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
	}

	return structure, nil
}

// segmentIfaceIDs preserves "not advertised" (nil) versus "advertised as 0".
func segmentIfaceIDs(segment *pb.Segment) (local, remote *uint32) {
	if segment == nil {
		return nil, nil
	}

	if segment.LocalIfaceId != nil {
		v := segment.GetLocalIfaceId()
		local = &v
	}

	if segment.RemoteIfaceId != nil {
		v := segment.GetRemoteIfaceId()
		remote = &v
	}

	return local, remote
}

func enrichSRv6Segment(srv6Seg table.SegmentSRv6, segment *pb.Segment, usidMode bool) (table.SegmentSRv6, error) {
	if usidMode {
		srv6Seg.USid = true
	}

	if structure, err := parseSidStructure(segment.GetSidStructure()); err != nil {
		return srv6Seg, err
	} else if structure != nil {
		srv6Seg.Structure = structure
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

	if b := segment.GetBehavior(); b != 0 {
		if b > math.MaxUint16 {
			return srv6Seg, fmt.Errorf("invalid behavior %d for SID %s: exceeds a 16-bit endpoint behavior code", b, segment.GetSid())
		}

		srv6Seg.Behavior = uint16(b)
	}

	srv6Seg.LocalIfaceID, srv6Seg.RemoteIfaceID = segmentIfaceIDs(segment)

	return srv6Seg, nil
}

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
	mplsSeg.LocalIfaceID, mplsSeg.RemoteIfaceID = segmentIfaceIDs(segment)

	return mplsSeg, nil
}

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
	Headend       netip.Addr
	Endpoint      netip.Addr
	SegmentList   []table.Segment
	CandidatePath table.CandidatePath
}

// endpointSpecFromPB extracts the endpoint specification from the request
// (RFC 9256 §2.1), supporting address and router-ID forms.
func endpointSpecFromPB(policy *pb.SRPolicy) (table.EndpointSpec, error) {
	headend, err := addrFromOptionalSlice(policy.GetHeadend())
	if err != nil {
		return table.EndpointSpec{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid headend address: %v", policy.GetHeadend())
	}

	endpoint, err := addrFromOptionalSlice(policy.GetEndpoint())
	if err != nil {
		return table.EndpointSpec{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid endpoint address: %v", policy.GetEndpoint())
	}

	return table.EndpointSpec{
		Headend:          headend,
		Endpoint:         endpoint,
		HeadendRouterID:  policy.GetHeadendRouterId(),
		EndpointRouterID: policy.GetEndpointRouterId(),
		Family:           fromPBAddressFamily(policy.GetEndpointFamily()),
	}, nil
}

// addrFromOptionalSlice parses an optional IPv4 or IPv6 address.
// An empty slice returns the zero address; an invalid non-empty slice returns an error.
func addrFromOptionalSlice(b []byte) (netip.Addr, error) {
	if len(b) == 0 {
		return netip.Addr{}, nil
	}

	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid address %v", b)
	}

	return addr.Unmap(), nil
}

// resolvePreference normalizes the proto3 zero value to table.DefaultPreference (RFC 9256 §2.7).
func resolvePreference(preference uint32) uint32 {
	if preference == 0 {
		return table.DefaultPreference
	}

	return preference
}

// resolvePolicy resolves a CreateSRPolicyRequest into a resolvedPath.
func resolvePolicy(s *APIServer, req *pb.CreateSRPolicyRequest) (resolvedPath, error) {
	policy := req.GetSrPolicy()

	spec, err := endpointSpecFromPB(policy)
	if err != nil {
		return resolvedPath{}, err
	}

	preference := resolvePreference(policy.GetCandidatePath().GetPreference())

	switch cp := policy.GetCandidatePath().GetPath().(type) {
	case *pb.CandidatePath_Dynamic:
		return resolveDynamicPolicy(s, req, spec, cp.Dynamic, preference)
	case *pb.CandidatePath_Explicit:
		return resolveExplicitPolicy(s, spec, cp.Explicit, preference)
	default:
		return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "candidatePath must specify either dynamic or explicit")
	}
}

// routerIDsForCSPF returns the router IDs CSPF needs.
// Address-form endpoints are resolved via the TED and can still use dynamic paths (§3.6).
func routerIDsForCSPF(ted *table.LsTED, spec table.EndpointSpec) (headendRouterID, endpointRouterID string, err error) {
	if spec.UsesRouterID() {
		return spec.HeadendRouterID, spec.EndpointRouterID, nil
	}

	if !spec.Headend.IsValid() || !spec.Endpoint.IsValid() {
		return "", "", newStatus(codes.InvalidArgument, ReasonInvalidRequest, "either headend/endpoint or headendRouterId/endpointRouterId must be set")
	}

	headendRouterID, ok := ted.FindRouterIDByLoopback(spec.Headend)
	if !ok {
		return "", "", newStatus(codes.InvalidArgument, ReasonInvalidRequest, "headend address %s not found in TED", spec.Headend)
	}

	endpointRouterID, ok = ted.FindRouterIDByLoopback(spec.Endpoint)
	if !ok {
		return "", "", newStatus(codes.InvalidArgument, ReasonInvalidRequest, "endpoint address %s not found in TED", spec.Endpoint)
	}

	return headendRouterID, endpointRouterID, nil
}

func resolveDynamicPolicy(s *APIServer, req *pb.CreateSRPolicyRequest, spec table.EndpointSpec, dyn *pb.DynamicPath, preference uint32) (resolvedPath, error) {
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

		if node.ASN != req.GetAsn() {
			return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "request ASN %d does not match ted ASN %d", req.GetAsn(), node.ASN)
		}

		break
	}

	headendRouterID, endpointRouterID, err := routerIDsForCSPF(ted, spec)
	if err != nil {
		return resolvedPath{}, err
	}

	metricType, err := getMetricType(dyn.GetMetric())
	if err != nil {
		return resolvedPath{}, err
	}

	scope, err := resolvePathScope(ted, headendRouterID, dyn.GetUnderlayFamily(), dyn.GetDataPlane())
	if err != nil {
		return resolvedPath{}, err
	}

	segmentList, err := computeDynamicSegmentList(headendRouterID, endpointRouterID, dyn.GetWaypoints(), metricType, scope, ted)
	if err != nil {
		return resolvedPath{}, err
	}

	headend, endpoint, err := spec.Resolve(ted, scope.Plane.Family)
	if err != nil {
		return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
	}

	// Endpoint and underlay families need not match; Pola aligns them by default
	// for PCC interoperability, but cross-AF is supported (§1.3).
	if endpointFamily := table.FamilyOfAddr(endpoint); scope.Plane.Family.IsValid() && endpointFamily != scope.Plane.Family {
		s.logger.Warn("cross address-family SR Policy",
			logger.String("endpointFamily", endpointFamily.String()),
			logger.String("underlayFamily", scope.Plane.Family.String()),
			logger.String("policyName", req.GetSrPolicy().GetPolicyName()))
	}

	return resolvedPath{
		Headend:     headend,
		Endpoint:    endpoint,
		SegmentList: segmentList,
		CandidatePath: table.CandidatePath{
			Preference: preference,
			Dynamic:    &table.DynamicPath{Metric: metricType, Plane: scope.Plane},
		},
	}, nil
}

func computeDynamicSegmentList(headendRouterID, endpointRouterID string, pbWaypoints []*pb.Waypoint, metricType table.MetricType, scope cspf.PathScope, ted *table.LsTED) ([]table.Segment, error) {
	if len(pbWaypoints) > 0 {
		waypoints := make([]table.Waypoint, 0, len(pbWaypoints))
		for _, w := range pbWaypoints {
			waypoints = append(waypoints, table.Waypoint{
				RouterID: w.GetRouterId(),
				SID:      w.GetSid(), // optional
			})
		}

		segs, err := cspf.WithLooseSourceRouting(headendRouterID, endpointRouterID, waypoints, metricType, scope, ted)
		if err != nil {
			return nil, statusFromCSPFError(err)
		}

		return segs, nil
	}

	segs, err := cspf.CSPF(headendRouterID, endpointRouterID, metricType, scope, ted)
	if err != nil {
		return nil, statusFromCSPFError(err)
	}

	return segs, nil
}

func resolveExplicitPolicy(s *APIServer, spec table.EndpointSpec, explicit *pb.ExplicitPath, preference uint32) (resolvedPath, error) {
	if len(explicit.GetSegmentList()) == 0 {
		return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "candidatePath.explicit.segmentList must not be empty")
	}

	var segmentList []table.Segment

	for _, segment := range explicit.GetSegmentList() {
		seg, err := newEnrichedSegment(segment, s.usidMode)
		if err != nil {
			return resolvedPath{}, err
		}

		segmentList = append(segmentList, seg)
	}

	var ted *table.LsTED

	if spec.UsesRouterID() {
		ted = s.pce.TED()
		if ted == nil {
			return resolvedPath{}, newStatus(codes.FailedPrecondition, ReasonTEDDisabled, "ted is disabled")
		}
	}

	headend, endpoint, err := spec.Resolve(ted, table.AFUnspecified)
	if err != nil {
		return resolvedPath{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
	}

	return resolvedPath{
		Headend:     headend,
		Endpoint:    endpoint,
		SegmentList: segmentList,
		CandidatePath: table.CandidatePath{
			Preference: preference,
			Explicit:   &table.ExplicitPath{SegmentList: segmentList},
		},
	}, nil
}

func sendSRPolicyRequest(s *APIServer, input *pb.CreateSRPolicyRequest, path resolvedPath) error {
	inputSRPolicy := input.GetSrPolicy()

	pcepSession, err := getSyncedPCEPSession(s.pce, inputSRPolicy.GetPeerAddr())
	if err != nil {
		return wrapStatusError(err, "failed to get synchronized PCEP session")
	}

	srPolicy := table.SRPolicy{
		Name:          inputSRPolicy.GetPolicyName(),
		SegmentList:   path.SegmentList,
		Headend:       path.Headend,
		Endpoint:      path.Endpoint,
		Color:         inputSRPolicy.GetColor(),
		CandidatePath: path.CandidatePath,
	}

	if id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), path.Endpoint); exists {
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
	if err := validate(req.GetSrPolicy(), req.GetAsn(), ValidationAdd); err != nil {
		return nil, wrapStatusError(err, "failed to validate SR policy creation")
	}

	path, err := resolvePolicy(s, req)
	if err != nil {
		return nil, wrapStatusError(err, "failed to resolve SR policy path")
	}

	if err := s.validateSIDs(req, path); err != nil {
		return nil, err
	}

	if err := sendSRPolicyRequest(s, req, path); err != nil {
		return nil, wrapStatusError(err, "failed to send SR policy request")
	}

	return &pb.CreateSRPolicyResponse{}, nil
}

func validateEndpointFamilies(path resolvedPath) error {
	headendFamily := table.FamilyOfAddr(path.Headend)
	endpointFamily := table.FamilyOfAddr(path.Endpoint)

	if path.Headend.IsValid() && path.Endpoint.IsValid() && headendFamily != endpointFamily {
		return fmt.Errorf("headend and endpoint addresses must share an address family (headend=%s endpoint=%s)", path.Headend, path.Endpoint)
	}

	if headendFamily == table.AFIPv6 {
		return nil
	}

	for _, seg := range path.SegmentList {
		if _, ok := seg.(table.SegmentSRv6); ok {
			return errors.New("an SRv6 segment list requires IPv6 endpoints")
		}
	}

	return nil
}

func (s *APIServer) validateSIDs(req *pb.CreateSRPolicyRequest, path resolvedPath) error {
	policy := req.GetSrPolicy()
	segmentList := path.SegmentList

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

	if err := validateEndpointFamilies(path); err != nil {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
	}

	if path.CandidatePath.Dynamic != nil {
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

	headendRouterID, ok := ted.FindRouterIDByLoopback(path.Headend)
	if !ok {
		return newStatus(codes.InvalidArgument, ReasonInvalidRequest,
			"headend address %s not found in TED", path.Headend)
	}

	if err := table.ValidateExplicitPath(ted, headendRouterID, segmentList); err != nil {
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

	var segmentList []table.Segment

	endpoint, ok := netip.AddrFromSlice(inputSRPolicy.GetEndpoint())
	if !ok {
		return nil, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "invalid endpoint address")
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
		Name:          inputSRPolicy.GetPolicyName(),
		SegmentList:   segmentList,
		Endpoint:      endpoint,
		Color:         inputSRPolicy.GetColor(),
		CandidatePath: table.CandidatePath{Preference: table.DefaultPreference},
	}

	id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), endpoint)
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
	// ValidationDelete validates an SR Policy for deletion.
	ValidationDelete ValidationKind = "Delete"
)

var validator = map[ValidationKind]func(policy *pb.SRPolicy, asn uint32) error{
	ValidationAdd: func(policy *pb.SRPolicy, asn uint32) error {
		if policy.PeerAddr == nil {
			return errors.New("policy.PeerAddr must not be nil")
		}

		if policy.GetColor() == 0 {
			return errors.New("policy.Color must not be zero")
		}

		if err := validateEndpointSpecInput(policy); err != nil {
			return err
		}

		if policy.GetCandidatePath().GetPath() == nil {
			return errors.New("policy.CandidatePath must specify either dynamic or explicit")
		}

		usesRouterID := policy.GetHeadendRouterId() != "" || policy.GetEndpointRouterId() != ""
		if (usesRouterID || policy.GetCandidatePath().GetDynamic() != nil) && asn == 0 {
			return errors.New("policy.Asn must not be zero")
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

		if len(policy.GetEndpoint()) == 0 {
			return errors.New("policy.Endpoint must not be empty")
		}

		if policy.GetPolicyName() == "" {
			return errors.New("policy.PolicyName must not be empty")
		}

		return nil
	},
}

// validateEndpointSpecInput requires exactly one endpoint form:
// address or router ID.
func validateEndpointSpecInput(policy *pb.SRPolicy) error {
	usesAddr := len(policy.GetHeadend()) > 0 || len(policy.GetEndpoint()) > 0
	usesRouterID := policy.GetHeadendRouterId() != "" || policy.GetEndpointRouterId() != ""

	switch {
	case usesAddr && usesRouterID:
		return errors.New("headend/endpoint and headendRouterId/endpointRouterId are mutually exclusive")
	case usesAddr:
		if len(policy.GetHeadend()) == 0 || len(policy.GetEndpoint()) == 0 {
			return errors.New("both policy.Headend and policy.Endpoint must be set")
		}
	case usesRouterID:
		if policy.GetHeadendRouterId() == "" || policy.GetEndpointRouterId() == "" {
			return errors.New("both policy.HeadendRouterId and policy.EndpointRouterId must be set")
		}
	default:
		return errors.New("either headend/endpoint or headendRouterId/endpointRouterId must be set")
	}

	return nil
}

func sortSessionsByAddr(sessions []*Session) {
	slices.SortFunc(sessions, func(a, b *Session) int {
		return a.peerAddr.Compare(b.peerAddr)
	})
}

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

func getSyncedPCEPSession(pce *Server, addr []byte) (*Session, error) {
	return resolveSession(pce, addr, true)
}

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

// resolvePlane resolves the requested underlay plane, defaulting to the
// node's unique viable plane when unspecified.
func resolvePlane(node *table.LsNode, pbFamily pb.AddressFamily, pbDataPlane pb.DataPlane) (table.Plane, error) {
	family := fromPBAddressFamily(pbFamily)
	dataPlane := fromPBDataPlane(pbDataPlane)

	if family.IsValid() && dataPlane != table.DPUnspecified {
		plane := table.Plane{Family: family, DataPlane: dataPlane}
		if err := plane.Validate(); err != nil {
			return table.Plane{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "%s", err.Error())
		}

		return plane, nil
	}

	plane, err := node.DefaultPlane()
	if err != nil {
		return table.Plane{}, newStatus(codes.FailedPrecondition, ReasonTEDDataIncomplete, "%s", err.Error())
	}

	if family.IsValid() && plane.Family != family {
		return table.Plane{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest,
			"node's unique viable plane uses address family %s, which does not match the requested underlay family %s", plane.Family, family)
	}

	if dataPlane != table.DPUnspecified && plane.DataPlane != dataPlane {
		return table.Plane{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest,
			"node's unique viable plane uses data plane %s, which does not match the requested data plane %s", plane.DataPlane, dataPlane)
	}

	return plane, nil
}

func resolvePathScope(ted *table.LsTED, routerID string, pbFamily pb.AddressFamily, pbDataPlane pb.DataPlane) (cspf.PathScope, error) {
	node, ok := tedNode(ted, routerID)
	if !ok {
		return cspf.PathScope{}, newStatus(codes.InvalidArgument, ReasonInvalidRequest, "no node with router ID %s", routerID)
	}

	plane, err := resolvePlane(node, pbFamily, pbDataPlane)
	if err != nil {
		return cspf.PathScope{}, err
	}

	return cspf.PathScope{Plane: plane}, nil
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
