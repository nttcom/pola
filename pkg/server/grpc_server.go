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
	"strconv"
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
	usidMode   bool
	logger     *zap.Logger
	pb.UnimplementedPceServiceServer
}

func NewAPIServer(pce *Server, grpcServer *grpc.Server, usidMode bool, logger *zap.Logger) *APIServer {
	s := &APIServer{
		pce:        pce,
		grpcServer: grpcServer,
		usidMode:   usidMode,
		logger:     logger.With(zap.String("server", "grpc")),
	}
	pb.RegisterPceServiceServer(grpcServer, s)
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

func (s *APIServer) createSRPolicy(_ context.Context, input *pb.CreateSRPolicyInput, withLinkState bool) (*pb.RequestStatus, error) {
	var err error

	if withLinkState {
		err = validate(input.GetSRPolicy(), input.GetAsn(), ValidationAdd)
		if err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	} else {
		err = validate(input.GetSRPolicy(), input.GetAsn(), ValidationAddWithoutLinkState)
		if err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
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
			var seg table.Segment
			if addr, err := netip.ParseAddr(segment.GetSid()); err == nil && addr.Is6() {
				segSRv6 := table.NewSegmentSRv6(addr)

				// handling of related to Nai
				if segment.GetLocalAddr() != "" {
					if la, addrErr := netip.ParseAddr(segment.GetLocalAddr()); addrErr == nil {
						segSRv6.LocalAddr = la
					} else {
						return &pb.RequestStatus{IsSuccess: false}, addrErr
					}
					if segment.GetRemoteAddr() != "" {
						if ra, addrErr := netip.ParseAddr(segment.GetRemoteAddr()); addrErr == nil {
							segSRv6.RemoteAddr = ra
						} else {
							return &pb.RequestStatus{IsSuccess: false}, addrErr
						}
					}
				}

				// handling of related to SID Structure
				if ss := strings.Split(segment.GetSidStructure(), ","); len(ss) == 4 {
					segSRv6.Structure = []uint8{}
					for _, strElem := range ss {
						elem, err := strconv.Atoi(strElem)
						if err != nil {
							return &pb.RequestStatus{IsSuccess: false}, errors.New("invalid SidStructure information")
						}
						segSRv6.Structure = append(segSRv6.Structure, uint8(elem))
					}

				}
				// usid option
				segSRv6.USid = s.usidMode
				seg = segSRv6
			} else if i, err := strconv.ParseUint(segment.GetSid(), 10, 32); err == nil {
				seg = table.NewSegmentSRMPLS(uint32(i))
			} else {
				return &pb.RequestStatus{IsSuccess: false}, errors.New("invalid SID")
			}
			segmentList = append(segmentList, seg)
		}
	}

	inputJson, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	s.logger.Info("Received CreateSRPolicy API request")
	s.logger.Debug("Received paramater", zap.String("input", string(inputJson)))

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

	if id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), dstAddr); exists {
		// Update SR Policy
		s.logger.Debug("Request to update SR Policy", zap.Uint32("plspID", id))
		srPolicy.PlspID = id

		if err := pcepSession.SendPCUpdate(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	} else {
		// Initiate SR Policy
		s.logger.Debug("Request to create SR Policy")
		if err := pcepSession.RequestSRPolicyCreated(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, err
		}
	}

	return &pb.RequestStatus{IsSuccess: true}, nil
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

	inputJson, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	s.logger.Info("Received DeleteSRPolicy API request")
	s.logger.Debug("Received paramater", zap.String("input", string(inputJson)))

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

	if id, exists := pcepSession.SearchPlspID(inputSRPolicy.GetColor(), dstAddr); exists {
		// Delete SR Policy
		s.logger.Debug("Request to delete SR Policy", zap.Uint32("plspID", id))
		srPolicy.PlspID = id

		if err := pcepSession.RequestSRPolicyDeleted(srPolicy); err != nil {
			return &pb.RequestStatus{IsSuccess: false}, nil
		}
	} else {
		// Invalid SR Policy
		return &pb.RequestStatus{IsSuccess: false}, fmt.Errorf("Requested SR Policy not found")
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
			policy.PcepSessionAddr != nil &&
			policy.Color != 0 &&
			policy.SrcRouterID != "" &&
			policy.DstRouterID != ""
	},
	ValidationKind("AddWithoutLinkState"): func(policy *pb.SRPolicy, asn uint32) bool {
		return policy.PcepSessionAddr != nil &&
			len(policy.SrcAddr) > 0 &&
			len(policy.DstAddr) > 0 &&
			len(policy.SegmentList) > 0
	},
	ValidationKind("Delete"): func(policy *pb.SRPolicy, asn uint32) bool {
		return policy.PcepSessionAddr != nil &&
			policy.Color != 0 &&
			len(policy.DstAddr) > 0 &&
			policy.PolicyName != ""
	},
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

	s.logger.Debug("Send SRPolicyList API reply")
	return &ret, nil
}

func (s *APIServer) GetTed(context.Context, *empty.Empty) (*pb.Ted, error) {
	s.logger.Info("Received GetTed API request")

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

	s.logger.Debug("Send GetTed API reply")
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
