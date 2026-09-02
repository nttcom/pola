// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/cspf"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	testAddrA          = "10.0.0.1"
	testAddrB          = "10.0.0.2"
	testSRv6SID1       = "2001:db8::1"
	testSRv6SID2       = "2001:db8:1005::"
	invalidAddrLiteral = "not-an-addr"
	invalidSidStr      = "not-a-sid"
	testSRPolicyName   = "test"
	testRouterID1      = "0000.0000.0001"
	testRouterID2      = "0000.0000.0002"
	wantErrColorZero   = "Color must not be zero"
)

func TestStatusFromCSPFError(t *testing.T) {
	reasonOf := func(t *testing.T, err error) (codes.Code, string) {
		t.Helper()
		st, ok := status.FromError(err)
		require.True(t, ok)
		var reason string
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok {
				reason = info.Reason
			}
		}
		return st.Code(), reason
	}

	t.Run("nil error maps to nil", func(t *testing.T) {
		assert.NoError(t, statusFromCSPFError(nil))
	})

	t.Run("InvalidInputError maps to InvalidArgument", func(t *testing.T) {
		err := statusFromCSPFError(&cspf.InvalidInputError{Err: errors.New("bad router ID")})
		code, reason := reasonOf(t, err)
		assert.Equal(t, codes.InvalidArgument, code)
		assert.Equal(t, ReasonInvalidRequest, reason)
		assert.ErrorContains(t, err, "bad router ID")
	})

	t.Run("TopologyLimitationError maps to FailedPrecondition with its own Reason", func(t *testing.T) {
		err := statusFromCSPFError(&cspf.TopologyLimitationError{Err: errors.New("no path"), Reason: "DESTINATION_UNREACHABLE"})
		code, reason := reasonOf(t, err)
		assert.Equal(t, codes.FailedPrecondition, code)
		assert.Equal(t, "DESTINATION_UNREACHABLE", reason)
		assert.ErrorContains(t, err, "no path")
	})

	t.Run("an unclassified error maps to Internal with ErrorInfo", func(t *testing.T) {
		got := statusFromCSPFError(errors.New("ted is nil"))
		code, reason := reasonOf(t, got)
		assert.Equal(t, codes.Internal, code)
		assert.Equal(t, ReasonPathComputationFailed, reason)
		assert.ErrorContains(t, got, "ted is nil")
	})
}

func TestNewEnrichedSegmentSRMPLS(t *testing.T) {
	tests := []struct {
		name       string
		segment    *pb.Segment
		wantLocal  string
		wantRemote string
		wantErr    bool
	}{
		{
			name:    "no addresses",
			segment: &pb.Segment{Sid: "16001"},
		},
		{
			name:      "node NAI",
			segment:   &pb.Segment{Sid: "16001", LocalAddr: "10.255.0.1"},
			wantLocal: "10.255.0.1",
		},
		{
			name:       "adjacency NAI",
			segment:    &pb.Segment{Sid: "24001", LocalAddr: testAddrA, RemoteAddr: testAddrB},
			wantLocal:  testAddrA,
			wantRemote: testAddrB,
		},
		{
			name:    "malformed localAddr",
			segment: &pb.Segment{Sid: "16001", LocalAddr: "10.255.0.300"},
			wantErr: true,
		},
		{
			name:    "malformed remoteAddr",
			segment: &pb.Segment{Sid: "16001", LocalAddr: testAddrA, RemoteAddr: invalidAddrLiteral},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := newEnrichedSegment(tt.segment, false)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			mplsSeg, ok := seg.(table.SegmentSRMPLS)
			require.Truef(t, ok, "segment type: got %T, want table.SegmentSRMPLS", seg)
			assert.Equal(t, tt.wantLocal, addrString(mplsSeg.LocalAddr), "LocalAddr")
			assert.Equal(t, tt.wantRemote, addrString(mplsSeg.RemoteAddr), "RemoteAddr")
		})
	}
}

func TestNewEnrichedSegmentSRv6(t *testing.T) {
	segment := &pb.Segment{
		Sid:          testSRv6SID2,
		LocalAddr:    "2001:db8::5",
		RemoteAddr:   "2001:db8::6",
		SidStructure: "32,16,0,80",
	}

	for _, usidMode := range []bool{false, true} {
		seg, err := newEnrichedSegment(segment, usidMode)
		require.NoError(t, err)

		srv6Seg, ok := seg.(table.SegmentSRv6)
		require.Truef(t, ok, "segment type: got %T, want table.SegmentSRv6", seg)
		assert.Equal(t, "2001:db8:1005::", srv6Seg.Sid.String(), "Sid")
		assert.Equal(t, "2001:db8::5", addrString(srv6Seg.LocalAddr), "LocalAddr")
		assert.Equal(t, "2001:db8::6", addrString(srv6Seg.RemoteAddr), "RemoteAddr")
		assert.Equal(t, table.SIDStructureBytes{32, 16, 0, 80}, srv6Seg.Structure, "Structure")
		assert.Equalf(t, usidMode, srv6Seg.USid, "USid with usidMode=%v", usidMode)
	}
}

func TestNewEnrichedSegmentInvalidSID(t *testing.T) {
	_, err := newEnrichedSegment(&pb.Segment{Sid: invalidSidStr}, false)
	assert.Error(t, err, "expected an error for an unparsable SID")
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func TestCreateEroFromSegmentListWithNAI(t *testing.T) {
	seg := table.NewSegmentSRMPLS(16002)
	seg.LocalAddr = netip.MustParseAddr("10.255.0.2")

	ero, err := createEroFromSegmentList([]table.Segment{seg})
	require.NoError(t, err)
	require.Len(t, ero.EroSubobjects, 1)

	raw, err := ero.EroSubobjects[0].Serialize()
	require.NoError(t, err)
	// Type, Length, NT/Flags (4byte) + SID (4byte) + NAI (4byte)
	require.Len(t, raw, 12)

	nt := raw[2] >> 4
	assert.Equalf(t, uint8(0x01), nt, "NAI type: got 0x%02x, want 0x01 (IPv4 node ID)", nt)
	assert.Zero(t, raw[3]&0x08, "F flag is set even though the NAI is present")
	assert.Equal(t, seg.LocalAddr.AsSlice(), raw[8:12], "NAI")
}

func newTestAPIServer(ted *table.LsTED) *APIServer {
	return &APIServer{
		pce:    &Server{ted: ted},
		logger: logger.NewNop(),
	}
}

func explicitPolicyRequest(noSIDValidate bool, sid string) *pb.CreateSRPolicyRequest {
	return &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
			PolicyName:  testSRPolicyName,
			Color:       100,
			SrcRouterId: testRouterID1,
			SegmentList: []*pb.Segment{{Sid: sid}},
		},
		NoSidValidate: noSIDValidate,
	}
}

func dynamicPolicyRequest() *pb.CreateSRPolicyRequest {
	return &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			Type:       pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
			PolicyName: testSRPolicyName,
			Color:      100,
		},
	}
}

func TestValidateSIDs_NoSidValidateSkipsCheck(t *testing.T) {
	s := newTestAPIServer(nil)
	req := explicitPolicyRequest(true, "16099")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16099)}

	err := s.validateSIDs(req, segmentList)
	assert.NoError(t, err, "expected no_sid_validate to skip the check even with no TED")
}

func TestValidateSIDs_DynamicPathSkipsCheck(t *testing.T) {
	s := newTestAPIServer(nil)
	req := dynamicPolicyRequest()
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16099)}

	err := s.validateSIDs(req, segmentList)
	assert.NoError(t, err, "expected a dynamic path to skip the check")
}

func TestValidateSIDs_DynamicWithDisablePathComputeIsStillValidated(t *testing.T) {
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node}}
	s := newTestAPIServer(ted)

	req := dynamicPolicyRequest()
	req.DisablePathCompute = true
	req.SrPolicy.SegmentList = []*pb.Segment{{Sid: "16099"}}
	req.SrPolicy.SrcAddr = netip.MustParseAddr("10.0.0.1").AsSlice()
	req.SrPolicy.DstAddr = netip.MustParseAddr("10.0.0.2").AsSlice()
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16099)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestValidateSIDs_NoTED(t *testing.T) {
	s := newTestAPIServer(nil)
	req := explicitPolicyRequest(false, "16003")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "TED is not enabled")
}

func TestValidateSIDs_TEDEmpty(t *testing.T) {
	s := newTestAPIServer(&table.LsTED{Nodes: map[string]*table.LsNode{}})
	req := explicitPolicyRequest(false, "16003")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "not yet synchronized", "expected a distinct message for an empty-but-enabled TED")
}

func TestValidateSIDs_MissingSID(t *testing.T) {
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node}}
	s := newTestAPIServer(ted)

	req := explicitPolicyRequest(false, "16099")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16099)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "hop 1", "expected the missing hop to be listed")
}

func TestValidateSIDs_EndpointFormIsStillValidated(t *testing.T) {
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node}}
	s := newTestAPIServer(ted)

	req := explicitPolicyRequest(false, "16099")
	req.DisablePathCompute = true
	req.SrPolicy.SrcAddr = netip.MustParseAddr("10.0.0.1").AsSlice()
	req.SrPolicy.DstAddr = netip.MustParseAddr("10.0.0.2").AsSlice()
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16099)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "hop 1", "expected the missing hop to be listed")
}

func TestValidateSIDs_DisablePathComputeInvalidSourceAddress(t *testing.T) {
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node}}
	s := newTestAPIServer(ted)

	req := explicitPolicyRequest(false, "16003")
	req.DisablePathCompute = true
	req.SrPolicy.SrcAddr = []byte{1, 2, 3}
	req.SrPolicy.DstAddr = netip.MustParseAddr("10.0.0.2").AsSlice()
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "invalid source address in request")
}

func TestValidateSIDs_DisablePathComputeSourceAddressNotFound(t *testing.T) {
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node}}
	s := newTestAPIServer(ted)

	req := explicitPolicyRequest(false, "16003")
	req.DisablePathCompute = true
	req.SrPolicy.SrcAddr = netip.MustParseAddr("10.0.0.9").AsSlice()
	req.SrPolicy.DstAddr = netip.MustParseAddr("10.0.0.2").AsSlice()
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "source address 10.0.0.9 not found in TED")
}

func TestValidateSIDs_LabelOutOfRangeIsRejectedEvenWithNoSidValidate(t *testing.T) {
	s := newTestAPIServer(nil)
	req := explicitPolicyRequest(true, "1048576")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(1048576)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "0-1048575")
	assert.Contains(t, st.Message(), "hop 1")
}

func TestValidateSIDs_LabelBoundsAreAccepted(t *testing.T) {
	s := newTestAPIServer(nil)

	for _, label := range []uint32{0, 1048575} {
		req := explicitPolicyRequest(true, strconv.FormatUint(uint64(label), 10))
		segmentList := []table.Segment{table.NewSegmentSRMPLS(label)}

		assert.NoErrorf(t, s.validateSIDs(req, segmentList), "expected label %d to be in range", label)
	}
}

func TestValidateSIDs_AllKnownSucceeds(t *testing.T) {
	node := &table.LsNode{
		RouterID:  testRouterID1,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 3, HasSidIndex: true},
		},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node}}
	s := newTestAPIServer(ted)

	req := explicitPolicyRequest(false, "16003")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := s.validateSIDs(req, segmentList)
	assert.NoError(t, err)
}

func TestValidateSIDs_UnknownSegmentTypeIsRejected(t *testing.T) {
	s := newTestAPIServer(nil)
	req := explicitPolicyRequest(true, "16099")
	segmentList := []table.Segment{unknownSegment{}}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "unrecognized SID family")
}

func TestValidateSIDs_MixedSegmentTypesAreRejected(t *testing.T) {
	s := newTestAPIServer(nil)
	req := explicitPolicyRequest(true, "16099")
	segmentList := []table.Segment{
		table.NewSegmentSRMPLS(16099),
		table.SegmentSRv6{Sid: netip.MustParseAddr("2001:db8::1")},
	}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "mixed SR-MPLS and SRv6 SIDs")
}

func TestServe_InvalidAddress(t *testing.T) {
	s := &APIServer{grpcServer: grpc.NewServer(), logger: logger.NewNop()}
	require.Error(t, s.Serve("", "50052"))
}

func TestServe_InvalidPort(t *testing.T) {
	s := &APIServer{grpcServer: grpc.NewServer(), logger: logger.NewNop()}
	require.Error(t, s.Serve("127.0.0.1", "notaport"))
}

func TestServe_PortOutOfRange(t *testing.T) {
	s := &APIServer{grpcServer: grpc.NewServer(), logger: logger.NewNop()}
	require.Error(t, s.Serve("127.0.0.1", "70000"))
}

func TestServe_ListenFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to reserve a port")
	t.Cleanup(func() {
		assert.NoError(t, ln.Close(), "failed to close listener")
	})

	addr, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	s := &APIServer{grpcServer: grpc.NewServer(), logger: logger.NewNop()}
	require.ErrorContains(t, s.Serve(addr, port), "failed to listen on gRPC port", "expected the already-bound port to be rejected")
}

func TestServe_ReturnsNilWhenAlreadyStoppedBeforeServing(t *testing.T) {
	grpcServer := grpc.NewServer()
	grpcServer.GracefulStop() // simulate cancellation winning the startup race

	s := &APIServer{grpcServer: grpcServer, logger: logger.NewNop()}
	assert.NoError(t, s.Serve("127.0.0.1", "0"), "grpc.ErrServerStopped from the startup race should not be reported as a failure")
}

func TestServe_ListensAndLogsActualAddr(t *testing.T) {
	lg, logs := logger.NewRecorder(logger.LevelInfo)
	s := &APIServer{grpcServer: grpc.NewServer(), logger: lg}

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve("127.0.0.1", "0") }()

	require.Eventually(t, func() bool {
		return len(logs.FilterByMessage("Start listening on gRPC port")) > 0
	}, 2*time.Second, 10*time.Millisecond, "expected listenInfo to be logged")

	s.grpcServer.GracefulStop()
	require.NoError(t, <-errCh)

	entries := logs.FilterByMessage("Start listening on gRPC port")
	require.Len(t, entries, 1)
	listenInfo, _ := entries[0].Fields["listenInfo"].(string)
	require.NotEmpty(t, listenInfo, "expected listenInfo to be logged")
	assert.False(t, strings.HasSuffix(listenInfo, ":0"), "expected the actual bound port, got %s", listenInfo)
}

func TestConvertLsPrefixes_SidIndexPresence(t *testing.T) {
	tests := []struct {
		name         string
		prefix       *table.LsPrefix
		wantSet      bool
		wantSidIndex uint32
	}{
		{
			name:    "no Prefix-SID",
			prefix:  &table.LsPrefix{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
			wantSet: false,
		},
		{
			name:         "Prefix-SID index 0",
			prefix:       &table.LsPrefix{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
			wantSet:      true,
			wantSidIndex: 0,
		},
		{
			name:         "Prefix-SID index 16000",
			prefix:       &table.LsPrefix{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 16000, HasSidIndex: true},
			wantSet:      true,
			wantSidIndex: 16000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertLsPrefixes([]*table.LsPrefix{tt.prefix})
			require.Len(t, got, 1)
			require.Equal(t, tt.wantSet, got[0].SidIndex != nil, "sid_index set")
			if tt.wantSet {
				assert.Equal(t, tt.wantSidIndex, got[0].GetSidIndex())
			}
		})
	}
}

func TestGetSessionList_DeduplicatesNonAdjacentCapabilities(t *testing.T) {
	session := &Session{
		peerAddr:  netip.MustParseAddr("10.0.0.1"),
		syncState: lspDBSyncFinished,
		advertisedCapabilities: []pcep.CapabilityInterface{
			&pcep.SRPCECapability{IsNAISupported: true},
			&pcep.SRv6PCECapability{IsNAISupported: true},
			&pcep.SRPCECapability{IsNAISupported: true},
		},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Sessions[0].LocalCapabilities, 2)

	sr := resp.Sessions[0].LocalCapabilities[0]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_SR, sr.GetType())
	assert.True(t, sr.GetSr().GetNaiSupported())

	srv6 := resp.Sessions[0].LocalCapabilities[1]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_SRV6, srv6.GetType())
	assert.True(t, srv6.GetSrv6().GetNaiSupported())
}

func TestGetSessionList_BuildsStructuredCapabilities(t *testing.T) {
	session := &Session{
		peerAddr:  netip.MustParseAddr("10.0.0.1"),
		syncState: lspDBSyncFinished,
		advertisedCapabilities: []pcep.CapabilityInterface{
			&pcep.SRPCECapability{IsNAISupported: true, MaximumSidDepth: 10},
			&pcep.LSPDBVersion{VersionNumber: 42},
		},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Sessions[0].LocalCapabilities, 2)

	sr := resp.Sessions[0].LocalCapabilities[0]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_SR, sr.GetType())
	assert.Equal(t, uint32(10), sr.GetSr().GetMsd())
	assert.True(t, sr.GetSr().GetNaiSupported())

	dbVersion := resp.Sessions[0].LocalCapabilities[1]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_LSP_DB_VERSION, dbVersion.GetType())
	assert.Equal(t, uint64(42), dbVersion.GetLspDbVersion().GetVersionNumber())
}

type failingCapability struct {
	pcep.SRPCECapability
}

func (c *failingCapability) Serialize() ([]byte, error) {
	return nil, errors.New("serialize failure")
}

func TestGetSessionList_SkipsCapabilityOnSerializeError(t *testing.T) {
	lg, logs := logger.NewRecorder(logger.LevelWarn)
	session := &Session{
		peerAddr:  netip.MustParseAddr("10.0.0.1"),
		syncState: lspDBSyncFinished,
		advertisedCapabilities: []pcep.CapabilityInterface{
			&failingCapability{},
			&pcep.SRv6PCECapability{IsNAISupported: true},
		},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: lg,
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Sessions[0].LocalCapabilities, 1, "the failing capability must be skipped")

	srv6 := resp.Sessions[0].LocalCapabilities[0]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_SRV6, srv6.GetType())
	assert.Len(t, logs.FilterByMessage("failed to serialize advertised capability"), 1)
}

func TestGetSessionList_MultipathCapabilityDoesNotSetMsd(t *testing.T) {
	session := &Session{
		peerAddr:  netip.MustParseAddr("10.0.0.1"),
		syncState: lspDBSyncFinished,
		advertisedCapabilities: []pcep.CapabilityInterface{
			pcep.NewMultipathCapability(8, true, true, true, true),
		},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Sessions[0].LocalCapabilities, 1)

	multipath := resp.Sessions[0].LocalCapabilities[0]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_MULTIPATH, multipath.GetType())
	assert.Nil(t, multipath.GetSr(), "MaxMultipaths must not be reported via the SR capability's Msd (Maximum SID Depth)")
	assert.Equal(t, uint32(8), multipath.GetMultipath().GetMaxMultipaths())
}

func TestGetSessionList_ReportsLocalAndPccTimersAndSessionID(t *testing.T) {
	session := &Session{
		peerAddr:  netip.MustParseAddr("10.0.0.1"),
		syncState: lspDBSyncFinished,
		state:     sessionStateUp,
		localOpen: &OpenParams{SessionID: 3, Keepalive: 30, DeadTimer: 120},
		pccOpen:   &OpenParams{SessionID: 7, Keepalive: 10, DeadTimer: 40},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)

	got := resp.Sessions[0]
	assert.Equal(t, pb.SessionState_SESSION_STATE_UP, got.GetState())
	assert.Equal(t, uint32(3), got.GetLocalSessionId())
	assert.Equal(t, uint32(7), got.GetPeerSessionId())
	assert.Equal(t, uint32(30), got.GetLocalTimers().GetKeepalive())
	assert.Equal(t, uint32(120), got.GetLocalTimers().GetDeadTimer())
	assert.Equal(t, uint32(10), got.GetPeerTimers().GetKeepalive())
	assert.Equal(t, uint32(40), got.GetPeerTimers().GetDeadTimer())
	assert.Equal(t, uint32(30), got.GetEffectiveTimers().GetKeepalive())
	assert.Equal(t, uint32(40), got.GetEffectiveTimers().GetDeadTimer())
}

func TestGetSessionList_LeavesAdvertisedValuesUnsetBeforeTheOpenExchange(t *testing.T) {
	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{peerAddr: netip.MustParseAddr("10.0.0.1"), state: sessionStateOpenWait},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)

	got := resp.Sessions[0]
	assert.Equal(t, pb.SessionState_SESSION_STATE_OPEN_WAIT, got.GetState())
	assert.Nil(t, got.LocalSessionId, "a SID of 0 must be distinguishable from an unsent Open message")
	assert.Nil(t, got.PeerSessionId, "a SID of 0 must be distinguishable from an unreceived Open message")
	assert.Nil(t, got.GetLocalTimers())
	assert.Nil(t, got.GetPeerTimers())
}

func TestGetSessionList_ReportsZeroPccSessionIDAsAdvertised(t *testing.T) {
	s := &APIServer{
		pce: &Server{sessionList: []*Session{{
			peerAddr:  netip.MustParseAddr("10.0.0.1"),
			state:     sessionStateUp,
			localOpen: &OpenParams{SessionID: 0, Keepalive: 30, DeadTimer: 120},
			pccOpen:   &OpenParams{SessionID: 0, Keepalive: 0, DeadTimer: 0},
		}}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)

	got := resp.Sessions[0]
	require.NotNil(t, got.LocalSessionId, "SID 0 is valid on the wire and must be reported")
	assert.Zero(t, got.GetLocalSessionId())
	require.NotNil(t, got.PeerSessionId)
	assert.Zero(t, got.GetPeerSessionId())
	assert.Zero(t, got.GetEffectiveTimers().GetDeadTimer())
}

func TestGetSessionList_SortsSessionsByAddr(t *testing.T) {
	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{peerAddr: netip.MustParseAddr("10.0.0.2")},
			{peerAddr: netip.MustParseAddr("10.0.0.1")},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 2)

	addr0, _ := netip.AddrFromSlice(resp.Sessions[0].GetPeerAddr())
	addr1, _ := netip.AddrFromSlice(resp.Sessions[1].GetPeerAddr())
	assert.Equal(t, "10.0.0.1", addr0.String())
	assert.Equal(t, "10.0.0.2", addr1.String())
}

func TestGetSessionList_FiltersBySessionAddr(t *testing.T) {
	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{peerAddr: netip.MustParseAddr("10.0.0.1")},
			{peerAddr: netip.MustParseAddr("10.0.0.2")},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{PeerAddr: netip.MustParseAddr("10.0.0.2").AsSlice()})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	addr, _ := netip.AddrFromSlice(resp.Sessions[0].GetPeerAddr())
	assert.Equal(t, "10.0.0.2", addr.String())
}

func TestGetSessionList_RejectsInvalidSessionFilter(t *testing.T) {
	s := &APIServer{
		pce:    &Server{},
		logger: logger.NewNop(),
	}

	_, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{PeerAddr: []byte{1, 2, 3}})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetSessionList_IncludeStatsControlsStatsPresence(t *testing.T) {
	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{peerAddr: netip.MustParseAddr("10.0.0.1")},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	assert.Nil(t, resp.Sessions[0].GetStats(), "Stats must be nil unless include_stats is set")

	resp, err = s.GetSessionList(context.Background(), &pb.GetSessionListRequest{IncludeStats: true})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	assert.NotNil(t, resp.Sessions[0].GetStats(), "Stats must be populated when include_stats is set")
}

func TestGetSRPolicyList_FillsMissingFieldsAndOrdersDeterministically(t *testing.T) {
	seg, err := table.NewSegment("16003")
	require.NoError(t, err)

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}
	srcNode := table.NewLsNode(65000, "0000.0aff.0001")
	srcPrefix := table.NewLsPrefix(srcNode)
	srcPrefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	srcNode.Prefixes = append(srcNode.Prefixes, srcPrefix)
	ted.Nodes[srcNode.RouterID] = srcNode

	session2 := &Session{
		peerAddr:  netip.MustParseAddr("10.0.0.2"),
		syncState: lspDBSyncFinished,
		srPolicies: []*table.SRPolicy{
			table.NewSRPolicy(1, "policy-b", []table.Segment{seg},
				netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20"),
				200, 100, 5, table.PolicyUp),
		},
	}
	session1 := &Session{
		peerAddr:  netip.MustParseAddr("10.0.0.1"),
		syncState: lspDBSyncFinished,
		srPolicies: []*table.SRPolicy{
			table.NewSRPolicy(2, "policy-a", []table.Segment{seg},
				netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20"),
				100, 100, 7, table.PolicyActive),
		},
	}

	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session2, session1}, ted: ted},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 2)

	// Verify ordering is independent of insertion order.
	addr0, _ := netip.AddrFromSlice(resp.Sessions[0].GetPeerAddr())
	assert.Equal(t, "10.0.0.1", addr0.String())
	require.Len(t, resp.Sessions[0].GetSrPolicies(), 1)

	policy := resp.Sessions[0].GetSrPolicies()[0]
	assert.Equal(t, uint32(2), policy.GetPlspId())
	assert.Equal(t, uint32(7), policy.GetLspId())
	assert.Equal(t, pb.SRPolicyState_SR_POLICY_STATE_ACTIVE, policy.GetState())
	assert.Equal(t, "0000.0aff.0001", policy.GetSrcRouterId())
	assert.Empty(t, policy.GetDstRouterId(), "no TED node owns the destination address")
}

func TestGetSRPolicyList_IncludesUnsyncedSessions(t *testing.T) {
	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{peerAddr: netip.MustParseAddr("10.0.0.1"), syncState: lspDBSyncPending},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1, "unsynced sessions must still be reported so callers can see why policies are missing")
	assert.Equal(t, pb.LspDbSyncState_LSP_DB_SYNC_STATE_PENDING, resp.Sessions[0].GetSyncState())
	assert.Empty(t, resp.Sessions[0].GetSrPolicies())
}

func TestGetSRPolicyList_FiltersBySessionAddr(t *testing.T) {
	seg, err := table.NewSegment("16003")
	require.NoError(t, err)

	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{
				peerAddr:  netip.MustParseAddr("10.0.0.1"),
				syncState: lspDBSyncFinished,
				srPolicies: []*table.SRPolicy{
					table.NewSRPolicy(1, "policy-a", []table.Segment{seg}, netip.Addr{}, netip.Addr{}, 100, 100, 0, table.PolicyUp),
				},
			},
			{
				peerAddr:  netip.MustParseAddr("10.0.0.2"),
				syncState: lspDBSyncFinished,
				srPolicies: []*table.SRPolicy{
					table.NewSRPolicy(2, "policy-b", []table.Segment{seg}, netip.Addr{}, netip.Addr{}, 200, 100, 0, table.PolicyUp),
				},
			},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{PeerAddr: netip.MustParseAddr("10.0.0.2").AsSlice()})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	addr, _ := netip.AddrFromSlice(resp.Sessions[0].GetPeerAddr())
	assert.Equal(t, "10.0.0.2", addr.String())
}

func TestGetSRPolicyList_RejectsInvalidSessionFilter(t *testing.T) {
	s := &APIServer{
		pce:    &Server{},
		logger: logger.NewNop(),
	}

	_, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{PeerAddr: []byte{1, 2, 3}})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestResolveSRPolicyIntent(t *testing.T) {
	tests := []struct {
		name               string
		policy             *pb.SRPolicy
		disablePathCompute bool
		metricType         table.MetricType
		wantType           table.PolicyType
		wantMetric         table.MetricType
		wantErr            bool
	}{
		{
			name:               "disable_path_compute is always explicit regardless of Type",
			policy:             &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC},
			disablePathCompute: true,
			metricType:         table.TEMetric,
			wantType:           table.PolicyTypeExplicit,
			wantMetric:         table.UnspecifiedMetric,
		},
		{
			name:       "explicit path has no metric",
			policy:     &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT},
			metricType: table.TEMetric,
			wantType:   table.PolicyTypeExplicit,
			wantMetric: table.UnspecifiedMetric,
		},
		{
			name:       "dynamic path passes through the already-resolved metric",
			policy:     &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC},
			metricType: table.TEMetric,
			wantType:   table.PolicyTypeDynamic,
			wantMetric: table.TEMetric,
		},
		{
			name:    "unspecified type is an error",
			policy:  &pb.SRPolicy{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotMetric, err := resolveSRPolicyIntent(tt.policy, tt.disablePathCompute, tt.metricType)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantType, gotType)
			assert.Equal(t, tt.wantMetric, gotMetric)
		})
	}
}

func TestGetSRPolicyList_RoundTripsTypeAndMetric(t *testing.T) {
	seg, err := table.NewSegment("16003")
	require.NoError(t, err)

	knownPolicy := table.NewSRPolicy(1, "policy-known", []table.Segment{seg}, netip.Addr{}, netip.Addr{}, 100, 100, 0, table.PolicyUp)
	knownPolicy.Type = table.PolicyTypeDynamic
	knownPolicy.Metric = table.DelayMetric

	unknownPolicy := table.NewSRPolicy(2, "policy-unknown", []table.Segment{seg}, netip.Addr{}, netip.Addr{}, 200, 100, 0, table.PolicyUp)

	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{
				peerAddr:   netip.MustParseAddr("10.0.0.1"),
				syncState:  lspDBSyncFinished,
				srPolicies: []*table.SRPolicy{knownPolicy, unknownPolicy},
			},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Sessions[0].GetSrPolicies(), 2)

	byColor := map[uint32]*pb.SRPolicy{}
	for _, p := range resp.Sessions[0].GetSrPolicies() {
		byColor[p.GetColor()] = p
	}

	known := byColor[100]
	require.NotNil(t, known)
	assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, known.GetType())
	assert.Equal(t, pb.MetricType_METRIC_TYPE_DELAY, known.GetMetric())

	unknown := byColor[200]
	require.NotNil(t, unknown)
	assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED, unknown.GetType())
	assert.Equal(t, pb.MetricType_METRIC_TYPE_UNSPECIFIED, unknown.GetMetric())
}

func TestConvertSegment_CarriesSRv6NAIAndStructure(t *testing.T) {
	sid := netip.MustParseAddr("2001:db8:1005::")
	seg := table.SegmentSRv6{
		Sid:        sid,
		LocalAddr:  netip.MustParseAddr("2001:db8::5"),
		RemoteAddr: netip.MustParseAddr("2001:db8::6"),
		Structure:  table.SIDStructureBytes{32, 16, 0, 80},
	}

	pbSeg := convertSegment(seg)
	assert.Equal(t, sid.String(), pbSeg.GetSid())
	assert.Equal(t, "2001:db8::5", pbSeg.GetLocalAddr())
	assert.Equal(t, "2001:db8::6", pbSeg.GetRemoteAddr())
	assert.Equal(t, "32,16,0,80", pbSeg.GetSidStructure())
}

func TestConvertSegment_SRMPLS(t *testing.T) {
	tests := []struct {
		name       string
		localAddr  netip.Addr
		remoteAddr netip.Addr
	}{
		{name: "localAddr only", localAddr: netip.MustParseAddr("192.0.2.1")},
		{name: "remoteAddr only", remoteAddr: netip.MustParseAddr("192.0.2.2")},
		{
			name:       "localAddr and remoteAddr",
			localAddr:  netip.MustParseAddr("192.0.2.1"),
			remoteAddr: netip.MustParseAddr("192.0.2.2"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg := table.SegmentSRMPLS{Sid: 16003, LocalAddr: tt.localAddr, RemoteAddr: tt.remoteAddr}

			pbSeg := convertSegment(seg)
			assert.Equal(t, "16003", pbSeg.GetSid())
			if tt.localAddr.IsValid() {
				assert.Equal(t, tt.localAddr.String(), pbSeg.GetLocalAddr())
			} else {
				assert.Empty(t, pbSeg.GetLocalAddr())
			}
			if tt.remoteAddr.IsValid() {
				assert.Equal(t, tt.remoteAddr.String(), pbSeg.GetRemoteAddr())
			} else {
				assert.Empty(t, pbSeg.GetRemoteAddr())
			}
		})
	}
}

func TestConvertSegment_SRMPLS_SidAbsent(t *testing.T) {
	seg := table.SegmentSRMPLS{SidAbsent: true, LocalAddr: netip.MustParseAddr("192.0.2.1")}

	pbSeg := convertSegment(seg)
	assert.True(t, pbSeg.GetSidAbsent())

	enriched, err := newEnrichedSegment(pbSeg, false)
	require.NoError(t, err)
	mplsSeg, ok := enriched.(table.SegmentSRMPLS)
	require.True(t, ok)
	assert.True(t, mplsSeg.SidAbsent)
	assert.Equal(t, "192.0.2.1", mplsSeg.LocalAddr.String())
}

func TestTED_ConcurrentUpdate(_ *testing.T) {
	s := &Server{ted: &table.LsTED{Nodes: map[string]*table.LsNode{}}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			node := table.NewLsNode(1, "router")
			prefix := table.NewLsPrefix(node)
			prefix.Prefix = netip.MustParsePrefix("192.0.2.1/32")
			node.Prefixes = append(node.Prefixes, prefix)
			s.setTED(&table.LsTED{Nodes: map[string]*table.LsNode{"router": node}})
		}
	}()

	for range 100 {
		_ = s.TED().RouterIDIndex()
	}
	<-done
}

func TestSessionList_ConcurrentAccess(_ *testing.T) {
	s := &Server{}
	addr := netip.MustParseAddr("192.0.2.1")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 100 {
			ss := &Session{localSessionID: uint8(i), peerAddr: addr, syncState: lspDBSyncFinished}

			s.sessionMu.Lock()
			s.sessionList = append(s.sessionList, ss)
			s.sessionMu.Unlock()

			s.sessionMu.Lock()
			for j, v := range s.sessionList {
				if v.localSessionID == ss.localSessionID {
					s.sessionList[j] = s.sessionList[len(s.sessionList)-1]
					s.sessionList = s.sessionList[:len(s.sessionList)-1]
					break
				}
			}
			s.sessionMu.Unlock()
		}
	}()

	for range 100 {
		s.SearchSession(addr)
		for _, ss := range s.Sessions() {
			ss.SRPolicies()
		}
	}
	<-done
}

func TestDeleteSRPolicy_SrcAddrOmitted(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	peerAddr := netip.MustParseAddr("10.0.255.1")
	dstAddr := netip.MustParseAddr("10.255.0.2")

	ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
	ss.syncState = lspDBSyncFinished
	ss.srPolicies = []*table.SRPolicy{
		{
			PlspID:     1,
			Name:       testSRPolicyName,
			DstAddr:    dstAddr,
			Color:      100,
			Preference: 100,
		},
	}

	pce := &Server{sessionList: []*Session{ss}}
	apiServer := &APIServer{pce: pce, logger: logger.NewNop()}

	req := &pb.DeleteSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			PeerAddr:   peerAddr.AsSlice(),
			DstAddr:    dstAddr.AsSlice(),
			Color:      100,
			PolicyName: testSRPolicyName,
		},
	}

	_, err := apiServer.DeleteSRPolicy(context.Background(), req)
	require.NoError(t, err)
}

func TestGetSegmentList_DynamicHopcountPrefersFewerHops(t *testing.T) {
	mkNode := func(routerID string, sidIndex uint32) *table.LsNode {
		return &table.LsNode{
			RouterID:  routerID,
			SrgbBegin: 16000,
			SrgbEnd:   17000,
			Prefixes: []*table.LsPrefix{
				{Prefix: netip.MustParsePrefix(fmt.Sprintf("10.0.0.%d/32", sidIndex)), SidIndex: sidIndex, HasSidIndex: true},
			},
		}
	}
	nodeA := mkNode("A", 1)
	nodeB := mkNode("B", 2)
	nodeD := mkNode("D", 4)
	nodeA.Links = []*table.LsLink{table.NewLsLink(nodeA, nodeD), table.NewLsLink(nodeA, nodeB)}
	nodeB.Links = []*table.LsLink{table.NewLsLink(nodeB, nodeD)}

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{"A": nodeA, "B": nodeB, "D": nodeD}}

	srPolicy := &pb.SRPolicy{
		Type:        pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
		SrcRouterId: "A",
		DstRouterId: "D",
		Metric:      pb.MetricType_METRIC_TYPE_HOPCOUNT,
	}

	segmentList, metricType, err := getSegmentList(srPolicy, ted, false)
	require.NoError(t, err)
	assert.Equal(t, table.HopcountMetric, metricType)
	require.Len(t, segmentList, 1, "expected the direct 1-hop path over the 2-hop detour")

	mplsSeg, ok := segmentList[0].(table.SegmentSRMPLS)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRMPLS", segmentList[0])
	assert.Equal(t, uint32(16004), mplsSeg.Sid)
}

func TestGetSegmentList_DynamicWithWaypointsForcesTransit(t *testing.T) {
	mkNode := func(routerID string, sidIndex uint32) *table.LsNode {
		return &table.LsNode{
			RouterID:  routerID,
			SrgbBegin: 16000,
			SrgbEnd:   17000,
			Prefixes: []*table.LsPrefix{
				{Prefix: netip.MustParsePrefix(fmt.Sprintf("10.0.0.%d/32", sidIndex)), SidIndex: sidIndex, HasSidIndex: true},
			},
		}
	}
	nodeA := mkNode("A", 1)
	nodeB := mkNode("B", 2)
	nodeD := mkNode("D", 4)
	nodeA.Links = []*table.LsLink{table.NewLsLink(nodeA, nodeD), table.NewLsLink(nodeA, nodeB)}
	nodeB.Links = []*table.LsLink{table.NewLsLink(nodeB, nodeD)}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{"A": nodeA, "B": nodeB, "D": nodeD}}

	srPolicy := &pb.SRPolicy{
		Type:        pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
		SrcRouterId: "A",
		DstRouterId: "D",
		Metric:      pb.MetricType_METRIC_TYPE_HOPCOUNT,
		Waypoints:   []*pb.Waypoint{{RouterId: "B"}},
	}

	segmentList, metricType, err := getSegmentList(srPolicy, ted, false)
	require.NoError(t, err)
	assert.Equal(t, table.HopcountMetric, metricType)
	require.Len(t, segmentList, 2, "expected the direct 1-hop A-D path to be overridden by the B waypoint")

	firstHop, ok := segmentList[0].(table.SegmentSRMPLS)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRMPLS", segmentList[0])
	assert.Equal(t, uint32(16002), firstHop.Sid, "first hop must be the waypoint node B")

	secondHop, ok := segmentList[1].(table.SegmentSRMPLS)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRMPLS", segmentList[1])
	assert.Equal(t, uint32(16004), secondHop.Sid, "second hop must be the destination node D")
}

func TestGetSegmentList_Explicit(t *testing.T) {
	tests := []struct {
		name    string
		policy  *pb.SRPolicy
		wantErr bool
		wantLen int
	}{
		{
			name:    "converts every segment",
			policy:  &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, SegmentList: []*pb.Segment{{Sid: "16003"}, {Sid: "16004"}}},
			wantLen: 2,
		},
		{
			name:    "empty segment list is an error",
			policy:  &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT},
			wantErr: true,
		},
		{
			name:    "malformed segment SID propagates the error",
			policy:  &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, SegmentList: []*pb.Segment{{Sid: invalidSidStr}}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, metricType, err := getSegmentList(tt.policy, &table.LsTED{}, false)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, table.UnspecifiedMetric, metricType)
			assert.Len(t, got, tt.wantLen)
		})
	}
}

func TestGetSegmentList_DynamicMetricError(t *testing.T) {
	policy := &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, Metric: pb.MetricType_METRIC_TYPE_UNSPECIFIED}
	_, _, err := getSegmentList(policy, &table.LsTED{Nodes: map[string]*table.LsNode{}}, false)
	assert.Error(t, err, "expected an unresolvable metric to be rejected before CSPF runs")
}

func TestGetSegmentList_UndefinedType(t *testing.T) {
	_, _, err := getSegmentList(&pb.SRPolicy{}, &table.LsTED{}, false)
	assert.Error(t, err)
}

func TestGetMetricType(t *testing.T) {
	tests := []struct {
		name    string
		in      pb.MetricType
		want    table.MetricType
		wantErr bool
	}{
		{name: "IGP", in: pb.MetricType_METRIC_TYPE_IGP, want: table.IGPMetric},
		{name: "TE", in: pb.MetricType_METRIC_TYPE_TE, want: table.TEMetric},
		{name: "delay", in: pb.MetricType_METRIC_TYPE_DELAY, want: table.DelayMetric},
		{name: "hopcount", in: pb.MetricType_METRIC_TYPE_HOPCOUNT, want: table.HopcountMetric},
		{name: "unspecified is an error", in: pb.MetricType_METRIC_TYPE_UNSPECIFIED, wantErr: true},
		{name: "value outside the enum is an error", in: pb.MetricType(99), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getMetricType(tt.in)
			if tt.wantErr {
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, codes.InvalidArgument, st.Code())
				var gotReason string
				for _, d := range st.Details() {
					if info, ok := d.(*errdetails.ErrorInfo); ok {
						gotReason = info.Reason
					}
				}
				assert.Equal(t, ReasonInvalidRequest, gotReason)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestToPBPolicyType(t *testing.T) {
	tests := []struct {
		name string
		in   table.PolicyType
		want pb.SRPolicyType
	}{
		{name: "explicit", in: table.PolicyTypeExplicit, want: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT},
		{name: "dynamic", in: table.PolicyTypeDynamic, want: pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC},
		{name: "unrecognized maps to unspecified", in: table.PolicyType("bogus"), want: pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toPBPolicyType(tt.in))
		})
	}
}

func TestToPBMetricType(t *testing.T) {
	tests := []struct {
		name string
		in   table.MetricType
		want pb.MetricType
	}{
		{name: "igp", in: table.IGPMetric, want: pb.MetricType_METRIC_TYPE_IGP},
		{name: "te", in: table.TEMetric, want: pb.MetricType_METRIC_TYPE_TE},
		{name: "delay", in: table.DelayMetric, want: pb.MetricType_METRIC_TYPE_DELAY},
		{name: "hopcount", in: table.HopcountMetric, want: pb.MetricType_METRIC_TYPE_HOPCOUNT},
		{name: "unspecified maps to unspecified", in: table.UnspecifiedMetric, want: pb.MetricType_METRIC_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toPBMetricType(tt.in))
		})
	}
}

func TestToPBPolicyState(t *testing.T) {
	tests := []struct {
		name string
		in   table.PolicyState
		want pb.SRPolicyState
	}{
		{name: "down", in: table.PolicyDown, want: pb.SRPolicyState_SR_POLICY_STATE_DOWN},
		{name: "up", in: table.PolicyUp, want: pb.SRPolicyState_SR_POLICY_STATE_UP},
		{name: "active", in: table.PolicyActive, want: pb.SRPolicyState_SR_POLICY_STATE_ACTIVE},
		{name: "unknown", in: table.PolicyUnknown, want: pb.SRPolicyState_SR_POLICY_STATE_UNKNOWN},
		{name: "unrecognized maps to unspecified", in: table.PolicyState("bogus"), want: pb.SRPolicyState_SR_POLICY_STATE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toPBPolicyState(tt.in))
		})
	}
}

func TestGetSRPolicyList_SortsBySameColorThenPlspIdThenName(t *testing.T) {
	mk := func(color, plspID uint32, name string) *table.SRPolicy {
		return table.NewSRPolicy(plspID, name, nil, netip.Addr{}, netip.Addr{}, color, 100, 0, table.PolicyUp)
	}

	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{
				peerAddr:  netip.MustParseAddr("10.0.0.1"),
				syncState: lspDBSyncFinished,
				srPolicies: []*table.SRPolicy{
					mk(200, 1, "z"),
					mk(100, 1, "z"),
					mk(100, 2, "b"),
					mk(100, 2, "a"),
					mk(100, 1, "y"),
				},
			},
		}},
		logger: logger.NewNop(),
	}

	resp, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)

	var gotOrder []string
	for _, p := range resp.Sessions[0].GetSrPolicies() {
		gotOrder = append(gotOrder, fmt.Sprintf("%d/%d/%s", p.GetColor(), p.GetPlspId(), p.GetPolicyName()))
	}
	assert.Equal(t, []string{"100/1/y", "100/1/z", "100/2/a", "100/2/b", "200/1/z"}, gotOrder)
}

func TestNewAPIServer(t *testing.T) {
	grpcServer := grpc.NewServer()
	pce := &Server{}
	lg := logger.NewNop()

	s := NewAPIServer(pce, grpcServer, true, lg)

	assert.Same(t, pce, s.pce)
	assert.Same(t, grpcServer, s.grpcServer)
	assert.True(t, s.usidMode)

	_, ok := grpcServer.GetServiceInfo()["api.pola.v1.PCEService"]
	assert.True(t, ok, "expected the PCE service to be registered with the gRPC server")
}

func TestValidateCreateSRPolicy(t *testing.T) {
	tests := []struct {
		name               string
		req                *pb.CreateSRPolicyRequest
		disablePathCompute bool
		wantErr            bool
	}{
		{
			name: "path-compute request valid",
			req: &pb.CreateSRPolicyRequest{
				Asn: 65000,
				SrPolicy: &pb.SRPolicy{
					PeerAddr:    netip.MustParseAddr("10.0.0.1").AsSlice(),
					Color:       100,
					SrcRouterId: "r1",
					DstRouterId: "r2",
				},
			},
		},
		{
			name: "path-compute request missing router IDs",
			req: &pb.CreateSRPolicyRequest{
				Asn:      65000,
				SrPolicy: &pb.SRPolicy{PeerAddr: netip.MustParseAddr("10.0.0.1").AsSlice(), Color: 100},
			},
			wantErr: true,
		},
		{
			name: "disable_path_compute request valid",
			req: &pb.CreateSRPolicyRequest{
				SrPolicy: &pb.SRPolicy{
					PeerAddr:    netip.MustParseAddr("10.0.0.1").AsSlice(),
					Color:       100,
					SrcAddr:     netip.MustParseAddr("10.0.0.1").AsSlice(),
					DstAddr:     netip.MustParseAddr("10.0.0.2").AsSlice(),
					SegmentList: []*pb.Segment{{Sid: "16003"}},
				},
				DisablePathCompute: true,
			},
			disablePathCompute: true,
		},
		{
			name: "disable_path_compute request missing segment list",
			req: &pb.CreateSRPolicyRequest{
				SrPolicy: &pb.SRPolicy{
					PeerAddr: netip.MustParseAddr("10.0.0.1").AsSlice(),
					Color:    100,
					SrcAddr:  netip.MustParseAddr("10.0.0.1").AsSlice(),
					DstAddr:  netip.MustParseAddr("10.0.0.2").AsSlice(),
				},
				DisablePathCompute: true,
			},
			disablePathCompute: true,
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCreateSRPolicy(tt.req, tt.disablePathCompute)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestGetLoopbackAddr(t *testing.T) {
	node := &table.LsNode{
		RouterID: "r1",
		Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}},
	}
	noLoopbackNode := &table.LsNode{
		RouterID: "r2",
		Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.0/24")}},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{node.RouterID: node, noLoopbackNode.RouterID: noLoopbackNode, "r3": nil}}

	addr, err := getLoopbackAddr(ted, "r1")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", addr.String())

	_, err = getLoopbackAddr(ted, "missing")
	require.ErrorContains(t, err, "no node with router ID missing")

	_, err = getLoopbackAddr(ted, "r2")
	require.Error(t, err, "expected an error for a node without a loopback address")

	_, err = getLoopbackAddr(ted, "r3")
	require.ErrorContains(t, err, "no node with router ID r3")

	_, err = getLoopbackAddr(nil, "r1")
	assert.ErrorContains(t, err, "no node with router ID r1")
}

func TestGetSyncedPCEPSession(t *testing.T) {
	peerAddr := netip.MustParseAddr("10.0.255.1")
	ss := &Session{peerAddr: peerAddr, syncState: lspDBSyncFinished}
	pce := &Server{sessionList: []*Session{ss}}

	got, err := getSyncedPCEPSession(pce, peerAddr.AsSlice())
	require.NoError(t, err)
	assert.Same(t, ss, got)

	_, err = getSyncedPCEPSession(pce, []byte{1, 2, 3})
	require.Error(t, err, "expected an error for a malformed address")

	_, err = getSyncedPCEPSession(pce, netip.MustParseAddr("10.0.255.2").AsSlice())
	assert.Error(t, err, "expected an error when no synced session matches")
}

func TestResolveSession(t *testing.T) {
	peerAddr := netip.MustParseAddr("10.0.255.1")

	t.Run("the peer address identifies the session", func(t *testing.T) {
		ss := &Session{peerAddr: peerAddr, syncState: lspDBSyncFinished}
		pce := &Server{sessionList: []*Session{ss}}

		got, err := resolveSession(pce, peerAddr.AsSlice(), true)
		require.NoError(t, err)
		assert.Same(t, ss, got)
	})

	t.Run("no session is NotFound", func(t *testing.T) {
		pce := &Server{}

		_, err := resolveSession(pce, peerAddr.AsSlice(), true)
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Equal(t, ReasonPCEPSessionNotFound, errInfoReason(t, err))
	})

	t.Run("an unsynced session reports not synced", func(t *testing.T) {
		ss := &Session{peerAddr: peerAddr, syncState: lspDBSyncPending}
		pce := &Server{sessionList: []*Session{ss}}

		_, err := resolveSession(pce, peerAddr.AsSlice(), true)
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.Equal(t, ReasonPCEPSessionNotSynced, errInfoReason(t, err))
	})

	t.Run("requireSynced false accepts an unsynced session", func(t *testing.T) {
		ss := &Session{peerAddr: peerAddr, syncState: lspDBSyncPending}
		pce := &Server{sessionList: []*Session{ss}}

		got, err := resolveSession(pce, peerAddr.AsSlice(), false)
		require.NoError(t, err)
		assert.Same(t, ss, got)
	})
}

func TestParseSidStructure(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []uint8
		wantErr bool
	}{
		{name: "empty string", in: "", want: nil},
		{name: "valid", in: "32,16,0,80", want: []uint8{32, 16, 0, 80}},
		{name: "wrong part count", in: "1,2,3", wantErr: true},
		{name: "non-numeric part", in: "1,2,3,x", wantErr: true},
		{name: "value out of uint8 range", in: "1,2,3,256", wantErr: true},
		{name: "sum exceeds 128 bits", in: "128,128,128,128", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSidStructure(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseSidStructure_SumExceeds128(t *testing.T) {
	_, err := parseSidStructure("128,128,128,128")
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())

	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			assert.Equal(t, ReasonInvalidRequest, info.GetReason())
			return
		}
	}
	t.Fatal("status has no ErrorInfo details")
}

func TestNewEnrichedSegmentSRv6_Errors(t *testing.T) {
	tests := []struct {
		name    string
		segment *pb.Segment
	}{
		{name: "malformed SID structure", segment: &pb.Segment{Sid: testSRv6SID2, SidStructure: "1,2,3"}},
		{name: "malformed localAddr", segment: &pb.Segment{Sid: testSRv6SID2, LocalAddr: invalidAddrLiteral}},
		{name: "malformed remoteAddr", segment: &pb.Segment{Sid: testSRv6SID2, LocalAddr: "2001:db8::5", RemoteAddr: invalidAddrLiteral}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newEnrichedSegment(tt.segment, false)
			assert.Error(t, err)
		})
	}
}

func TestNewEnrichedSegmentSRv6_SubobjectValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		segment *pb.Segment
	}{
		{name: "IPv4 LocalAddr on SRv6 segment", segment: &pb.Segment{Sid: testSRv6SID2, LocalAddr: testAddrA}},
		{name: "RemoteAddr without LocalAddr", segment: &pb.Segment{Sid: testSRv6SID2, RemoteAddr: "2001:db8::6"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newEnrichedSegment(tt.segment, false)
			assert.Error(t, err)
		})
	}
}

func TestNewEnrichedSegmentSRMPLS_SubobjectValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		segment *pb.Segment
	}{
		{name: "RemoteAddr without LocalAddr", segment: &pb.Segment{Sid: "16001", RemoteAddr: testAddrB}},
		{name: "mismatched address families", segment: &pb.Segment{Sid: "16001", LocalAddr: testAddrA, RemoteAddr: testSRv6SID1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newEnrichedSegment(tt.segment, false)
			assert.Error(t, err)
		})
	}
}

func TestResolvePath_PathCompute(t *testing.T) {
	srcNode := &table.LsNode{ASN: 65000, RouterID: "r1", Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}}}
	dstNode := &table.LsNode{ASN: 65000, RouterID: "r2", Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.2/32")}}}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{srcNode.RouterID: srcNode, dstNode.RouterID: dstNode}}

	explicitReq := func() *pb.CreateSRPolicyRequest {
		return &pb.CreateSRPolicyRequest{
			Asn: 65000,
			SrPolicy: &pb.SRPolicy{
				Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
				SrcRouterId: "r1",
				DstRouterId: "r2",
				SegmentList: []*pb.Segment{{Sid: "16003"}},
			},
		}
	}

	t.Run("success resolves loopbacks and segments", func(t *testing.T) {
		s := newTestAPIServer(ted)
		path, err := resolvePath(s, explicitReq(), false)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", path.SrcAddr.String())
		assert.Equal(t, "10.0.0.2", path.DstAddr.String())
		assert.Len(t, path.SegmentList, 1)
	})

	t.Run("TED disabled", func(t *testing.T) {
		s := newTestAPIServer(nil)
		_, err := resolvePath(s, explicitReq(), false)
		assert.ErrorContains(t, err, "ted is disabled")
	})

	t.Run("TED not yet synchronized", func(t *testing.T) {
		s := newTestAPIServer(&table.LsTED{Nodes: map[string]*table.LsNode{}})
		_, err := resolvePath(s, explicitReq(), false)
		assert.ErrorContains(t, err, "no node in TED")
	})

	t.Run("ASN mismatch", func(t *testing.T) {
		s := newTestAPIServer(ted)
		req := explicitReq()
		req.Asn = 1
		_, err := resolvePath(s, req, false)
		assert.ErrorContains(t, err, "does not match ted ASN")
	})

	t.Run("nil TED entry is skipped by the ASN check", func(t *testing.T) {
		nodes := map[string]*table.LsNode{srcNode.RouterID: srcNode, dstNode.RouterID: dstNode, "r0": nil}
		s := newTestAPIServer(&table.LsTED{Nodes: nodes})
		_, err := resolvePath(s, explicitReq(), false)
		require.NoError(t, err)
	})

	t.Run("TED holding only nil entries", func(t *testing.T) {
		s := newTestAPIServer(&table.LsTED{Nodes: map[string]*table.LsNode{"r0": nil}})
		_, err := resolvePath(s, explicitReq(), false)
		assert.ErrorContains(t, err, "no node with router ID r1")
	})

	t.Run("unknown source router ID", func(t *testing.T) {
		s := newTestAPIServer(ted)
		req := explicitReq()
		req.SrPolicy.SrcRouterId = "missing"
		_, err := resolvePath(s, req, false)
		assert.ErrorContains(t, err, "no node with router ID missing")
	})

	t.Run("unknown destination router ID", func(t *testing.T) {
		s := newTestAPIServer(ted)
		req := explicitReq()
		req.SrPolicy.DstRouterId = "missing"
		_, err := resolvePath(s, req, false)
		assert.ErrorContains(t, err, "no node with router ID missing")
	})

	t.Run("segment list resolution error propagates", func(t *testing.T) {
		s := newTestAPIServer(ted)
		req := explicitReq()
		req.SrPolicy.SegmentList = nil
		_, err := resolvePath(s, req, false)
		assert.ErrorContains(t, err, "no segments in SRPolicy input")
	})
}

func TestResolvePath_DisablePathCompute(t *testing.T) {
	disabledReq := func() *pb.CreateSRPolicyRequest {
		return &pb.CreateSRPolicyRequest{
			DisablePathCompute: true,
			SrPolicy: &pb.SRPolicy{
				SrcAddr:     netip.MustParseAddr("10.0.0.1").AsSlice(),
				DstAddr:     netip.MustParseAddr("10.0.0.2").AsSlice(),
				SegmentList: []*pb.Segment{{Sid: "16003"}},
			},
		}
	}

	t.Run("success uses the request addresses and segments verbatim", func(t *testing.T) {
		s := newTestAPIServer(nil)
		path, err := resolvePath(s, disabledReq(), true)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", path.SrcAddr.String())
		assert.Equal(t, "10.0.0.2", path.DstAddr.String())
		assert.Len(t, path.SegmentList, 1)
	})

	t.Run("malformed source address", func(t *testing.T) {
		s := newTestAPIServer(nil)
		req := disabledReq()
		req.SrPolicy.SrcAddr = []byte{1, 2, 3}
		_, err := resolvePath(s, req, true)
		assert.ErrorContains(t, err, "invalid source address")
	})

	t.Run("malformed destination address", func(t *testing.T) {
		s := newTestAPIServer(nil)
		req := disabledReq()
		req.SrPolicy.DstAddr = []byte{1, 2, 3}
		_, err := resolvePath(s, req, true)
		assert.ErrorContains(t, err, "invalid destination address")
	})

	t.Run("malformed segment SID", func(t *testing.T) {
		s := newTestAPIServer(nil)
		req := disabledReq()
		req.SrPolicy.SegmentList = []*pb.Segment{{Sid: invalidSidStr}}
		_, err := resolvePath(s, req, true)
		assert.Error(t, err)
	})
}

func TestCreateSRPolicy(t *testing.T) {
	srcNode := &table.LsNode{ASN: 65000, RouterID: "r1", Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}}}
	dstNode := &table.LsNode{
		ASN: 65000, RouterID: "r2", SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.2/32"), SidIndex: 3, HasSidIndex: true}},
	}
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{srcNode.RouterID: srcNode, dstNode.RouterID: dstNode}}

	baseReq := func() *pb.CreateSRPolicyRequest {
		return &pb.CreateSRPolicyRequest{
			Asn: 65000,
			SrPolicy: &pb.SRPolicy{
				Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
				PolicyName:  testSRPolicyName,
				Color:       100,
				PeerAddr:    netip.MustParseAddr("10.0.255.1").AsSlice(),
				SrcRouterId: "r1",
				DstRouterId: "r2",
				SegmentList: []*pb.Segment{{Sid: "16003"}},
			},
			NoSidValidate: true,
		}
	}

	t.Run("validation error", func(t *testing.T) {
		s := newTestAPIServer(ted)
		req := baseReq()
		req.Asn = 0
		_, err := s.CreateSRPolicy(context.Background(), req)
		assert.ErrorContains(t, err, "failed to validate SR policy creation")
	})

	t.Run("resolve path error", func(t *testing.T) {
		s := newTestAPIServer(nil)
		_, err := s.CreateSRPolicy(context.Background(), baseReq())
		assert.ErrorContains(t, err, "failed to resolve SR policy path")
	})

	t.Run("SID validation error", func(t *testing.T) {
		s := newTestAPIServer(ted)
		req := baseReq()
		req.NoSidValidate = false
		req.SrPolicy.SegmentList = []*pb.Segment{{Sid: "16099"}}
		_, err := s.CreateSRPolicy(context.Background(), req)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("send request error", func(t *testing.T) {
		s := newTestAPIServer(ted)
		_, err := s.CreateSRPolicy(context.Background(), baseReq())
		assert.ErrorContains(t, err, "failed to send SR policy request")
	})

	t.Run("success", func(t *testing.T) {
		server, client := newTCPConnPair(t)
		t.Cleanup(func() {
			assert.NoError(t, client.Close(), "failed to close client connection")
		})

		peerAddr := netip.MustParseAddr("10.0.255.1")
		ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
		ss.syncState = lspDBSyncFinished

		s := &APIServer{pce: &Server{ted: ted, sessionList: []*Session{ss}}, logger: logger.NewNop()}

		_, err := s.CreateSRPolicy(context.Background(), baseReq())
		require.NoError(t, err)
	})
}

// readEROBehavior reads a PCEP message and returns the behavior from its first ERO subobject.
func readEROBehavior(t *testing.T, r io.Reader) uint16 {
	t.Helper()

	headerBytes := make([]byte, pcep.CommonHeaderLength)
	_, err := io.ReadFull(r, headerBytes)
	require.NoError(t, err)

	var header pcep.CommonHeader
	require.NoError(t, header.DecodeFromBytes(headerBytes))

	body := make([]byte, int(header.MessageLength)-int(pcep.CommonHeaderLength))
	_, err = io.ReadFull(r, body)
	require.NoError(t, err)

	const objectHeaderLength = 4
	for len(body) > 0 {
		var objHeader pcep.CommonObjectHeader
		require.NoError(t, objHeader.DecodeFromBytes(body))
		objBody := body[objectHeaderLength:objHeader.ObjectLength]
		if objHeader.ObjectClass == pcep.ObjectClassERO {
			require.GreaterOrEqual(t, len(objBody), 8)
			return binary.BigEndian.Uint16(objBody[6:8])
		}
		body = body[objHeader.ObjectLength:]
	}
	t.Fatal("ERO object not found in PCEP message")
	return 0
}

func TestCreateSRPolicy_SRv6WithoutLocalAddr(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	peerAddr := netip.MustParseAddr("10.0.255.1")
	ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
	ss.syncState = lspDBSyncFinished

	s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}

	req := &pb.CreateSRPolicyRequest{
		DisablePathCompute: true,
		SrPolicy: &pb.SRPolicy{
			PolicyName:  testSRPolicyName,
			Color:       100,
			PeerAddr:    netip.MustParseAddr("10.0.255.1").AsSlice(),
			SrcAddr:     netip.MustParseAddr("10.0.0.1").AsSlice(),
			DstAddr:     netip.MustParseAddr("10.0.0.2").AsSlice(),
			SegmentList: []*pb.Segment{{Sid: testSRv6SID1}},
		},
		NoSidValidate: true,
	}

	_, err := s.CreateSRPolicy(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, table.BehaviorOpaque, readEROBehavior(t, client))
}

func TestCreateSRPolicy_StatusCodes(t *testing.T) {
	newTED := func() *table.LsTED {
		mk := func(routerID, loopback string, sidIndex uint32) *table.LsNode {
			return &table.LsNode{
				ASN: 65000, RouterID: routerID, SrgbBegin: 16000, SrgbEnd: 17000,
				Prefixes: []*table.LsPrefix{
					{Prefix: netip.MustParsePrefix(loopback + "/32"), SidIndex: sidIndex, HasSidIndex: true},
				},
			}
		}
		r1, r2, r3 := mk("r1", "10.0.0.1", 1), mk("r2", "10.0.0.2", 2), mk("r3", "10.0.0.3", 3)
		link := table.NewLsLink(r1, r2)
		link.Metrics = []*table.Metric{table.NewMetric(table.IGPMetric, 10)}
		r1.Links = append(r1.Links, link)
		reverseLink := table.NewLsLink(r2, r1)
		reverseLink.Metrics = []*table.Metric{table.NewMetric(table.IGPMetric, 10)}
		r2.Links = append(r2.Links, reverseLink)
		return &table.LsTED{Nodes: map[string]*table.LsNode{"r1": r1, "r2": r2, "r3": r3}}
	}

	explicitReq := func() *pb.CreateSRPolicyRequest {
		return &pb.CreateSRPolicyRequest{
			Asn: 65000,
			SrPolicy: &pb.SRPolicy{
				Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, PolicyName: testSRPolicyName, Color: 100,
				PeerAddr:    netip.MustParseAddr("10.0.255.1").AsSlice(),
				SrcRouterId: "r1", DstRouterId: "r2",
				SegmentList: []*pb.Segment{{Sid: "16002"}},
			},
			NoSidValidate: true,
		}
	}
	dynamicReq := func() *pb.CreateSRPolicyRequest {
		req := explicitReq()
		req.SrPolicy.Type = pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC
		req.SrPolicy.Metric = pb.MetricType_METRIC_TYPE_IGP
		req.SrPolicy.SegmentList = nil
		return req
	}

	tests := []struct {
		name       string
		useTED     bool
		req        func() *pb.CreateSRPolicyRequest
		wantCode   codes.Code
		wantReason string
		wantMsg    string
	}{
		{
			"ASN is zero", true, func() *pb.CreateSRPolicyRequest { r := explicitReq(); r.Asn = 0; return r },
			codes.InvalidArgument, ReasonInvalidRequest, "ASN must not be zero",
		},
		{
			"color is zero", true, func() *pb.CreateSRPolicyRequest { r := explicitReq(); r.SrPolicy.Color = 0; return r },
			codes.InvalidArgument, ReasonInvalidRequest, wantErrColorZero,
		},
		{
			"PCEP session address is absent", true, func() *pb.CreateSRPolicyRequest { r := explicitReq(); r.SrPolicy.PeerAddr = nil; return r },
			codes.InvalidArgument, ReasonInvalidRequest, "policy.PeerAddr must not be nil",
		},
		{
			"request ASN does not match the TED", true, func() *pb.CreateSRPolicyRequest { r := explicitReq(); r.Asn = 65001; return r },
			codes.InvalidArgument, ReasonInvalidRequest, "does not match ted ASN",
		},
		{
			"source router ID is not in the TED", true, func() *pb.CreateSRPolicyRequest { r := dynamicReq(); r.SrPolicy.SrcRouterId = "r9"; return r },
			codes.InvalidArgument, ReasonInvalidRequest, "no node with router ID r9",
		},
		{
			"destination router ID is not in the TED", true, func() *pb.CreateSRPolicyRequest { r := dynamicReq(); r.SrPolicy.DstRouterId = "r9"; return r },
			codes.InvalidArgument, ReasonInvalidRequest, "no node with router ID r9",
		},
		{"waypoint router ID is not in the TED", true, func() *pb.CreateSRPolicyRequest {
			r := dynamicReq()
			r.SrPolicy.Waypoints = []*pb.Waypoint{{RouterId: "r9"}}
			return r
		}, codes.InvalidArgument, ReasonInvalidRequest, "waypoint router r9 not found in TED"},
		{"waypoint SID is malformed", true, func() *pb.CreateSRPolicyRequest {
			r := dynamicReq()
			r.SrPolicy.Waypoints = []*pb.Waypoint{{RouterId: "r2", Sid: "not-an-address"}}
			return r
		}, codes.InvalidArgument, ReasonInvalidRequest, "failed to build segment for waypoint r2"},
		{"dynamic policy without a metric", true, func() *pb.CreateSRPolicyRequest {
			r := dynamicReq()
			r.SrPolicy.Metric = pb.MetricType_METRIC_TYPE_UNSPECIFIED
			return r
		}, codes.InvalidArgument, ReasonInvalidRequest, "unknown metric type"},
		{"dynamic policy with a metric outside the enum", true, func() *pb.CreateSRPolicyRequest {
			r := dynamicReq()
			r.SrPolicy.Metric = pb.MetricType(99)
			return r
		}, codes.InvalidArgument, ReasonInvalidRequest, "unknown metric type"},
		{
			"policy type is unset", true, func() *pb.CreateSRPolicyRequest {
				r := explicitReq()
				r.SrPolicy.Type = pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED
				return r
			},
			codes.InvalidArgument, ReasonInvalidRequest, "undefined SR Policy type",
		},
		{
			"explicit policy with an empty segment list", true, func() *pb.CreateSRPolicyRequest { r := explicitReq(); r.SrPolicy.SegmentList = nil; return r },
			codes.InvalidArgument, ReasonInvalidRequest, "no segments in SRPolicy input",
		},
		{"explicit policy with a malformed SID", true, func() *pb.CreateSRPolicyRequest {
			r := explicitReq()
			r.SrPolicy.SegmentList = []*pb.Segment{{Sid: invalidSidStr}}
			return r
		}, codes.InvalidArgument, ReasonInvalidRequest, "invalid SID"},
		{"SID is not present in the TED", true, func() *pb.CreateSRPolicyRequest {
			r := explicitReq()
			r.NoSidValidate = false
			r.SrPolicy.SegmentList = []*pb.Segment{{Sid: "16099"}}
			return r
		}, codes.FailedPrecondition, "SID_VALIDATION_FAILED", "SID validation failed"},

		// FailedPrecondition: request is well formed, PCE/TED state cannot satisfy it.
		{"TED is disabled", false, explicitReq, codes.FailedPrecondition, "TED_DISABLED", "ted is disabled"},
		{
			"destination is unreachable", true, func() *pb.CreateSRPolicyRequest { r := dynamicReq(); r.SrPolicy.DstRouterId = "r3"; return r },
			codes.FailedPrecondition, "DESTINATION_UNREACHABLE", "next node not found",
		},
		{"requested metric is not carried by a traversed link", true, func() *pb.CreateSRPolicyRequest {
			r := dynamicReq()
			r.SrPolicy.Metric = pb.MetricType_METRIC_TYPE_TE
			return r
		}, codes.FailedPrecondition, "METRIC_NOT_CARRIED", "metric METRIC_TYPE_TE not defined"},
		{"no PCEP session", true, explicitReq, codes.NotFound, "PCEP_SESSION_NOT_FOUND", "no session with address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ted *table.LsTED
			if tt.useTED {
				ted = newTED()
			}
			s := newTestAPIServer(ted)

			_, err := s.CreateSRPolicy(context.Background(), tt.req())
			require.Error(t, err)
			st := status.Convert(err)
			assert.Equal(t, tt.wantCode, st.Code(), "unexpected status code for %q", err)
			assert.Contains(t, st.Message(), tt.wantMsg)

			var gotReason string
			for _, d := range st.Details() {
				if info, ok := d.(*errdetails.ErrorInfo); ok {
					gotReason = info.Reason
				}
			}
			assert.Equal(t, tt.wantReason, gotReason, "unexpected ErrorInfo.Reason for %q", err)
		})
	}
}

func TestDeleteSRPolicy(t *testing.T) {
	peerAddr := netip.MustParseAddr("10.0.255.1")
	dstAddr := netip.MustParseAddr("10.255.0.2")

	validPolicy := func() *pb.SRPolicy {
		return &pb.SRPolicy{
			PeerAddr:   peerAddr.AsSlice(),
			DstAddr:    dstAddr.AsSlice(),
			Color:      100,
			PolicyName: testSRPolicyName,
		}
	}

	t.Run("validation error", func(t *testing.T) {
		s := &APIServer{logger: logger.NewNop()}
		resp, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: &pb.SRPolicy{}})
		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("malformed source address", func(t *testing.T) {
		s := &APIServer{logger: logger.NewNop()}
		policy := validPolicy()
		policy.SrcAddr = []byte{1, 2, 3}
		resp, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: policy})
		require.ErrorContains(t, err, "invalid source address")
		assert.Nil(t, resp)
	})

	t.Run("malformed destination address", func(t *testing.T) {
		s := &APIServer{logger: logger.NewNop()}
		policy := validPolicy()
		policy.DstAddr = []byte{1, 2, 3}
		resp, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: policy})
		require.ErrorContains(t, err, "invalid destination address")
		assert.Nil(t, resp)
	})

	t.Run("malformed segment SID", func(t *testing.T) {
		s := &APIServer{logger: logger.NewNop()}
		policy := validPolicy()
		policy.SegmentList = []*pb.Segment{{Sid: invalidSidStr}}
		resp, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: policy})
		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("no synced session", func(t *testing.T) {
		s := &APIServer{pce: &Server{}, logger: logger.NewNop()}
		resp, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: validPolicy()})
		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("SR Policy not found", func(t *testing.T) {
		ss := &Session{peerAddr: peerAddr, syncState: lspDBSyncFinished}
		s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
		resp, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: validPolicy()})
		require.ErrorContains(t, err, "requested SR Policy not found")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
		var gotReason string
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok {
				gotReason = info.Reason
			}
		}
		assert.Equal(t, ReasonSRPolicyNotFound, gotReason)
	})

	t.Run("delete request send failure", func(t *testing.T) {
		server, client := newTCPConnPair(t)
		t.Cleanup(func() {
			assert.NoError(t, client.Close(), "failed to close client connection")
		})

		ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
		ss.syncState = lspDBSyncFinished
		ss.srPolicies = []*table.SRPolicy{{PlspID: 1, Name: testSRPolicyName, DstAddr: dstAddr, Color: 100, Preference: 100}}
		require.NoError(t, server.Close(), "failed to close server connection")

		s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
		resp, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: validPolicy()})
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ReasonPCEPRequestFailed, errInfoReason(t, err))
	})

	t.Run("success with explicit segment list", func(t *testing.T) {
		server, client := newTCPConnPair(t)
		t.Cleanup(func() {
			assert.NoError(t, client.Close(), "failed to close client connection")
		})

		ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
		ss.syncState = lspDBSyncFinished
		ss.srPolicies = []*table.SRPolicy{{PlspID: 1, Name: testSRPolicyName, DstAddr: dstAddr, Color: 100, Preference: 100}}

		s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
		policy := validPolicy()
		policy.SegmentList = []*pb.Segment{{Sid: "16003"}}
		_, err := s.DeleteSRPolicy(context.Background(), &pb.DeleteSRPolicyRequest{SrPolicy: policy})
		require.NoError(t, err)
	})
}

func TestValidate_NilPolicy(t *testing.T) {
	assert.ErrorContains(t, validate(nil, 100, ValidationAdd), "input is nil")
}

func TestValidate_AddRequiresNonZeroASN(t *testing.T) {
	policy := &pb.SRPolicy{PeerAddr: []byte{10, 0, 0, 1}, Color: 100, SrcRouterId: "r1", DstRouterId: "r2"}
	assert.ErrorContains(t, validate(policy, 0, ValidationAdd), "ASN must not be zero")
}

func TestValidate_UnknownKind(t *testing.T) {
	policy := &pb.SRPolicy{PeerAddr: []byte{10, 0, 0, 1}, Color: 100}
	assert.ErrorContains(t, validate(policy, 100, ValidationKind("bogus")), "unknown validation kind")
}

func TestValidate_Add(t *testing.T) {
	full := func() *pb.SRPolicy {
		return &pb.SRPolicy{PeerAddr: []byte{10, 0, 0, 1}, Color: 100, SrcRouterId: "r1", DstRouterId: "r2"}
	}

	tests := []struct {
		name    string
		mutate  func(*pb.SRPolicy)
		wantErr string
	}{
		{name: "valid"},
		{name: "missing PCEP session address", mutate: func(p *pb.SRPolicy) { p.PeerAddr = nil }, wantErr: "policy.PeerAddr must not be nil"},
		{name: "zero color", mutate: func(p *pb.SRPolicy) { p.Color = 0 }, wantErr: wantErrColorZero},
		{name: "missing source router ID", mutate: func(p *pb.SRPolicy) { p.SrcRouterId = "" }, wantErr: "SrcRouterId must not be empty"},
		{name: "missing destination router ID", mutate: func(p *pb.SRPolicy) { p.DstRouterId = "" }, wantErr: "DstRouterId must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := full()
			if tt.mutate != nil {
				tt.mutate(policy)
			}
			err := validate(policy, 65000, ValidationAdd)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidate_AddDisablePathCompute(t *testing.T) {
	full := func() *pb.SRPolicy {
		return &pb.SRPolicy{
			PeerAddr:    []byte{10, 0, 0, 1},
			Color:       100,
			SrcAddr:     []byte{10, 0, 0, 1},
			DstAddr:     []byte{10, 0, 0, 2},
			SegmentList: []*pb.Segment{{Sid: "16003"}},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*pb.SRPolicy)
		wantErr string
	}{
		{name: "valid"},
		{name: "missing PCEP session address", mutate: func(p *pb.SRPolicy) { p.PeerAddr = nil }, wantErr: "policy.PeerAddr must not be nil"},
		{name: "zero color", mutate: func(p *pb.SRPolicy) { p.Color = 0 }, wantErr: wantErrColorZero},
		{name: "missing source address", mutate: func(p *pb.SRPolicy) { p.SrcAddr = nil }, wantErr: "SrcAddr must not be empty"},
		{name: "missing destination address", mutate: func(p *pb.SRPolicy) { p.DstAddr = nil }, wantErr: "DstAddr must not be empty"},
		{name: "missing segment list", mutate: func(p *pb.SRPolicy) { p.SegmentList = nil }, wantErr: "SegmentList must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := full()
			if tt.mutate != nil {
				tt.mutate(policy)
			}
			err := validate(policy, 65000, ValidationAddDisablePathCompute)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidate_Delete(t *testing.T) {
	full := func() *pb.SRPolicy {
		return &pb.SRPolicy{
			PeerAddr:   []byte{10, 0, 0, 1},
			Color:      100,
			DstAddr:    []byte{10, 0, 0, 2},
			PolicyName: testSRPolicyName,
		}
	}

	tests := []struct {
		name    string
		mutate  func(*pb.SRPolicy)
		wantErr string
	}{
		{name: "valid"},
		{name: "missing PCEP session address", mutate: func(p *pb.SRPolicy) { p.PeerAddr = nil }, wantErr: "policy.PeerAddr must not be nil"},
		{name: "zero color", mutate: func(p *pb.SRPolicy) { p.Color = 0 }, wantErr: wantErrColorZero},
		{name: "missing destination address", mutate: func(p *pb.SRPolicy) { p.DstAddr = nil }, wantErr: "DstAddr must not be empty"},
		{name: "missing policy name", mutate: func(p *pb.SRPolicy) { p.PolicyName = "" }, wantErr: "PolicyName must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := full()
			if tt.mutate != nil {
				tt.mutate(policy)
			}
			err := validate(policy, 0, ValidationDelete)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSendSRPolicyRequest_GetSyncedPCEPSessionError(t *testing.T) {
	s := &APIServer{pce: &Server{}, logger: logger.NewNop()}
	req := &pb.CreateSRPolicyRequest{SrPolicy: &pb.SRPolicy{PeerAddr: netip.MustParseAddr("10.0.255.1").AsSlice()}}

	err := sendSRPolicyRequest(s, req, resolvedPath{}, false)
	assert.ErrorContains(t, err, "failed to get synchronized PCEP session")
}

func TestSendSRPolicyRequest_ResolveIntentError(t *testing.T) {
	peerAddr := netip.MustParseAddr("10.0.255.1")
	ss := &Session{peerAddr: peerAddr, syncState: lspDBSyncFinished}
	s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
	req := &pb.CreateSRPolicyRequest{SrPolicy: &pb.SRPolicy{PeerAddr: peerAddr.AsSlice(), Type: pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED}}

	err := sendSRPolicyRequest(s, req, resolvedPath{}, false)
	assert.ErrorContains(t, err, "failed to resolve SR policy type")
}

func TestSendSRPolicyRequest_CreatesNewPolicy(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	peerAddr := netip.MustParseAddr("10.0.255.1")
	dstAddr := netip.MustParseAddr("10.255.0.2")
	ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
	ss.syncState = lspDBSyncFinished

	s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
	req := &pb.CreateSRPolicyRequest{SrPolicy: &pb.SRPolicy{PeerAddr: peerAddr.AsSlice(), Color: 100, Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT}}
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	require.NoError(t, sendSRPolicyRequest(s, req, resolvedPath{SegmentList: segmentList, SrcAddr: netip.MustParseAddr("10.255.0.1"), DstAddr: dstAddr, Metric: table.UnspecifiedMetric}, false))
	assert.NoError(t, readPCEPMessage(client), "expected a well-framed PCInitiate message on the wire")
}

func TestSendSRPolicyRequest_UpdatesExistingPolicy(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	peerAddr := netip.MustParseAddr("10.0.255.1")
	dstAddr := netip.MustParseAddr("10.255.0.2")
	ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
	ss.syncState = lspDBSyncFinished
	ss.srPolicies = []*table.SRPolicy{{PlspID: 7, Color: 100, DstAddr: dstAddr}}

	s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
	req := &pb.CreateSRPolicyRequest{SrPolicy: &pb.SRPolicy{PeerAddr: peerAddr.AsSlice(), Color: 100, Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT}}
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	require.NoError(t, sendSRPolicyRequest(s, req, resolvedPath{SegmentList: segmentList, SrcAddr: netip.MustParseAddr("10.255.0.1"), DstAddr: dstAddr, Metric: table.UnspecifiedMetric}, false))
	assert.NoError(t, readPCEPMessage(client), "expected a well-framed PCUpdate message on the wire")
}

func TestSendSRPolicyRequest_UpdateSendFailure(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	peerAddr := netip.MustParseAddr("10.0.255.1")
	dstAddr := netip.MustParseAddr("10.255.0.2")
	ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
	ss.syncState = lspDBSyncFinished
	ss.srPolicies = []*table.SRPolicy{{PlspID: 7, Color: 100, DstAddr: dstAddr}}
	require.NoError(t, server.Close(), "failed to close server connection")

	s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
	req := &pb.CreateSRPolicyRequest{SrPolicy: &pb.SRPolicy{PeerAddr: peerAddr.AsSlice(), Color: 100, Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT}}
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := sendSRPolicyRequest(s, req, resolvedPath{SegmentList: segmentList, SrcAddr: netip.MustParseAddr("10.255.0.1"), DstAddr: dstAddr, Metric: table.UnspecifiedMetric}, false)
	require.ErrorContains(t, err, "failed to send PC update")
	assert.Equal(t, ReasonPCEPRequestFailed, errInfoReason(t, err))
}

func TestSendSRPolicyRequest_CreateSendFailure(t *testing.T) {
	server, client := newTCPConnPair(t)
	t.Cleanup(func() {
		assert.NoError(t, client.Close(), "failed to close client connection")
	})

	peerAddr := netip.MustParseAddr("10.0.255.1")
	dstAddr := netip.MustParseAddr("10.255.0.2")
	ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
	ss.syncState = lspDBSyncFinished
	require.NoError(t, server.Close(), "failed to close server connection")

	s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
	req := &pb.CreateSRPolicyRequest{SrPolicy: &pb.SRPolicy{PeerAddr: peerAddr.AsSlice(), Color: 100, Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT}}
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := sendSRPolicyRequest(s, req, resolvedPath{SegmentList: segmentList, SrcAddr: netip.MustParseAddr("10.255.0.1"), DstAddr: dstAddr, Metric: table.UnspecifiedMetric}, false)
	require.ErrorContains(t, err, "failed to request SR policy creation")
	assert.Equal(t, ReasonPCEPRequestFailed, errInfoReason(t, err))
}

func TestGetSRPolicyList_InvalidFilterAddrReason(t *testing.T) {
	s := &APIServer{logger: logger.NewNop()}
	_, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{PeerAddr: []byte{1, 2, 3}})
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid session filter address")
	assert.Equal(t, ReasonInvalidRequest, errInfoReason(t, err))
}

func errInfoReason(t *testing.T, err error) string {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error")
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	t.Fatal("status has no ErrorInfo details")
	return ""
}

func TestWrapStatusError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantNil    bool
		wantCode   codes.Code
		wantMsg    string
		wantReason string
	}{
		{
			name:    "non-status error is wrapped with a plain message",
			err:     errors.New("boom"),
			wantMsg: "context: boom",
		},
		{
			name:     "status error without details keeps its code and gets a prefixed message",
			err:      status.Errorf(codes.NotFound, "not found"),
			wantCode: codes.NotFound,
			wantMsg:  "context: not found",
		},
		{
			name:       "status error with ErrorInfo details preserves the Reason",
			err:        newStatus(codes.InvalidArgument, ReasonInvalidRequest, "bad input"),
			wantCode:   codes.InvalidArgument,
			wantMsg:    "context: bad input",
			wantReason: ReasonInvalidRequest,
		},
		{
			name:    "nil error stays nil",
			err:     nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapStatusError(tt.err, "context")

			if tt.wantNil {
				assert.NoError(t, got)
				return
			}
			require.Error(t, got)

			if st, ok := status.FromError(got); ok && tt.wantCode != codes.OK {
				assert.Equal(t, tt.wantCode, st.Code())
				assert.Equal(t, tt.wantMsg, st.Message())
			} else {
				assert.EqualError(t, got, tt.wantMsg)
			}
			if tt.wantReason != "" {
				assert.Equal(t, tt.wantReason, errInfoReason(t, got))
			}
		})
	}
}

func TestBuildCapability(t *testing.T) {
	tests := []struct {
		name string
		cap  pcep.CapabilityInterface
		want *pb.Capability
	}{
		{
			name: "stateful",
			cap: &pcep.StatefulPCECapability{
				LSPUpdateCapability:        true,
				IncludeDBVersion:           true,
				LSPInstantiationCapability: true,
				TriggeredResync:            true,
				DeltaLSPSyncCapability:     true,
				TriggeredInitialSync:       true,
				ColorCapability:            true,
			},
			want: &pb.Capability{
				Type: pb.CapabilityType_CAPABILITY_TYPE_STATEFUL,
				Detail: &pb.Capability_Stateful{Stateful: &pb.StatefulCapability{
					LspUpdate: true, IncludeDbVersion: true, LspInstantiation: true,
					TriggeredResync: true, DeltaLspSync: true, TriggeredInitialSync: true, Color: true,
				}},
			},
		},
		{
			name: "sr",
			cap:  &pcep.SRPCECapability{IsNAISupported: true, MaximumSidDepth: 8},
			want: &pb.Capability{
				Type:   pb.CapabilityType_CAPABILITY_TYPE_SR,
				Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{NaiSupported: true, Msd: proto.Uint32(8)}},
			},
		},
		{
			name: "sr with unlimited MSD",
			cap:  &pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true, MaximumSidDepth: 0},
			want: &pb.Capability{
				Type:   pb.CapabilityType_CAPABILITY_TYPE_SR,
				Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{UnlimitedMsd: true}},
			},
		},
		{
			name: "path setup type",
			cap:  &pcep.PathSetupTypeCapability{PathSetupTypes: pcep.Psts{1, 3}},
			want: &pb.Capability{
				Type:   pb.CapabilityType_CAPABILITY_TYPE_PATH_SETUP_TYPE,
				Detail: &pb.Capability_PathSetupType{PathSetupType: &pb.PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}},
			},
		},
		{
			name: "path setup type with SR/SRv6 sub-capabilities",
			cap: &pcep.PathSetupTypeCapability{
				PathSetupTypes: pcep.Psts{1, 3},
				SubTLVs: []pcep.TLVInterface{
					&pcep.SRPCECapability{HasUnlimitedMaxSIDDepth: true},
					&pcep.SRv6PCECapability{},
				},
			},
			want: &pb.Capability{
				Type: pb.CapabilityType_CAPABILITY_TYPE_PATH_SETUP_TYPE,
				Detail: &pb.Capability_PathSetupType{PathSetupType: &pb.PathSetupTypeCapability{
					PathSetupTypes: []uint32{1, 3},
					SubCapabilities: []*pb.Capability{
						{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{UnlimitedMsd: true}}},
						{Type: pb.CapabilityType_CAPABILITY_TYPE_SRV6, Detail: &pb.Capability_Srv6{Srv6: &pb.Srv6Capability{}}},
					},
				}},
			},
		},
		{
			name: "association type list",
			cap:  &pcep.AssocTypeList{AssocTypes: []pcep.AssocType{1, 2}},
			want: &pb.Capability{
				Type:   pb.CapabilityType_CAPABILITY_TYPE_ASSOC_TYPE_LIST,
				Detail: &pb.Capability_AssocTypeList{AssocTypeList: &pb.AssocTypeListCapability{AssocTypes: []uint32{1, 2}}},
			},
		},
		{
			name: "vendor information",
			cap:  &pcep.VendorInformation{EnterpriseNumber: 9},
			want: &pb.Capability{
				Type:   pb.CapabilityType_CAPABILITY_TYPE_VENDOR_INFORMATION,
				Detail: &pb.Capability_VendorInformation{VendorInformation: &pb.VendorInformationCapability{EnterpriseNumber: 9}},
			},
		},
		{
			name: "unknown TLV falls back to the unknown capability type",
			cap:  &pcep.UnknownTLV{Typ: pcep.TLVType(0x9999)},
			want: &pb.Capability{
				Type:   pb.CapabilityType_CAPABILITY_TYPE_UNKNOWN,
				Detail: &pb.Capability_Unknown{Unknown: &pb.UnknownCapability{TlvType: 0x9999}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildCapability(tt.cap))
		})
	}
}

func TestGetTED_Disabled(t *testing.T) {
	tests := []struct {
		name string
		s    *APIServer
	}{
		{name: "pce is nil", s: &APIServer{logger: logger.NewNop()}},
		{name: "TED is nil", s: newTestAPIServer(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.s.GetTED(context.Background(), &pb.GetTEDRequest{})
			require.NoError(t, err)
			assert.False(t, resp.GetEnabled())
			assert.Empty(t, resp.GetNodes())
		})
	}
}

func TestConvertMetrics_Nil(t *testing.T) {
	assert.Nil(t, convertMetrics(nil))
}

func TestGetTED_ConvertsFullNode(t *testing.T) {
	node := &table.LsNode{
		ASN:        65000,
		RouterID:   testRouterID1,
		IsisAreaID: "49.0001",
		Hostname:   "pe1",
		SrgbBegin:  16000,
		SrgbEnd:    17000,
	}
	remote := &table.LsNode{ASN: 65000, RouterID: testRouterID2}

	link := table.NewLsLink(node, remote)
	link.LocalIP = netip.MustParseAddr("192.0.2.1")
	link.RemoteIP = netip.MustParseAddr("192.0.2.2")
	link.AdjSid = 24001
	link.Metrics = []*table.Metric{
		nil,
		table.NewMetric(table.IGPMetric, 10),
		table.NewMetric(table.TEMetric, 20),
	}
	link.Srv6EndXSID = &table.Srv6EndXSID{
		EndpointBehavior: table.BehaviorENDX,
		Sids:             []string{testSRv6SID1, ""},
		Srv6SIDStructure: table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
	}
	node.Links = []*table.LsLink{
		link,
		{LocalNode: node, RemoteNode: nil},
		nil,
	}

	node.Prefixes = []*table.LsPrefix{
		{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
		{Prefix: netip.MustParsePrefix("10.0.0.0/24")},
		nil,
	}

	node.SRv6SIDs = []*table.LsSrv6SID{
		{
			Sids:             []string{"2001:db8:1::1", ""},
			EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorEND, Flags: 0x40, Algorithm: 0},
			SIDStructure:     table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
			MultiTopoIDs:     []uint32{0, 1},
		},
		{Sids: []string{"2001:db8:2::1"}},
		nil,
	}

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{
		node.RouterID:   node,
		remote.RouterID: remote,
		"ghost":         nil,
	}}

	s := newTestAPIServer(ted)
	resp, err := s.GetTED(context.Background(), &pb.GetTEDRequest{})
	require.NoError(t, err)
	require.True(t, resp.GetEnabled())
	require.Len(t, resp.GetNodes(), 2, "the nil TED entry must not produce a node")

	byRouterID := map[string]*pb.LsNode{}
	for _, n := range resp.GetNodes() {
		byRouterID[n.GetRouterId()] = n
	}

	want := &pb.LsNode{
		Asn:        65000,
		RouterId:   testRouterID1,
		IsisAreaId: "49.0001",
		Hostname:   "pe1",
		SrgbBegin:  16000,
		SrgbEnd:    17000,
		Links: []*pb.LsLink{
			{
				LocalRouterId:  testRouterID1,
				LocalAsn:       65000,
				LocalIp:        "192.0.2.1",
				RemoteRouterId: testRouterID2,
				RemoteAsn:      65000,
				RemoteIp:       "192.0.2.2",
				Metrics: []*pb.Metric{
					{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10},
					{Type: pb.MetricType_METRIC_TYPE_TE, Value: 20},
				},
				AdjSid: 24001,
				Srv6EndXSid: &pb.Srv6EndXSID{
					EndpointBehavior: uint32(table.BehaviorENDX),
					Sids:             []*pb.SID{{Sid: testSRv6SID1}},
					SidStructure:     &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
				},
			},
		},
		Prefixes: []*pb.LsPrefix{
			{Prefix: "10.0.0.1/32", SidIndex: proto.Uint32(0)},
			{Prefix: "10.0.0.0/24"},
		},
		Srv6Sids: []*pb.LsSrv6SID{
			{
				Sids:         []*pb.SID{{Sid: "2001:db8:1::1"}},
				MultiTopoIds: []*pb.MultiTopoID{{MultiTopoId: 0}, {MultiTopoId: 1}},
				SidStructure: &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
				EndpointBehavior: &pb.EndpointBehavior{
					Behavior: uint32(table.BehaviorEND),
					Flags:    0x40,
				},
			},
			{
				Sids:         []*pb.SID{{Sid: "2001:db8:2::1"}},
				MultiTopoIds: []*pb.MultiTopoID{},
				SidStructure: &pb.SidStructure{},
			},
		},
	}
	assert.Equal(t, want, byRouterID[node.RouterID])
	assert.Equal(t, &pb.LsNode{Asn: 65000, RouterId: testRouterID2}, byRouterID[remote.RouterID])
}

func TestDeleteSession(t *testing.T) {
	t.Run("malformed address", func(t *testing.T) {
		s := &APIServer{pce: &Server{}, logger: logger.NewNop()}
		_, err := s.DeleteSession(context.Background(), &pb.DeleteSessionRequest{PeerAddr: []byte{1, 2, 3}})
		require.ErrorContains(t, err, "invalid PCEP session address")
		assert.Equal(t, ReasonInvalidRequest, errInfoReason(t, err))
	})

	t.Run("no such session", func(t *testing.T) {
		s := &APIServer{pce: &Server{}, logger: logger.NewNop()}
		_, err := s.DeleteSession(context.Background(), &pb.DeleteSessionRequest{PeerAddr: netip.MustParseAddr("10.0.255.1").AsSlice()})
		require.ErrorContains(t, err, "no session with address")
		assert.Equal(t, ReasonPCEPSessionNotFound, errInfoReason(t, err))
	})

	t.Run("close message send failure", func(t *testing.T) {
		server, client := newTCPConnPair(t)
		t.Cleanup(func() {
			assert.NoError(t, client.Close(), "failed to close client connection")
		})

		peerAddr := netip.MustParseAddr("10.0.255.1")
		ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
		require.NoError(t, server.Close(), "failed to close server connection")

		s := &APIServer{pce: &Server{sessionList: []*Session{ss}}, logger: logger.NewNop()}
		resp, err := s.DeleteSession(context.Background(), &pb.DeleteSessionRequest{PeerAddr: peerAddr.AsSlice()})
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ReasonPCEPRequestFailed, errInfoReason(t, err))
	})

	t.Run("success closes and removes the session", func(t *testing.T) {
		server, client := newTCPConnPair(t)
		t.Cleanup(func() {
			assert.NoError(t, client.Close(), "failed to close client connection")
		})

		peerAddr := netip.MustParseAddr("10.0.255.1")
		ss := NewSession(testLocalOpen(1), peerAddr, server, logger.NewNop(), nil, 0)
		pce := &Server{sessionList: []*Session{ss}}
		s := &APIServer{pce: pce, logger: logger.NewNop()}

		_, err := s.DeleteSession(context.Background(), &pb.DeleteSessionRequest{PeerAddr: peerAddr.AsSlice()})
		require.NoError(t, err)
		assert.Nil(t, pce.SearchSession(peerAddr), "expected the session to be removed from the PCE")
	})
}
