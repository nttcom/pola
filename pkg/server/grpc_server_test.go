// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// localAddr / remoteAddr from the gRPC message must land on the SR-MPLS segment.
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
			segment:    &pb.Segment{Sid: "24001", LocalAddr: "10.0.0.1", RemoteAddr: "10.0.0.2"},
			wantLocal:  "10.0.0.1",
			wantRemote: "10.0.0.2",
		},
		{
			name:    "malformed localAddr",
			segment: &pb.Segment{Sid: "16001", LocalAddr: "10.255.0.300"},
			wantErr: true,
		},
		{
			name:    "malformed remoteAddr",
			segment: &pb.Segment{Sid: "16001", LocalAddr: "10.0.0.1", RemoteAddr: "not-an-addr"},
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

// newEnrichedSegment is shared by the SR-MPLS and the SRv6 call paths, so the
// SRv6 extras must keep being applied.
func TestNewEnrichedSegmentSRv6(t *testing.T) {
	segment := &pb.Segment{
		Sid:          "2001:db8:1005::",
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
		assert.Equal(t, []uint8{32, 16, 0, 80}, srv6Seg.Structure, "Structure")
		assert.Equalf(t, usidMode, srv6Seg.USid, "USid with usidMode=%v", usidMode)
	}
}

func TestNewEnrichedSegmentInvalidSID(t *testing.T) {
	_, err := newEnrichedSegment(&pb.Segment{Sid: "not-a-sid"}, false)
	assert.Error(t, err, "expected an error for an unparsable SID")
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

// An SR-MPLS segment carrying a localAddr must be serialized into an SR-ERO
// subobject whose body ends with that address (RFC8664 4.3.1 node NAI).
func TestCreateEroFromSegmentListWithNAI(t *testing.T) {
	seg := table.NewSegmentSRMPLS(16002)
	seg.LocalAddr = netip.MustParseAddr("10.255.0.2")

	ero := createEroFromSegmentList([]table.Segment{seg})
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
		logger: zap.NewNop(),
	}
}

func explicitPolicyRequest(noSIDValidate bool, sid string) *pb.CreateSRPolicyRequest {
	return &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
			PolicyName:  "test",
			Color:       100,
			SegmentList: []*pb.Segment{{Sid: sid}},
		},
		NoSidValidate: noSIDValidate,
	}
}

func dynamicPolicyRequest() *pb.CreateSRPolicyRequest {
	return &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			Type:       pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
			PolicyName: "test",
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
		RouterID:  "0000.0000.0001",
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
	assert.Equal(t, codes.InvalidArgument, st.Code())
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
		RouterID:  "0000.0000.0001",
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
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "hop 1", "expected the missing hop to be listed")
}

func TestValidateSIDs_EndpointFormIsStillValidated(t *testing.T) {
	node := &table.LsNode{
		RouterID:  "0000.0000.0001",
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
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "hop 1", "expected the missing hop to be listed")
}

func TestValidateSIDs_LabelOutOfRangeIsRejectedEvenWithNoSidValidate(t *testing.T) {
	s := newTestAPIServer(nil)
	req := explicitPolicyRequest(true, "1048576")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(1048576)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
	if !strings.Contains(st.Message(), "0-1048575") || !strings.Contains(st.Message(), "hop 1") {
		t.Errorf("unexpected message: %s", st.Message())
	}
}

func TestValidateSIDs_LabelBoundsAreAccepted(t *testing.T) {
	s := newTestAPIServer(nil)

	for _, label := range []uint32{0, 1048575} {
		req := explicitPolicyRequest(true, strconv.FormatUint(uint64(label), 10))
		segmentList := []table.Segment{table.NewSegmentSRMPLS(label)}

		if err := s.validateSIDs(req, segmentList); err != nil {
			t.Errorf("expected label %d to be in range, got: %v", label, err)
		}
	}
}

func TestValidateSIDs_AllKnownSucceeds(t *testing.T) {
	node := &table.LsNode{
		RouterID:  "0000.0000.0001",
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

func TestServe_InvalidAddress(t *testing.T) {
	s := &APIServer{grpcServer: grpc.NewServer(), logger: zap.NewNop()}
	require.Error(t, s.Serve("", "50052"))
}

func TestServe_InvalidPort(t *testing.T) {
	s := &APIServer{grpcServer: grpc.NewServer(), logger: zap.NewNop()}
	require.Error(t, s.Serve("127.0.0.1", "notaport"))
}

func TestServe_PortOutOfRange(t *testing.T) {
	s := &APIServer{grpcServer: grpc.NewServer(), logger: zap.NewNop()}
	require.Error(t, s.Serve("127.0.0.1", "70000"))
}

func TestServe_ListensAndLogsActualAddr(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	s := &APIServer{grpcServer: grpc.NewServer(), logger: zap.New(core)}

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve("127.0.0.1", "0") }()

	require.Eventually(t, func() bool {
		return len(logs.FilterMessage("Start listening on gRPC port").All()) > 0
	}, 2*time.Second, 10*time.Millisecond, "expected listenInfo to be logged")

	s.grpcServer.GracefulStop()
	require.NoError(t, <-errCh)

	entries := logs.FilterMessage("Start listening on gRPC port").All()
	require.Len(t, entries, 1)
	listenInfo, _ := entries[0].ContextMap()["listenInfo"].(string)
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
			if len(got) != 1 {
				t.Fatalf("convertLsPrefixes() returned %d prefixes, want 1", len(got))
			}
			if (got[0].SidIndex != nil) != tt.wantSet {
				t.Fatalf("sid_index set = %v, want %v", got[0].SidIndex != nil, tt.wantSet)
			}
			if tt.wantSet && got[0].GetSidIndex() != tt.wantSidIndex {
				t.Errorf("sid_index = %d, want %d", got[0].GetSidIndex(), tt.wantSidIndex)
			}
		})
	}
}

func TestGetSessionList_DeduplicatesNonAdjacentCaps(t *testing.T) {
	session := &Session{
		peerAddr: netip.MustParseAddr("10.0.0.1"),
		isSynced: true,
		advertisedCapabilities: []pcep.CapabilityInterface{
			&pcep.SRPCECapability{IsNAISupported: true},
			&pcep.SRv6PCECapability{IsNAISupported: true},
			&pcep.SRPCECapability{IsNAISupported: true},
		},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: zap.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)

	assert.Equal(t, []string{
		"SR", "MSD=0", "SR-NAI-Supported",
		"SRv6", "SRv6-NAI-Supported",
	}, resp.Sessions[0].Caps)
}
