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

// TestNewEnrichedSegmentSRMPLS verifies that localAddr and remoteAddr are
// propagated to SR-MPLS segments.
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

// TestNewEnrichedSegmentSRv6 verifies that SRv6 segment attributes are preserved.
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
		assert.Equal(t, table.SIDStructureBytes{32, 16, 0, 80}, srv6Seg.Structure, "Structure")
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

// TestCreateEroFromSegmentListWithNAI verifies that a localAddr is encoded as
// the SR-ERO node NAI.
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
	require.Len(t, resp.Sessions[0].Capabilities, 2)

	sr := resp.Sessions[0].Capabilities[0]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_SR, sr.GetType())
	assert.True(t, sr.GetSr().GetNaiSupported())

	srv6 := resp.Sessions[0].Capabilities[1]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_SRV6, srv6.GetType())
	assert.True(t, srv6.GetSrv6().GetNaiSupported())
}

func TestGetSessionList_BuildsStructuredCapabilities(t *testing.T) {
	session := &Session{
		peerAddr: netip.MustParseAddr("10.0.0.1"),
		isSynced: true,
		advertisedCapabilities: []pcep.CapabilityInterface{
			&pcep.SRPCECapability{IsNAISupported: true, MaximumSidDepth: 10},
			&pcep.LSPDBVersion{VersionNumber: 42},
		},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: zap.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Sessions[0].Capabilities, 2)

	sr := resp.Sessions[0].Capabilities[0]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_SR, sr.GetType())
	assert.Equal(t, uint32(10), sr.GetSr().GetMsd())
	assert.True(t, sr.GetSr().GetNaiSupported())

	dbVersion := resp.Sessions[0].Capabilities[1]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_LSP_DB_VERSION, dbVersion.GetType())
	assert.Equal(t, uint64(42), dbVersion.GetLspDbVersion().GetVersionNumber())
}

func TestGetSessionList_MultipathCapabilityDoesNotSetMsd(t *testing.T) {
	session := &Session{
		peerAddr: netip.MustParseAddr("10.0.0.1"),
		isSynced: true,
		advertisedCapabilities: []pcep.CapabilityInterface{
			pcep.NewMultipathCapability(8, true, true, true, true),
		},
	}
	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session}},
		logger: zap.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	require.Len(t, resp.Sessions[0].Capabilities, 1)

	multipath := resp.Sessions[0].Capabilities[0]
	assert.Equal(t, pb.CapabilityType_CAPABILITY_TYPE_MULTIPATH, multipath.GetType())
	assert.Nil(t, multipath.GetSr(), "MaxMultipaths must not be reported via the SR capability's Msd (Maximum SID Depth)")
	assert.Equal(t, uint32(8), multipath.GetMultipath().GetMaxMultipaths())
}

func TestGetSessionList_SortsSessionsByAddr(t *testing.T) {
	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{peerAddr: netip.MustParseAddr("10.0.0.2")},
			{peerAddr: netip.MustParseAddr("10.0.0.1")},
		}},
		logger: zap.NewNop(),
	}

	resp, err := s.GetSessionList(context.Background(), &pb.GetSessionListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 2)

	addr0, _ := netip.AddrFromSlice(resp.Sessions[0].GetAddr())
	addr1, _ := netip.AddrFromSlice(resp.Sessions[1].GetAddr())
	assert.Equal(t, "10.0.0.1", addr0.String())
	assert.Equal(t, "10.0.0.2", addr1.String())
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
		peerAddr: netip.MustParseAddr("10.0.0.2"),
		isSynced: true,
		srPolicies: []*table.SRPolicy{
			table.NewSRPolicy(1, "policy-b", []table.Segment{seg},
				netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20"),
				200, 100, 5, table.PolicyUp),
		},
	}
	session1 := &Session{
		peerAddr: netip.MustParseAddr("10.0.0.1"),
		isSynced: true,
		srPolicies: []*table.SRPolicy{
			table.NewSRPolicy(2, "policy-a", []table.Segment{seg},
				netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20"),
				100, 100, 7, table.PolicyActive),
		},
	}

	s := &APIServer{
		pce:    &Server{sessionList: []*Session{session2, session1}, ted: ted},
		logger: zap.NewNop(),
	}

	resp, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 2)

	// Sessions are ordered by peer address, not insertion order.
	addr0, _ := netip.AddrFromSlice(resp.Sessions[0].GetAddr())
	assert.Equal(t, "10.0.0.1", addr0.String())
	require.Len(t, resp.Sessions[0].GetSrPolicies(), 1)

	policy := resp.Sessions[0].GetSrPolicies()[0]
	assert.Equal(t, uint32(2), policy.GetPlspId())
	assert.Equal(t, uint32(7), policy.GetLspId())
	assert.Equal(t, pb.SRPolicyState_SR_POLICY_STATE_ACTIVE, policy.GetState())
	assert.Equal(t, "0000.0aff.0001", policy.GetSrcRouterId())
	assert.Empty(t, policy.GetDstRouterId(), "no TED node owns the destination address")
}

func TestBuildRouterIDIndex(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}

	v4Node := table.NewLsNode(65000, "router-v4")
	v4Prefix := table.NewLsPrefix(v4Node)
	v4Prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	v4Node.Prefixes = append(v4Node.Prefixes, v4Prefix)
	ted.Nodes[v4Node.RouterID] = v4Node

	v6Node := table.NewLsNode(65000, "router-v6")
	v6Prefix := table.NewLsPrefix(v6Node)
	v6Prefix.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	v6Node.Prefixes = append(v6Node.Prefixes, v6Prefix)
	ted.Nodes[v6Node.RouterID] = v6Node

	// A node without a loopback (host) prefix must not appear in the index.
	noLoopbackNode := table.NewLsNode(65000, "router-no-loopback")
	nonHostPrefix := table.NewLsPrefix(noLoopbackNode)
	nonHostPrefix.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	noLoopbackNode.Prefixes = append(noLoopbackNode.Prefixes, nonHostPrefix)
	ted.Nodes[noLoopbackNode.RouterID] = noLoopbackNode

	index := buildRouterIDIndex(ted)
	assert.Equal(t, "router-v4", index[netip.MustParseAddr("192.0.2.10")])
	assert.Equal(t, "router-v6", index[netip.MustParseAddr("2001:db8::1")])
	assert.Empty(t, index[netip.MustParseAddr("192.0.2.0")])

	assert.Nil(t, buildRouterIDIndex(nil))
}

func TestBuildAddressRouterIDIndex(t *testing.T) {
	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}

	v4Node := table.NewLsNode(65000, "router-v4")
	v4Prefix := table.NewLsPrefix(v4Node)
	v4Prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	v4Node.Prefixes = append(v4Node.Prefixes, v4Prefix)
	ted.Nodes[v4Node.RouterID] = v4Node

	v6Node := table.NewLsNode(65000, "router-v6")
	v6Prefix := table.NewLsPrefix(v6Node)
	v6Prefix.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	v6Node.Prefixes = append(v6Node.Prefixes, v6Prefix)
	ted.Nodes[v6Node.RouterID] = v6Node

	// Non-host prefixes are indexed too, by their network address.
	subnetNode := table.NewLsNode(65000, "router-subnet")
	subnetPrefix := table.NewLsPrefix(subnetNode)
	subnetPrefix.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	subnetNode.Prefixes = append(subnetNode.Prefixes, subnetPrefix)
	ted.Nodes[subnetNode.RouterID] = subnetNode

	index := buildAddressRouterIDIndex(ted)
	assert.Equal(t, "router-v4", index[netip.MustParseAddr("192.0.2.10")])
	assert.Equal(t, "router-v6", index[netip.MustParseAddr("2001:db8::1")])
	assert.Equal(t, "router-subnet", index[netip.MustParseAddr("192.0.2.0")])

	assert.Nil(t, buildAddressRouterIDIndex(nil))
}

func TestGetSRPolicyList_FiltersBySessionAddr(t *testing.T) {
	seg, err := table.NewSegment("16003")
	require.NoError(t, err)

	s := &APIServer{
		pce: &Server{sessionList: []*Session{
			{
				peerAddr: netip.MustParseAddr("10.0.0.1"),
				isSynced: true,
				srPolicies: []*table.SRPolicy{
					table.NewSRPolicy(1, "policy-a", []table.Segment{seg}, netip.Addr{}, netip.Addr{}, 100, 100, 0, table.PolicyUp),
				},
			},
			{
				peerAddr: netip.MustParseAddr("10.0.0.2"),
				isSynced: true,
				srPolicies: []*table.SRPolicy{
					table.NewSRPolicy(2, "policy-b", []table.Segment{seg}, netip.Addr{}, netip.Addr{}, 200, 100, 0, table.PolicyUp),
				},
			},
		}},
		logger: zap.NewNop(),
	}

	resp, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{SessionAddr: netip.MustParseAddr("10.0.0.2").AsSlice()})
	require.NoError(t, err)
	require.Len(t, resp.Sessions, 1)
	addr, _ := netip.AddrFromSlice(resp.Sessions[0].GetAddr())
	assert.Equal(t, "10.0.0.2", addr.String())
}

func TestGetSRPolicyList_RejectsInvalidSessionFilter(t *testing.T) {
	s := &APIServer{
		pce:    &Server{},
		logger: zap.NewNop(),
	}

	_, err := s.GetSRPolicyList(context.Background(), &pb.GetSRPolicyListRequest{SessionAddr: []byte{1, 2, 3}})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestResolveSRPolicyIntent(t *testing.T) {
	tests := []struct {
		name               string
		policy             *pb.SRPolicy
		disablePathCompute bool
		wantType           table.PolicyType
		wantMetric         table.MetricType
		wantErr            bool
	}{
		{
			name:               "disable_path_compute is always explicit regardless of Type",
			policy:             &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC},
			disablePathCompute: true,
			wantType:           table.PolicyTypeExplicit,
			wantMetric:         table.UnspecifiedMetric,
		},
		{
			name:       "explicit path has no metric",
			policy:     &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT},
			wantType:   table.PolicyTypeExplicit,
			wantMetric: table.UnspecifiedMetric,
		},
		{
			name:       "dynamic path resolves its metric",
			policy:     &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, Metric: pb.MetricType_METRIC_TYPE_TE},
			wantType:   table.PolicyTypeDynamic,
			wantMetric: table.TEMetric,
		},
		{
			name:    "dynamic path with unresolvable metric is an error",
			policy:  &pb.SRPolicy{Type: pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, Metric: pb.MetricType_METRIC_TYPE_UNSPECIFIED},
			wantErr: true,
		},
		{
			name:    "unspecified type is an error",
			policy:  &pb.SRPolicy{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotMetric, err := resolveSRPolicyIntent(tt.policy, tt.disablePathCompute)
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
				isSynced:   true,
				srPolicies: []*table.SRPolicy{knownPolicy, unknownPolicy},
			},
		}},
		logger: zap.NewNop(),
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

// TestTED_ConcurrentUpdate verifies that TED reads and updates are synchronized.
func TestTED_ConcurrentUpdate(t *testing.T) {
	s := &Server{ted: &table.LsTED{Nodes: map[string]*table.LsNode{}}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			node := table.NewLsNode(1, "router")
			prefix := table.NewLsPrefix(node)
			prefix.Prefix = netip.MustParsePrefix("192.0.2.1/32")
			node.Prefixes = append(node.Prefixes, prefix)
			s.setTED(&table.LsTED{Nodes: map[string]*table.LsNode{"router": node}})
		}
	}()

	for i := 0; i < 100; i++ {
		_ = buildRouterIDIndex(s.TED())
	}
	<-done
}

// TestSessionList_ConcurrentAccess verifies that session list reads and updates are synchronized.
func TestSessionList_ConcurrentAccess(t *testing.T) {
	s := &Server{}
	addr := netip.MustParseAddr("192.0.2.1")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			ss := &Session{sessionID: uint8(i), peerAddr: addr, isSynced: true}

			s.sessionMu.Lock()
			s.sessionList = append(s.sessionList, ss)
			s.sessionMu.Unlock()

			s.sessionMu.Lock()
			for j, v := range s.sessionList {
				if v.sessionID == ss.sessionID {
					s.sessionList[j] = s.sessionList[len(s.sessionList)-1]
					s.sessionList = s.sessionList[:len(s.sessionList)-1]
					break
				}
			}
			s.sessionMu.Unlock()
		}
	}()

	for i := 0; i < 100; i++ {
		s.SearchSession(addr, false)
		s.SRPolicies()
		s.Sessions()
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

	ss := NewSession(1, peerAddr, server, zap.NewNop(), nil, 0)
	ss.isSynced = true
	ss.srPolicies = []*table.SRPolicy{
		{
			PlspID:     1,
			Name:       "test-policy",
			DstAddr:    dstAddr,
			Color:      100,
			Preference: 100,
		},
	}

	pce := &Server{sessionList: []*Session{ss}}
	apiServer := &APIServer{pce: pce, logger: zap.NewNop()}

	req := &pb.DeleteSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			PcepSessionAddr: peerAddr.AsSlice(),
			DstAddr:         dstAddr.AsSlice(),
			Color:           100,
			PolicyName:      "test-policy",
		},
	}

	resp, err := apiServer.DeleteSRPolicy(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.GetIsSuccess())
}
