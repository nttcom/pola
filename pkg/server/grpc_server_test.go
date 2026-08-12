// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"bytes"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/table"
	"go.uber.org/zap"
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
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("newEnrichedSegment returned an error: %v", err)
			}

			mplsSeg, ok := seg.(table.SegmentSRMPLS)
			if !ok {
				t.Fatalf("segment type: got %T, want table.SegmentSRMPLS", seg)
			}
			if got := addrString(mplsSeg.LocalAddr); got != tt.wantLocal {
				t.Errorf("LocalAddr: got %q, want %q", got, tt.wantLocal)
			}
			if got := addrString(mplsSeg.RemoteAddr); got != tt.wantRemote {
				t.Errorf("RemoteAddr: got %q, want %q", got, tt.wantRemote)
			}
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
		if err != nil {
			t.Fatalf("newEnrichedSegment returned an error: %v", err)
		}

		srv6Seg, ok := seg.(table.SegmentSRv6)
		if !ok {
			t.Fatalf("segment type: got %T, want table.SegmentSRv6", seg)
		}
		if got := srv6Seg.Sid.String(); got != "2001:db8:1005::" {
			t.Errorf("Sid: got %q, want %q", got, "2001:db8:1005::")
		}
		if got := addrString(srv6Seg.LocalAddr); got != "2001:db8::5" {
			t.Errorf("LocalAddr: got %q, want %q", got, "2001:db8::5")
		}
		if got := addrString(srv6Seg.RemoteAddr); got != "2001:db8::6" {
			t.Errorf("RemoteAddr: got %q, want %q", got, "2001:db8::6")
		}
		if want := []uint8{32, 16, 0, 80}; !slices.Equal(srv6Seg.Structure, want) {
			t.Errorf("Structure: got %v, want %v", srv6Seg.Structure, want)
		}
		if srv6Seg.USid != usidMode {
			t.Errorf("USid with usidMode=%v: got %v", usidMode, srv6Seg.USid)
		}
	}
}

func TestNewEnrichedSegmentInvalidSID(t *testing.T) {
	if _, err := newEnrichedSegment(&pb.Segment{Sid: "not-a-sid"}, false); err == nil {
		t.Error("expected an error for an unparsable SID, got none")
	}
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
	if len(ero.EroSubobjects) != 1 {
		t.Fatalf("ERO subobject count: got %d, want 1", len(ero.EroSubobjects))
	}

	raw, err := ero.EroSubobjects[0].Serialize()
	if err != nil {
		t.Fatalf("Serialize returned an error: %v", err)
	}
	// Type, Length, NT/Flags (4byte) + SID (4byte) + NAI (4byte)
	if len(raw) != 12 {
		t.Fatalf("serialized size: got %d, want 12", len(raw))
	}
	if nt := raw[2] >> 4; nt != 0x01 {
		t.Errorf("NAI type: got 0x%02x, want 0x01 (IPv4 node ID)", nt)
	}
	if raw[3]&0x08 != 0 {
		t.Error("F flag is set even though the NAI is present")
	}
	if want := seg.LocalAddr.AsSlice(); !bytes.Equal(raw[8:12], want) {
		t.Errorf("NAI: got %v, want %v", raw[8:12], want)
	}
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

	if err := s.validateSIDs(req, segmentList); err != nil {
		t.Errorf("expected no_sid_validate to skip the check even with no TED, got: %v", err)
	}
}

func TestValidateSIDs_DynamicPathSkipsCheck(t *testing.T) {
	s := newTestAPIServer(nil)
	req := dynamicPolicyRequest()
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16099)}

	if err := s.validateSIDs(req, segmentList); err != nil {
		t.Errorf("expected a dynamic path to skip the check, got: %v", err)
	}
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
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
}

func TestValidateSIDs_NoTED(t *testing.T) {
	s := newTestAPIServer(nil)
	req := explicitPolicyRequest(false, "16003")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected codes.FailedPrecondition, got: %v", err)
	}
	if !strings.Contains(st.Message(), "TED is not enabled") {
		t.Errorf("unexpected message: %s", st.Message())
	}
}

func TestValidateSIDs_TEDEmpty(t *testing.T) {
	s := newTestAPIServer(&table.LsTED{Nodes: map[string]*table.LsNode{}})
	req := explicitPolicyRequest(false, "16003")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16003)}

	err := s.validateSIDs(req, segmentList)
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected codes.FailedPrecondition, got: %v", err)
	}
	if !strings.Contains(st.Message(), "not yet synchronized") {
		t.Errorf("expected a distinct message for an empty-but-enabled TED, got: %s", st.Message())
	}
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
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
	if !strings.Contains(st.Message(), "hop 1") {
		t.Errorf("expected the missing hop to be listed, got: %s", st.Message())
	}
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
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
	if !strings.Contains(st.Message(), "hop 1") {
		t.Errorf("expected the missing hop to be listed, got: %s", st.Message())
	}
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

	if err := s.validateSIDs(req, segmentList); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
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
