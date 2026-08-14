// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package grpc

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type fakeClient struct {
	pb.PCEServiceClient

	sessionListResp *pb.GetSessionListResponse
	sessionListErr  error

	deleteSessionErr error

	srPolicyListResp *pb.GetSRPolicyListResponse
	srPolicyListErr  error

	createSRPolicyErr error
	deleteSRPolicyErr error

	tedResp *pb.GetTEDResponse
	tedErr  error
}

func (f *fakeClient) GetSessionList(ctx context.Context, in *pb.GetSessionListRequest, opts ...grpc.CallOption) (*pb.GetSessionListResponse, error) {
	return f.sessionListResp, f.sessionListErr
}

func (f *fakeClient) DeleteSession(ctx context.Context, in *pb.DeleteSessionRequest, opts ...grpc.CallOption) (*pb.DeleteSessionResponse, error) {
	if f.deleteSessionErr != nil {
		return nil, f.deleteSessionErr
	}
	return &pb.DeleteSessionResponse{}, nil
}

func (f *fakeClient) GetSRPolicyList(ctx context.Context, in *pb.GetSRPolicyListRequest, opts ...grpc.CallOption) (*pb.GetSRPolicyListResponse, error) {
	return f.srPolicyListResp, f.srPolicyListErr
}

func (f *fakeClient) CreateSRPolicy(ctx context.Context, in *pb.CreateSRPolicyRequest, opts ...grpc.CallOption) (*pb.CreateSRPolicyResponse, error) {
	if f.createSRPolicyErr != nil {
		return nil, f.createSRPolicyErr
	}
	return &pb.CreateSRPolicyResponse{IsSuccess: true}, nil
}

func (f *fakeClient) DeleteSRPolicy(ctx context.Context, in *pb.DeleteSRPolicyRequest, opts ...grpc.CallOption) (*pb.DeleteSRPolicyResponse, error) {
	if f.deleteSRPolicyErr != nil {
		return nil, f.deleteSRPolicyErr
	}
	return &pb.DeleteSRPolicyResponse{IsSuccess: true}, nil
}

func (f *fakeClient) GetTED(ctx context.Context, in *pb.GetTEDRequest, opts ...grpc.CallOption) (*pb.GetTEDResponse, error) {
	return f.tedResp, f.tedErr
}

// sid_index presence must distinguish index 0 from an absent Prefix-SID.
func TestCreateLsPrefix_SidIndexPresence(t *testing.T) {
	tests := []struct {
		name            string
		prefix          *pb.LsPrefix
		wantSidIndex    uint32
		wantHasSidIndex bool
	}{
		{
			name:            "no Prefix-SID",
			prefix:          &pb.LsPrefix{Prefix: "10.0.0.1/32"},
			wantSidIndex:    0,
			wantHasSidIndex: false,
		},
		{
			name:            "Prefix-SID index 0",
			prefix:          &pb.LsPrefix{Prefix: "10.0.0.1/32", SidIndex: proto.Uint32(0)},
			wantSidIndex:    0,
			wantHasSidIndex: true,
		},
		{
			name:            "Prefix-SID index 16000",
			prefix:          &pb.LsPrefix{Prefix: "10.0.0.1/32", SidIndex: proto.Uint32(16000)},
			wantSidIndex:    16000,
			wantHasSidIndex: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lsPrefix, err := createLsPrefix(table.NewLsNode(65000, "0000.0000.0001"), tt.prefix)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSidIndex, lsPrefix.SidIndex)
			assert.Equal(t, tt.wantHasSidIndex, lsPrefix.HasSidIndex)
			assert.Equal(t, tt.wantHasSidIndex, lsPrefix.HasPrefixSID())
		})
	}
}

func TestCreateLsPrefix_InvalidPrefix(t *testing.T) {
	_, err := createLsPrefix(table.NewLsNode(65000, "0000.0000.0001"), &pb.LsPrefix{Prefix: "not-a-prefix"})
	require.Error(t, err)
}

func TestSegmentFromPB_SRMPLS(t *testing.T) {
	tests := []struct {
		name       string
		localAddr  string
		remoteAddr string
	}{
		{name: "localAddr only", localAddr: "192.0.2.1"},
		{name: "remoteAddr only", remoteAddr: "192.0.2.2"},
		{name: "localAddr and remoteAddr", localAddr: "192.0.2.1", remoteAddr: "192.0.2.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := segmentFromPB(&pb.Segment{
				Sid:        "16003",
				LocalAddr:  tt.localAddr,
				RemoteAddr: tt.remoteAddr,
			})
			require.NoError(t, err)

			mplsSeg, ok := seg.(table.SegmentSRMPLS)
			require.Truef(t, ok, "segment type: got %T, want table.SegmentSRMPLS", seg)
			assert.Equal(t, "16003", mplsSeg.SidString())
			if tt.localAddr == "" {
				assert.False(t, mplsSeg.LocalAddr.IsValid())
			} else {
				assert.Equal(t, tt.localAddr, mplsSeg.LocalAddr.String())
			}
			if tt.remoteAddr == "" {
				assert.False(t, mplsSeg.RemoteAddr.IsValid())
			} else {
				assert.Equal(t, tt.remoteAddr, mplsSeg.RemoteAddr.String())
			}
		})
	}
}

func TestSegmentFromPB_SRv6(t *testing.T) {
	seg, err := segmentFromPB(&pb.Segment{
		Sid:          "2001:db8:1005::",
		LocalAddr:    "2001:db8::5",
		RemoteAddr:   "2001:db8::6",
		SidStructure: "32,16,0,80",
	})
	require.NoError(t, err)

	srv6Seg, ok := seg.(table.SegmentSRv6)
	require.Truef(t, ok, "segment type: got %T, want table.SegmentSRv6", seg)
	assert.Equal(t, "2001:db8:1005::", srv6Seg.SidString())
	assert.Equal(t, "2001:db8::5", srv6Seg.LocalAddr.String())
	assert.Equal(t, "2001:db8::6", srv6Seg.RemoteAddr.String())
	assert.Equal(t, table.SIDStructureBytes{32, 16, 0, 80}, srv6Seg.Structure)
}

func TestSegmentFromPB_InvalidSID(t *testing.T) {
	_, err := segmentFromPB(&pb.Segment{Sid: "not-a-sid"})
	require.Error(t, err)
}

func TestParseSidStructure(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []uint8
	}{
		{"empty returns nil", "", nil},
		{"valid", "32,16,0,80", []uint8{32, 16, 0, 80}},
		{"wrong part count", "32,16,0", nil},
		{"non-numeric part", "32,16,0,xx", nil},
		{"value out of uint8 range", "32,16,0,256", nil},
		{"whitespace around parts is trimmed", " 32 , 16 , 0 , 80 ", []uint8{32, 16, 0, 80}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseSidStructure(tt.in))
		})
	}
}

func TestGetSessions_NoCapabilitiesIsEmptySlice(t *testing.T) {
	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				Addr:  netip.MustParseAddr("192.0.2.1").AsSlice(),
				State: pb.SessionState_SESSION_STATE_UP,
			},
		},
	}}

	sessions, err := GetSessions(client)
	require.NoError(t, err)
	require.Len(t, sessions, 1)

	require.NotNil(t, sessions[0].Capabilities)
	assert.Empty(t, sessions[0].Capabilities)

	marshaled, err := json.Marshal(sessions[0])
	require.NoError(t, err)
	assert.Contains(t, string(marshaled), `"Capabilities":[]`)
}

func TestGetSessions_WithCapabilities(t *testing.T) {
	client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
		Sessions: []*pb.Session{
			{
				Addr:  netip.MustParseAddr("192.0.2.1").AsSlice(),
				State: pb.SessionState_SESSION_STATE_UP,
				Capabilities: []*pb.Capability{
					{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: 10}}},
				},
			},
		},
	}}

	sessions, err := GetSessions(client)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, []Capability{{Type: "SR", Detail: SRCapability{MSD: 10}}}, sessions[0].Capabilities)
}

func TestGetSessions_Errors(t *testing.T) {
	t.Run("client error propagates", func(t *testing.T) {
		client := &fakeClient{sessionListErr: assert.AnError}
		_, err := GetSessions(client)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("malformed session address", func(t *testing.T) {
		client := &fakeClient{sessionListResp: &pb.GetSessionListResponse{
			Sessions: []*pb.Session{{Addr: []byte{1, 2, 3}}},
		}}
		_, err := GetSessions(client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session address")
	})
}

func TestDeleteSession(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := &fakeClient{}
		err := DeleteSession(client, &pb.DeleteSessionRequest{Addr: netip.MustParseAddr("192.0.2.1").AsSlice()})
		require.NoError(t, err)
	})

	t.Run("error propagates", func(t *testing.T) {
		client := &fakeClient{deleteSessionErr: assert.AnError}
		err := DeleteSession(client, &pb.DeleteSessionRequest{})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestCapabilityDetail_Strings(t *testing.T) {
	tests := []struct {
		name   string
		detail capabilityDetail
		want   []string
	}{
		{
			name: "Stateful with every RFC 8231/8232 flag set",
			detail: StatefulCapability{
				LSPUpdate: true, IncludeDBVersion: true, LSPInstantiation: true,
				TriggeredResync: true, DeltaLSPSync: true, TriggeredInitialSync: true, Color: true,
			},
			want: []string{"Stateful", "Update", "Include-DB-Ver", "Instantiation", "Triggered-Resync", "Delta-LSP-Sync", "Triggered-Initial-Sync", "Color"},
		},
		{name: "Stateful with no flags", detail: StatefulCapability{}, want: []string{"Stateful"}},
		{name: "SR unlimited MSD with NAI support", detail: SRCapability{UnlimitedMSD: true, NAISupported: true}, want: []string{"SR", "Unlimited-SID-Depth", "SR-NAI-Supported"}},
		{name: "SR bounded MSD without NAI support", detail: SRCapability{MSD: 10}, want: []string{"SR", "MSD=10"}},
		{name: "SRv6 with NAI support", detail: SRv6Capability{NAISupported: true}, want: []string{"SRv6", "SRv6-NAI-Supported"}},
		{name: "SRv6 without NAI support", detail: SRv6Capability{}, want: []string{"SRv6"}},
		{name: "PathSetupType SR-TE (1) and SRv6-TE (3)", detail: PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}, want: []string{"SR-TE", "SRv6-TE"}},
		{name: "PathSetupType unrecognized value is omitted", detail: PathSetupTypeCapability{PathSetupTypes: []uint32{99}}, want: nil},
		{name: "AssocTypeList", detail: AssocTypeListCapability{AssocTypes: []uint32{6, 7}}, want: []string{"AssocType:6", "AssocType:7"}},
		{name: "LSPDBVersion", detail: LSPDBVersionCapability{VersionNumber: 5}, want: []string{"LSP-DB-VERSION"}},
		{
			name:   "Multipath with every RFC 8751 flag set",
			detail: MultipathCapability{MaxMultipaths: 4, Weighted: true, OppositeDir: true, ForwardClass: true, CompositePath: true},
			want:   []string{"Multipath", "MaxMultipaths=4", "Weighted", "OppositeDir", "ForwardClass", "CompositePath"},
		},
		{name: "Multipath with no flags", detail: MultipathCapability{MaxMultipaths: 2}, want: []string{"Multipath", "MaxMultipaths=2"}},
		{name: "VendorInformation", detail: VendorInformationCapability{EnterpriseNumber: 9}, want: []string{"Vendor-Info(9)"}},
		{name: "Unknown TLV", detail: UnknownCapability{TLVType: 42}, want: []string{"unknown_type_42"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.detail.Strings())
		})
	}
}

func TestCapability_Strings(t *testing.T) {
	t.Run("nil Detail falls back to type token", func(t *testing.T) {
		cap := Capability{Type: "VENDOR_INFORMATION"}
		assert.Equal(t, []string{"VENDOR_INFORMATION"}, cap.Strings())
	})

	t.Run("typed Detail is unaffected", func(t *testing.T) {
		cap := Capability{Type: "SR", Detail: SRCapability{MSD: 10}}
		assert.Equal(t, []string{"SR", "MSD=10"}, cap.Strings())
	})
}

func TestSession_CapStrings(t *testing.T) {
	s := Session{Capabilities: []Capability{
		{Type: "SR", Detail: SRCapability{MSD: 10}},
		{Type: "SRV6", Detail: SRv6Capability{NAISupported: true}},
	}}
	assert.Equal(t, []string{"SR", "MSD=10", "SRv6", "SRv6-NAI-Supported"}, s.CapStrings())
}

func TestCapabilityFromPB(t *testing.T) {
	tests := []struct {
		name  string
		pbCap *pb.Capability
		want  Capability
	}{
		{
			name:  "Stateful",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_STATEFUL, Detail: &pb.Capability_Stateful{Stateful: &pb.StatefulCapability{LspUpdate: true, Color: true}}},
			want:  Capability{Type: "STATEFUL", Detail: StatefulCapability{LSPUpdate: true, Color: true}},
		},
		{
			name:  "SR",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{UnlimitedMsd: true, NaiSupported: true, Msd: 5}}},
			want:  Capability{Type: "SR", Detail: SRCapability{UnlimitedMSD: true, NAISupported: true, MSD: 5}},
		},
		{
			name:  "SRv6",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_SRV6, Detail: &pb.Capability_Srv6{Srv6: &pb.Srv6Capability{NaiSupported: true}}},
			want:  Capability{Type: "SRV6", Detail: SRv6Capability{NAISupported: true}},
		},
		{
			name:  "PathSetupType",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_PATH_SETUP_TYPE, Detail: &pb.Capability_PathSetupType{PathSetupType: &pb.PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}}},
			want:  Capability{Type: "PATH_SETUP_TYPE", Detail: PathSetupTypeCapability{PathSetupTypes: []uint32{1, 3}}},
		},
		{
			name:  "AssocTypeList",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_ASSOC_TYPE_LIST, Detail: &pb.Capability_AssocTypeList{AssocTypeList: &pb.AssocTypeListCapability{AssocTypes: []uint32{6}}}},
			want:  Capability{Type: "ASSOC_TYPE_LIST", Detail: AssocTypeListCapability{AssocTypes: []uint32{6}}},
		},
		{
			name:  "LspDbVersion",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_LSP_DB_VERSION, Detail: &pb.Capability_LspDbVersion{LspDbVersion: &pb.LspDbVersionCapability{VersionNumber: 9}}},
			want:  Capability{Type: "LSP_DB_VERSION", Detail: LSPDBVersionCapability{VersionNumber: 9}},
		},
		{
			name:  "Multipath",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_MULTIPATH, Detail: &pb.Capability_Multipath{Multipath: &pb.MultipathCapability{MaxMultipaths: 3, Weighted: true}}},
			want:  Capability{Type: "MULTIPATH", Detail: MultipathCapability{MaxMultipaths: 3, Weighted: true}},
		},
		{
			name:  "VendorInformation",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_VENDOR_INFORMATION, Detail: &pb.Capability_VendorInformation{VendorInformation: &pb.VendorInformationCapability{EnterpriseNumber: 12}}},
			want:  Capability{Type: "VENDOR_INFORMATION", Detail: VendorInformationCapability{EnterpriseNumber: 12}},
		},
		{
			name:  "Unknown",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_UNKNOWN, Detail: &pb.Capability_Unknown{Unknown: &pb.UnknownCapability{TlvType: 77}}},
			want:  Capability{Type: "UNKNOWN", Detail: UnknownCapability{TLVType: 77}},
		},
		{
			name:  "no detail set falls back to nil Detail",
			pbCap: &pb.Capability{Type: pb.CapabilityType_CAPABILITY_TYPE_UNSPECIFIED},
			want:  Capability{Type: "UNSPECIFIED", Detail: nil},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, capabilityFromPB(tt.pbCap))
		})
	}
}

func TestPolicyStateFromPB(t *testing.T) {
	tests := []struct {
		name string
		in   pb.SRPolicyState
		want table.PolicyState
	}{
		{"down", pb.SRPolicyState_SR_POLICY_STATE_DOWN, table.PolicyDown},
		{"up", pb.SRPolicyState_SR_POLICY_STATE_UP, table.PolicyUp},
		{"active", pb.SRPolicyState_SR_POLICY_STATE_ACTIVE, table.PolicyActive},
		{"unknown", pb.SRPolicyState_SR_POLICY_STATE_UNKNOWN, table.PolicyUnknown},
		{"unspecified maps to the empty state", pb.SRPolicyState_SR_POLICY_STATE_UNSPECIFIED, table.PolicyState("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, policyStateFromPB(tt.in))
		})
	}
}

func TestPolicyTypeFromPB(t *testing.T) {
	tests := []struct {
		name string
		in   pb.SRPolicyType
		want table.PolicyType
	}{
		{"explicit", pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, table.PolicyTypeExplicit},
		{"dynamic", pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, table.PolicyTypeDynamic},
		{"unspecified maps to the unknown type", pb.SRPolicyType_SR_POLICY_TYPE_UNSPECIFIED, table.PolicyType("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, policyTypeFromPB(tt.in))
		})
	}
}

func TestMetricTypeFromPB(t *testing.T) {
	tests := []struct {
		name string
		in   pb.MetricType
		want table.MetricType
	}{
		{"igp", pb.MetricType_METRIC_TYPE_IGP, table.IGPMetric},
		{"te", pb.MetricType_METRIC_TYPE_TE, table.TEMetric},
		{"delay", pb.MetricType_METRIC_TYPE_DELAY, table.DelayMetric},
		{"hopcount", pb.MetricType_METRIC_TYPE_HOPCOUNT, table.HopcountMetric},
		{"unspecified maps to no optimization objective (explicit path)", pb.MetricType_METRIC_TYPE_UNSPECIFIED, table.UnspecifiedMetric},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, metricTypeFromPB(tt.in))
		})
	}
}

func TestConvertSRPolicy(t *testing.T) {
	t.Run("full mapping", func(t *testing.T) {
		p := &pb.SRPolicy{
			PlspId:      7,
			PolicyName:  "pol1",
			SrcAddr:     netip.MustParseAddr("192.0.2.1").AsSlice(),
			DstAddr:     netip.MustParseAddr("192.0.2.2").AsSlice(),
			SrcRouterId: "0000.0aff.0001",
			DstRouterId: "0000.0aff.0002",
			Color:       100,
			Preference:  200,
			LspId:       3,
			State:       pb.SRPolicyState_SR_POLICY_STATE_UP,
			Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
			Metric:      pb.MetricType_METRIC_TYPE_UNSPECIFIED,
			SegmentList: []*pb.Segment{{Sid: "16003"}},
		}
		got, err := convertSRPolicy(p)
		require.NoError(t, err)
		want := table.SRPolicy{
			PlspID:      7,
			Name:        "pol1",
			SegmentList: []table.Segment{table.SegmentSRMPLS{Sid: 16003}},
			SrcAddr:     netip.MustParseAddr("192.0.2.1"),
			DstAddr:     netip.MustParseAddr("192.0.2.2"),
			SrcRouterID: "0000.0aff.0001",
			DstRouterID: "0000.0aff.0002",
			Color:       100,
			Preference:  200,
			LSPID:       3,
			State:       table.PolicyUp,
			Type:        table.PolicyTypeExplicit,
			Metric:      table.UnspecifiedMetric,
		}
		assert.Equal(t, want, got)
	})

	t.Run("invalid source address", func(t *testing.T) {
		_, err := convertSRPolicy(&pb.SRPolicy{SrcAddr: []byte{1, 2, 3}, DstAddr: netip.MustParseAddr("192.0.2.2").AsSlice()})
		require.Error(t, err)
	})

	t.Run("invalid destination address", func(t *testing.T) {
		_, err := convertSRPolicy(&pb.SRPolicy{SrcAddr: netip.MustParseAddr("192.0.2.1").AsSlice(), DstAddr: []byte{1, 2, 3}})
		require.Error(t, err)
	})

	t.Run("invalid segment propagates the error", func(t *testing.T) {
		_, err := convertSRPolicy(&pb.SRPolicy{
			SrcAddr:     netip.MustParseAddr("192.0.2.1").AsSlice(),
			DstAddr:     netip.MustParseAddr("192.0.2.2").AsSlice(),
			SegmentList: []*pb.Segment{{Sid: "not-a-sid"}},
		})
		require.Error(t, err)
	})
}

func TestGetSRPolicyList(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := &fakeClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.Session{{
				Addr: netip.MustParseAddr("192.0.2.1").AsSlice(),
				SrPolicies: []*pb.SRPolicy{{
					PolicyName: "pol1",
					SrcAddr:    netip.MustParseAddr("192.0.2.1").AsSlice(),
					DstAddr:    netip.MustParseAddr("192.0.2.2").AsSlice(),
				}},
			}},
		}}
		got, err := GetSRPolicyList(client, netip.MustParseAddr("192.0.2.1"))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "192.0.2.1", got[0].Addr.String())
		require.Len(t, got[0].SRPolicies, 1)
		assert.Equal(t, "pol1", got[0].SRPolicies[0].Name)
	})

	t.Run("client error propagates", func(t *testing.T) {
		client := &fakeClient{srPolicyListErr: assert.AnError}
		_, err := GetSRPolicyList(client, netip.Addr{})
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("invalid session address", func(t *testing.T) {
		client := &fakeClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.Session{{Addr: []byte{1, 2, 3}}},
		}}
		_, err := GetSRPolicyList(client, netip.Addr{})
		require.Error(t, err)
	})

	t.Run("policy conversion error propagates", func(t *testing.T) {
		client := &fakeClient{srPolicyListResp: &pb.GetSRPolicyListResponse{
			Sessions: []*pb.Session{{
				Addr:       netip.MustParseAddr("192.0.2.1").AsSlice(),
				SrPolicies: []*pb.SRPolicy{{SrcAddr: []byte{1, 2, 3}}},
			}},
		}}
		_, err := GetSRPolicyList(client, netip.Addr{})
		require.Error(t, err)
	})
}

func TestCreateSRPolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		require.NoError(t, CreateSRPolicy(&fakeClient{}, &pb.CreateSRPolicyRequest{}))
	})

	t.Run("error propagates", func(t *testing.T) {
		err := CreateSRPolicy(&fakeClient{createSRPolicyErr: assert.AnError}, &pb.CreateSRPolicyRequest{})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestDeleteSRPolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		require.NoError(t, DeleteSRPolicy(&fakeClient{}, &pb.DeleteSRPolicyRequest{}))
	})

	t.Run("error propagates", func(t *testing.T) {
		err := DeleteSRPolicy(&fakeClient{deleteSRPolicyErr: assert.AnError}, &pb.DeleteSRPolicyRequest{})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestGetTED_Disabled(t *testing.T) {
	ted, err := GetTED(&fakeClient{tedResp: &pb.GetTEDResponse{Enable: false}})
	require.NoError(t, err)
	assert.Nil(t, ted)
}

func TestGetTED_ClientError(t *testing.T) {
	_, err := GetTED(&fakeClient{tedErr: assert.AnError})
	require.ErrorIs(t, err, assert.AnError)
}

func TestGetTED_Success(t *testing.T) {
	nodeA := &pb.LsNode{
		Asn:        65000,
		RouterId:   "0000.0aff.0001",
		Hostname:   "routerA",
		IsisAreaId: "49.0001",
		SrgbBegin:  16000,
		SrgbEnd:    23999,
		LsLinks: []*pb.LsLink{
			{
				LocalRouterId:  "0000.0aff.0001",
				RemoteRouterId: "0000.0aff.0002",
				LocalIp:        "192.0.2.1",
				RemoteIp:       "192.0.2.2",
				AdjSid:         24001,
				Metrics: []*pb.Metric{
					{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10},
					{Type: pb.MetricType_METRIC_TYPE_TE, Value: 20},
					{Type: pb.MetricType_METRIC_TYPE_DELAY, Value: 30},
					{Type: pb.MetricType_METRIC_TYPE_HOPCOUNT, Value: 1},
				},
				Srv6EndXSid: &pb.Srv6EndXSID{
					EndpointBehavior: uint32(table.BehaviorENDX),
					Sids:             []*pb.SID{{Sid: "2001:db8:1::"}},
					SidStructure:     &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80},
				},
			},
			{
				LocalRouterId:  "0000.0aff.0001",
				RemoteRouterId: "0000.0aff.0002",
			},
		},
		LsPrefixes: []*pb.LsPrefix{
			{Prefix: "10.0.0.1/32", SidIndex: proto.Uint32(1)},
			{Prefix: "10.0.0.2/32"},
		},
		LsSrv6Sids: []*pb.LsSrv6SID{
			{
				Sids:             []*pb.SID{{Sid: "2001:db8:1::"}},
				EndpointBehavior: &pb.EndpointBehavior{Behavior: uint32(table.BehaviorEND), Flags: 1, Algorithm: 0},
				SidStructure:     &pb.SidStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80},
				MultiTopoIds:     []*pb.MultiTopoID{{MultiTopoId: 1}},
			},
		},
	}
	nodeB := &pb.LsNode{Asn: 65000, RouterId: "0000.0aff.0002"}

	client := &fakeClient{tedResp: &pb.GetTEDResponse{Enable: true, LsNodes: []*pb.LsNode{nodeA, nodeB}}}
	ted, err := GetTED(client)
	require.NoError(t, err)
	require.NotNil(t, ted)

	a := ted.Nodes["0000.0aff.0001"]
	require.NotNil(t, a)
	assert.Equal(t, "routerA", a.Hostname)
	assert.Equal(t, "49.0001", a.IsisAreaID)
	assert.Equal(t, uint32(16000), a.SrgbBegin)
	assert.Equal(t, uint32(23999), a.SrgbEnd)
	require.Len(t, a.Links, 2)

	link0 := a.Links[0]
	assert.Equal(t, "192.0.2.1", link0.LocalIP.String())
	assert.Equal(t, "192.0.2.2", link0.RemoteIP.String())
	assert.Same(t, ted.Nodes["0000.0aff.0002"], link0.RemoteNode)
	assert.Equal(t, uint32(24001), link0.AdjSid)
	assert.Equal(t, []*table.Metric{
		table.NewMetric(table.IGPMetric, 10),
		table.NewMetric(table.TEMetric, 20),
		table.NewMetric(table.DelayMetric, 30),
		table.NewMetric(table.HopcountMetric, 1),
	}, link0.Metrics)
	require.NotNil(t, link0.Srv6EndXSID)
	assert.Equal(t, table.BehaviorENDX, link0.Srv6EndXSID.EndpointBehavior)
	assert.Equal(t, []string{"2001:db8:1::"}, link0.Srv6EndXSID.Sids)
	assert.Equal(t, table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80}, link0.Srv6EndXSID.Srv6SIDStructure)

	link1 := a.Links[1]
	assert.False(t, link1.LocalIP.IsValid())
	assert.False(t, link1.RemoteIP.IsValid())

	require.Len(t, a.Prefixes, 2)
	assert.True(t, a.Prefixes[0].HasPrefixSID())
	assert.Equal(t, uint32(1), a.Prefixes[0].SidIndex)
	assert.False(t, a.Prefixes[1].HasPrefixSID())

	require.Len(t, a.SRv6SIDs, 1)
	sid := a.SRv6SIDs[0]
	assert.Equal(t, []string{"2001:db8:1::"}, sid.Sids)
	assert.Equal(t, []uint32{1}, sid.MultiTopoIDs)
	assert.Equal(t, table.EndpointBehavior{Behavior: table.BehaviorEND, Flags: 1, Algorithm: 0}, sid.EndpointBehavior)
	assert.Equal(t, table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 0, LocalArg: 80}, sid.SIDStructure)
}

func TestGetTED_PropagatesConversionErrors(t *testing.T) {
	t.Run("invalid link IP", func(t *testing.T) {
		node := &pb.LsNode{RouterId: "0000.0aff.0001", LsLinks: []*pb.LsLink{
			{LocalRouterId: "0000.0aff.0001", RemoteRouterId: "0000.0aff.0001", LocalIp: "not-an-ip"},
		}}
		_, err := GetTED(&fakeClient{tedResp: &pb.GetTEDResponse{Enable: true, LsNodes: []*pb.LsNode{node}}})
		require.Error(t, err)
	})

	t.Run("invalid prefix", func(t *testing.T) {
		node := &pb.LsNode{RouterId: "0000.0aff.0001", LsPrefixes: []*pb.LsPrefix{{Prefix: "not-a-prefix"}}}
		_, err := GetTED(&fakeClient{tedResp: &pb.GetTEDResponse{Enable: true, LsNodes: []*pb.LsNode{node}}})
		require.Error(t, err)
	})
}

func TestCreateLsLink(t *testing.T) {
	localNode := table.NewLsNode(65000, "0000.0000.0001")
	remoteNode := table.NewLsNode(65000, "0000.0000.0002")

	t.Run("invalid localIp", func(t *testing.T) {
		_, err := createLsLink(localNode, remoteNode, &pb.LsLink{LocalIp: "not-an-ip"})
		require.Error(t, err)
	})

	t.Run("invalid remoteIp", func(t *testing.T) {
		_, err := createLsLink(localNode, remoteNode, &pb.LsLink{RemoteIp: "not-an-ip"})
		require.Error(t, err)
	})

	t.Run("metric conversion error propagates", func(t *testing.T) {
		_, err := createLsLink(localNode, remoteNode, &pb.LsLink{
			Metrics: []*pb.Metric{{Type: pb.MetricType_METRIC_TYPE_UNSPECIFIED, Value: 1}},
		})
		require.Error(t, err)
	})
}

func TestCreateMetric(t *testing.T) {
	tests := []struct {
		name string
		in   *pb.Metric
		want *table.Metric
	}{
		{"igp", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10}, table.NewMetric(table.IGPMetric, 10)},
		{"te", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_TE, Value: 20}, table.NewMetric(table.TEMetric, 20)},
		{"delay", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_DELAY, Value: 30}, table.NewMetric(table.DelayMetric, 30)},
		{"hopcount", &pb.Metric{Type: pb.MetricType_METRIC_TYPE_HOPCOUNT, Value: 1}, table.NewMetric(table.HopcountMetric, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createMetric(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("unspecified metric type is an error", func(t *testing.T) {
		_, err := createMetric(&pb.Metric{Type: pb.MetricType_METRIC_TYPE_UNSPECIFIED})
		require.Error(t, err)
	})
}
