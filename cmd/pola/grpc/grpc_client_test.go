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

// The optional sid_index field carries presence, so index 0 must not be
// confused with an absent Prefix-SID.
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
			if err != nil {
				t.Fatalf("createLsPrefix() returned an error: %v", err)
			}
			if lsPrefix.SidIndex != tt.wantSidIndex {
				t.Errorf("SidIndex = %d, want %d", lsPrefix.SidIndex, tt.wantSidIndex)
			}
			if lsPrefix.HasSidIndex != tt.wantHasSidIndex {
				t.Errorf("HasSidIndex = %v, want %v", lsPrefix.HasSidIndex, tt.wantHasSidIndex)
			}
			if lsPrefix.HasPrefixSID() != tt.wantHasSidIndex {
				t.Errorf("HasPrefixSID() = %v, want %v", lsPrefix.HasPrefixSID(), tt.wantHasSidIndex)
			}
		})
	}
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

// fakeSessionListClient returns a fixed GetSessionListResponse.
type fakeSessionListClient struct {
	pb.PCEServiceClient
	resp *pb.GetSessionListResponse
}

func (f *fakeSessionListClient) GetSessionList(ctx context.Context, in *pb.GetSessionListRequest, opts ...grpc.CallOption) (*pb.GetSessionListResponse, error) {
	return f.resp, nil
}

func TestGetSessions_NoCapabilitiesIsEmptySlice(t *testing.T) {
	client := &fakeSessionListClient{resp: &pb.GetSessionListResponse{
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
