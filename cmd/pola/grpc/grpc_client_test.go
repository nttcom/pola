// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package grpc

import (
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/table"
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
