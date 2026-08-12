// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package gobgp

import (
	"testing"

	api "github.com/osrg/gobgp/v4/api"
)

func testLsAddrPrefixV4(t *testing.T, prefix string) *api.LsAddrPrefix {
	t.Helper()
	return &api.LsAddrPrefix{
		Nlri: &api.LsAddrPrefix_LsNLRI{
			Nlri: &api.LsAddrPrefix_LsNLRI_PrefixV4{
				PrefixV4: &api.LsPrefixV4NLRI{
					LocalNode: &api.LsNodeDescriptor{
						Asn:         65000,
						IgpRouterId: "0000.0000.0001",
					},
					PrefixDescriptor: &api.LsPrefixDescriptor{
						IpReachability: []string{prefix},
					},
				},
			},
		},
	}
}

func TestGetLsPrefix_SidIndex(t *testing.T) {
	tests := []struct {
		name            string
		attr            *api.LsAttributePrefix
		wantSidIndex    uint32
		wantHasSidIndex bool
	}{
		{
			name:            "no Prefix-SID",
			attr:            &api.LsAttributePrefix{},
			wantSidIndex:    0,
			wantHasSidIndex: false,
		},
		{
			name:            "singular Prefix-SID",
			attr:            &api.LsAttributePrefix{SrPrefixSid: 3},
			wantSidIndex:    3,
			wantHasSidIndex: true,
		},
		{
			name: "Prefix-SID index 0 advertised for algorithm 0",
			attr: &api.LsAttributePrefix{
				SrPrefixSids: []*api.LsAttributePrefixSID{
					{Algorithm: 0, Sid: 0},
				},
			},
			wantSidIndex:    0,
			wantHasSidIndex: true,
		},
		{
			name: "Prefix-SID index 0 only for a non-zero algorithm",
			attr: &api.LsAttributePrefix{
				SrPrefixSids: []*api.LsAttributePrefixSID{
					{Algorithm: 128, Sid: 0},
				},
			},
			wantSidIndex:    0,
			wantHasSidIndex: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lsPrefix, err := getLsPrefix(testLsAddrPrefixV4(t, "10.0.0.1/32"), tt.attr)
			if err != nil {
				t.Fatalf("getLsPrefix() error = %v, want nil", err)
			}
			if lsPrefix.SidIndex != tt.wantSidIndex {
				t.Errorf("SidIndex = %d, want %d", lsPrefix.SidIndex, tt.wantSidIndex)
			}
			if lsPrefix.HasSidIndex != tt.wantHasSidIndex {
				t.Errorf("HasSidIndex = %v, want %v", lsPrefix.HasSidIndex, tt.wantHasSidIndex)
			}
		})
	}
}
