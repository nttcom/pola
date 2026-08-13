// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package gobgp

import (
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{
			name: "singular field kept alongside an algorithm 0 index of 0",
			attr: &api.LsAttributePrefix{
				SrPrefixSid: 0,
				SrPrefixSids: []*api.LsAttributePrefixSID{
					{Algorithm: 0, Sid: 0},
				},
			},
			wantSidIndex:    0,
			wantHasSidIndex: true,
		},
		{
			name: "singular field contradicts a list without algorithm 0",
			attr: &api.LsAttributePrefix{
				SrPrefixSid: 3,
				SrPrefixSids: []*api.LsAttributePrefixSID{
					{Algorithm: 128, Sid: 3},
				},
			},
			wantSidIndex:    0,
			wantHasSidIndex: false,
		},
		{
			name: "algorithm 0 entry after a Flex-Algo entry wins over the singular field",
			attr: &api.LsAttributePrefix{
				SrPrefixSid: 3,
				SrPrefixSids: []*api.LsAttributePrefixSID{
					{Algorithm: 128, Sid: 3},
					{Algorithm: 0, Sid: 16003},
				},
			},
			wantSidIndex:    16003,
			wantHasSidIndex: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lsPrefix, err := getLsPrefix(testLsAddrPrefixV4(t, "10.0.0.1/32"), tt.attr)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSidIndex, lsPrefix.SidIndex)
			assert.Equal(t, tt.wantHasSidIndex, lsPrefix.HasSidIndex)
		})
	}
}
