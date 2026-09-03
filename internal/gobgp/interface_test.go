// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package gobgp

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/table"
	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testRouterID1   = "0000.0000.0001"
	testRouterID2   = "0000.0000.0002"
	testBadIP       = "bad-ip"
	testSrv6EndXSID = "2001:db8::1:0"
	testSrv6SID     = "2001:db8:1::"
)

func testLsAddrPrefixV4(t *testing.T, prefix string) *api.LsAddrPrefix {
	t.Helper()
	return &api.LsAddrPrefix{
		Nlri: &api.LsAddrPrefix_LsNLRI{
			Nlri: &api.LsAddrPrefix_LsNLRI_PrefixV4{
				PrefixV4: &api.LsPrefixV4NLRI{
					LocalNode: &api.LsNodeDescriptor{
						Asn:         65000,
						IgpRouterId: testRouterID1,
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
	t.Parallel()

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
			t.Parallel()
			lsPrefix, err := getLsPrefix(testLsAddrPrefixV4(t, "10.0.0.1/32"), tt.attr)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSidIndex, lsPrefix.SidIndex)
			assert.Equal(t, tt.wantHasSidIndex, lsPrefix.HasSidIndex)
		})
	}
}

func TestGetLsPrefix_NLRITypesAndErrors(t *testing.T) {
	t.Parallel()

	localNodeDesc := &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1}

	t.Run("PrefixV6 NLRI", func(t *testing.T) {
		t.Parallel()
		nlri := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_PrefixV6{
					PrefixV6: &api.LsPrefixV6NLRI{
						LocalNode:        localNodeDesc,
						PrefixDescriptor: &api.LsPrefixDescriptor{IpReachability: []string{"2001:db8::/64"}},
					},
				},
			},
		}

		got, err := getLsPrefix(nlri, &api.LsAttributePrefix{SrPrefixSid: 100})
		require.NoError(t, err)

		want := table.NewLsPrefix(table.NewLsNode(65000, testRouterID1))
		want.Prefix = netip.MustParsePrefix("2001:db8::/64")
		want.SidIndex, want.HasSidIndex = 100, true
		assert.Equal(t, want, got)
	})

	t.Run("unsupported NLRI type", func(t *testing.T) {
		t.Parallel()
		nlri := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Node{Node: &api.LsNodeNLRI{}},
			},
		}

		_, err := getLsPrefix(nlri, &api.LsAttributePrefix{})
		assert.EqualError(t, err, "invalid LS prefix NLRI type")
	})

	t.Run("nil NLRI", func(t *testing.T) {
		t.Parallel()
		_, err := getLsPrefix(nil, &api.LsAttributePrefix{})
		require.EqualError(t, err, "LS Prefix NLRI is nil")
	})

	t.Run("nil NLRI field", func(t *testing.T) {
		t.Parallel()
		_, err := getLsPrefix(&api.LsAddrPrefix{}, &api.LsAttributePrefix{})
		require.EqualError(t, err, "LS Prefix NLRI is nil")
	})

	reachTests := []struct {
		name          string
		reach         []string
		wantErrSubstr string
	}{
		{"no reachability entries", nil, "invalid prefix length"},
		{"multiple reachability entries", []string{"10.0.0.0/24", "10.0.1.0/24"}, "invalid prefix length"},
		{"unparsable prefix", []string{"not-a-prefix"}, "failed to parse prefix"},
	}
	for _, tt := range reachTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nlri := &api.LsAddrPrefix{
				Nlri: &api.LsAddrPrefix_LsNLRI{
					Nlri: &api.LsAddrPrefix_LsNLRI_PrefixV4{
						PrefixV4: &api.LsPrefixV4NLRI{
							LocalNode:        localNodeDesc,
							PrefixDescriptor: &api.LsPrefixDescriptor{IpReachability: tt.reach},
						},
					},
				},
			}

			_, err := getLsPrefix(nlri, &api.LsAttributePrefix{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrSubstr)
		})
	}
}

func TestGetLsPrefixList(t *testing.T) {
	t.Parallel()

	attr := &api.LsAttributePrefix{SrPrefixSid: 100}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		nlris := []*api.NLRI{
			{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: testLsAddrPrefixV4(t, "10.0.0.1/32")}},
			{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: testLsAddrPrefixV4(t, "10.0.0.2/32")}},
		}

		got, err := getLsPrefixList(nlris, attr)
		require.NoError(t, err)
		require.Len(t, got, 2)
	})

	t.Run("propagates a per-prefix error", func(t *testing.T) {
		t.Parallel()
		nlris := []*api.NLRI{
			{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: testLsAddrPrefixV4(t, "not-a-prefix")}},
		}

		_, err := getLsPrefixList(nlris, attr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get LS Prefix")
	})

	t.Run("no NLRIs", func(t *testing.T) {
		t.Parallel()
		got, err := getLsPrefixList(nil, attr)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestFormatIsisAreaID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		area []byte
		want string
	}{
		{"empty area ID", nil, ""},
		{"single byte, no grouping boundary", []byte{0x0a}, "0a"},
		{"two bytes, exactly one group", []byte{0x12, 0x34}, "1234"},
		{"three bytes, short leading group", []byte{0x12, 0x34, 0x56}, "12.3456"},
		{"four bytes, one dot", []byte{0x49, 0x00, 0x00, 0x01}, "4900.0001"},
		{"eight bytes, three dots", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, "0102.0304.0506.0708"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, formatIsisAreaID(tt.area))
		})
	}
}

func TestGetLsNode(t *testing.T) {
	t.Parallel()

	nlri := &api.LsAddrPrefix{
		Nlri: &api.LsAddrPrefix_LsNLRI{
			Nlri: &api.LsAddrPrefix_LsNLRI_Node{
				Node: &api.LsNodeNLRI{
					LocalNode: &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1},
				},
			},
		},
	}

	t.Run("no SR Capabilities TLV", func(t *testing.T) {
		t.Parallel()
		attr := &api.LsAttributeNode{Name: "r1", IsisArea: []byte{0x49, 0x00}}

		got, err := getLsNode(nlri, attr)
		require.NoError(t, err)

		want := table.NewLsNode(65000, testRouterID1)
		want.Hostname = "r1"
		want.IsisAreaID = "4900"
		assert.Equal(t, want, got)
	})

	t.Run("one SR Capability Range TLV", func(t *testing.T) {
		t.Parallel()
		attr := &api.LsAttributeNode{
			Name:           "r1",
			SrCapabilities: &api.LsSrCapabilities{Ranges: []*api.LsSrRange{{Begin: 16000, End: 23999}}},
		}

		got, err := getLsNode(nlri, attr)
		require.NoError(t, err)

		want := table.NewLsNode(65000, testRouterID1)
		want.Hostname = "r1"
		want.SrgbBegin, want.SrgbEnd = 16000, 23999
		assert.Equal(t, want, got)
	})

	t.Run("SR Capabilities present with no Range TLV", func(t *testing.T) {
		t.Parallel()
		attr := &api.LsAttributeNode{SrCapabilities: &api.LsSrCapabilities{}}

		_, err := getLsNode(nlri, attr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 1 SR Capability TLV, got: 0")
	})

	t.Run("SR Capabilities with more than one Range TLV", func(t *testing.T) {
		t.Parallel()
		attr := &api.LsAttributeNode{
			SrCapabilities: &api.LsSrCapabilities{Ranges: []*api.LsSrRange{
				{Begin: 16000, End: 23999},
				{Begin: 24000, End: 25000},
			}},
		}

		_, err := getLsNode(nlri, attr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 1 SR Capability TLV, got: 2")
	})
}

func TestGetLsLink(t *testing.T) {
	t.Parallel()

	localDesc := &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1}
	remoteDesc := &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID2}
	expectedLocal := table.NewLsNode(65000, testRouterID1)
	expectedRemote := table.NewLsNode(65000, testRouterID2)

	newNLRI := func(desc *api.LsLinkDescriptor) *api.LsAddrPrefix {
		return &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Link{
					Link: &api.LsLinkNLRI{
						LocalNode:      localDesc,
						RemoteNode:     remoteDesc,
						LinkDescriptor: desc,
					},
				},
			},
		}
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			desc *api.LsLinkDescriptor
			attr *api.LsAttributeLink
			want *table.LsLink
		}{
			{
				name: "IPv4 addresses and IGP metric only",
				desc: &api.LsLinkDescriptor{InterfaceAddrIpv4: "10.0.0.1", NeighborAddrIpv4: "10.0.0.2"},
				attr: &api.LsAttributeLink{IgpMetric: 10},
				want: &table.LsLink{
					LocalNode:  expectedLocal,
					RemoteNode: expectedRemote,
					LocalIP:    netip.MustParseAddr("10.0.0.1"),
					RemoteIP:   netip.MustParseAddr("10.0.0.2"),
					Metrics:    []*table.Metric{table.NewMetric(table.IGPMetric, 10)},
				},
			},
			{
				name: "IPv6 addresses with TE and delay metrics",
				desc: &api.LsLinkDescriptor{InterfaceAddrIpv6: "2001:db8::1", NeighborAddrIpv6: "2001:db8::2"},
				attr: &api.LsAttributeLink{
					IgpMetric:               10,
					DefaultTeMetric:         20,
					UnidirectionalLinkDelay: 30,
					SrAdjacencySid:          12345,
				},
				want: &table.LsLink{
					LocalNode:  expectedLocal,
					RemoteNode: expectedRemote,
					LocalIP:    netip.MustParseAddr("2001:db8::1"),
					RemoteIP:   netip.MustParseAddr("2001:db8::2"),
					Metrics: []*table.Metric{
						table.NewMetric(table.IGPMetric, 10),
						table.NewMetric(table.TEMetric, 20),
						table.NewMetric(table.DelayMetric, 30),
					},
					AdjSid: 12345,
				},
			},
			{
				name: "no addresses and an SRv6 End.X SID (RFC 8986)",
				desc: &api.LsLinkDescriptor{},
				attr: &api.LsAttributeLink{
					IgpMetric: 5,
					Srv6EndXSid: &api.LsSrv6EndXSID{
						EndpointBehavior: uint32(table.BehaviorENDX),
						Sids:             []string{testSrv6EndXSID},
						Srv6SidStructure: &api.LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
					},
				},
				want: &table.LsLink{
					LocalNode:  expectedLocal,
					RemoteNode: expectedRemote,
					LocalIP:    netip.Addr{},
					RemoteIP:   netip.Addr{},
					Metrics:    []*table.Metric{table.NewMetric(table.IGPMetric, 5)},
					Srv6EndXSID: &table.Srv6EndXSID{
						EndpointBehavior: table.BehaviorENDX,
						Sids:             []string{testSrv6EndXSID},
						Srv6SIDStructure: table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
					},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				got, err := getLsLink(newNLRI(tt.desc), tt.attr)
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("address parse errors", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			desc    *api.LsLinkDescriptor
			wantErr string
		}{
			{"invalid local IPv4 address", &api.LsLinkDescriptor{InterfaceAddrIpv4: testBadIP}, "failed to parse local IPv4 address"},
			{"invalid local IPv6 address", &api.LsLinkDescriptor{InterfaceAddrIpv6: testBadIP}, "failed to parse local IPv6 address"},
			{"invalid remote IPv4 address", &api.LsLinkDescriptor{NeighborAddrIpv4: testBadIP}, "failed to parse remote IPv4 address"},
			{"invalid remote IPv6 address", &api.LsLinkDescriptor{NeighborAddrIpv6: testBadIP}, "failed to parse remote IPv6 address"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				_, err := getLsLink(newNLRI(tt.desc), &api.LsAttributeLink{})
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("invalid NLRI", func(t *testing.T) {
		t.Parallel()
		// Node NLRI where a Link NLRI is expected.
		wrongNLRI := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Node{
					Node: &api.LsNodeNLRI{},
				},
			},
		}

		tests := []struct {
			name string
			nlri *api.LsAddrPrefix
		}{
			{"nil NLRI", nil},
			{"wrong NLRI type", wrongNLRI},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				_, err := getLsLink(tt.nlri, &api.LsAttributeLink{})
				require.Error(t, err)
			})
		}
	})

	t.Run("SRv6 End.X SID conversion error propagates", func(t *testing.T) {
		t.Parallel()
		_, err := getLsLink(newNLRI(&api.LsLinkDescriptor{}), &api.LsAttributeLink{
			Srv6EndXSid: &api.LsSrv6EndXSID{EndpointBehavior: math.MaxUint16 + 1},
		})
		require.Error(t, err)
	})
}

func TestSrv6EndXSIDFromAPI(t *testing.T) {
	t.Parallel()

	validStructure := &api.LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := srv6EndXSIDFromAPI(&api.LsSrv6EndXSID{
			EndpointBehavior: uint32(table.BehaviorENDX),
			Sids:             []string{testSrv6EndXSID},
			Srv6SidStructure: validStructure,
		})
		require.NoError(t, err)
		assert.Equal(t, &table.Srv6EndXSID{
			EndpointBehavior: table.BehaviorENDX,
			Sids:             []string{testSrv6EndXSID},
			Srv6SIDStructure: table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
		}, got)
	})

	t.Run("endpoint behavior overflow", func(t *testing.T) {
		t.Parallel()
		_, err := srv6EndXSIDFromAPI(&api.LsSrv6EndXSID{
			EndpointBehavior: math.MaxUint16 + 1,
			Srv6SidStructure: validStructure,
		})
		require.Error(t, err)
	})

	t.Run("SID structure overflow propagates", func(t *testing.T) {
		t.Parallel()
		_, err := srv6EndXSIDFromAPI(&api.LsSrv6EndXSID{
			EndpointBehavior: uint32(table.BehaviorENDX),
			Srv6SidStructure: &api.LsSrv6SIDStructure{LocalBlock: math.MaxUint8 + 1},
		})
		require.Error(t, err)
	})
}

func TestSrv6SIDStructureFromAPI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    *api.LsSrv6SIDStructure
	}{
		{"LocalBlock overflow", &api.LsSrv6SIDStructure{LocalBlock: math.MaxUint8 + 1}},
		{"LocalNode overflow", &api.LsSrv6SIDStructure{LocalNode: math.MaxUint8 + 1}},
		{"LocalFunc overflow", &api.LsSrv6SIDStructure{LocalFunc: math.MaxUint8 + 1}},
		{"LocalArg overflow", &api.LsSrv6SIDStructure{LocalArg: math.MaxUint8 + 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := srv6SIDStructureFromAPI(tt.s)
			require.Error(t, err)
		})
	}
}

func TestGetLsSrv6SID(t *testing.T) {
	t.Parallel()

	attr := &api.LsAttributeSrv6SID{
		Srv6EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: uint32(table.BehaviorEND)},
		Srv6SidStructure:     &api.LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		nlri := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Srv6Sid{
					Srv6Sid: &api.LsSrv6SIDNLRI{
						LocalNode:          &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1},
						Srv6SidInformation: &api.LsSrv6SIDInformation{Sids: []string{testSrv6SID}},
						MultiTopoId:        &api.LsMultiTopologyIdentifier{MultiTopoIds: []uint32{0}},
					},
				},
			},
		}

		got, err := getLsSrv6SID(nlri, attr)
		require.NoError(t, err)

		want := table.NewLsSrv6SID(table.NewLsNode(65000, testRouterID1))
		want.Sids = []string{testSrv6SID}
		want.MultiTopoIDs = []uint32{0}
		want.SIDStructure = table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0}
		want.EndpointBehavior = table.EndpointBehavior{Behavior: table.BehaviorEND}
		assert.Equal(t, want, got)
	})

	t.Run("invalid NLRI", func(t *testing.T) {
		t.Parallel()
		wrongNLRI := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Node{
					Node: &api.LsNodeNLRI{},
				},
			},
		}

		tests := []struct {
			name string
			nlri *api.LsAddrPrefix
		}{
			{"nil NLRI", nil},
			{"wrong NLRI type", wrongNLRI},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				_, err := getLsSrv6SID(tt.nlri, attr)
				require.Error(t, err)
			})
		}
	})

	t.Run("attribute conversion errors", func(t *testing.T) {
		t.Parallel()
		nlri := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Srv6Sid{
					Srv6Sid: &api.LsSrv6SIDNLRI{
						LocalNode:          &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1},
						Srv6SidInformation: &api.LsSrv6SIDInformation{Sids: []string{testSrv6SID}},
						MultiTopoId:        &api.LsMultiTopologyIdentifier{},
					},
				},
			},
		}

		tests := []struct {
			name string
			attr *api.LsAttributeSrv6SID
		}{
			{
				name: "SID structure overflow",
				attr: &api.LsAttributeSrv6SID{
					Srv6EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: uint32(table.BehaviorEND)},
					Srv6SidStructure:     &api.LsSrv6SIDStructure{LocalBlock: math.MaxUint8 + 1},
				},
			},
			{
				name: "endpoint behavior overflow",
				attr: &api.LsAttributeSrv6SID{
					Srv6EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: math.MaxUint16 + 1},
					Srv6SidStructure:     &api.LsSrv6SIDStructure{},
				},
			},
			{
				name: "flags overflow",
				attr: &api.LsAttributeSrv6SID{
					Srv6EndpointBehavior: &api.LsSrv6EndpointBehavior{Flags: math.MaxUint8 + 1},
					Srv6SidStructure:     &api.LsSrv6SIDStructure{},
				},
			},
			{
				name: "algorithm overflow",
				attr: &api.LsAttributeSrv6SID{
					Srv6EndpointBehavior: &api.LsSrv6EndpointBehavior{Algorithm: math.MaxUint8 + 1},
					Srv6SidStructure:     &api.LsSrv6SIDStructure{},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				_, err := getLsSrv6SID(nlri, tt.attr)
				require.Error(t, err)
			})
		}
	})
}

func TestGetLsSrv6SIDList(t *testing.T) {
	t.Parallel()

	newNLRI := func(routerID string) *api.NLRI {
		return &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Srv6Sid{
					Srv6Sid: &api.LsSrv6SIDNLRI{
						LocalNode:          &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: routerID},
						Srv6SidInformation: &api.LsSrv6SIDInformation{},
						MultiTopoId:        &api.LsMultiTopologyIdentifier{},
					},
				},
			},
		}}}
	}
	attr := &api.LsAttributeSrv6SID{
		Srv6EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: uint32(table.BehaviorEND)},
		Srv6SidStructure:     &api.LsSrv6SIDStructure{},
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := getLsSrv6SIDList([]*api.NLRI{newNLRI(testRouterID1), newNLRI(testRouterID2)}, attr)
		require.NoError(t, err)
		require.Len(t, got, 2)
	})

	t.Run("no NLRIs", func(t *testing.T) {
		t.Parallel()
		got, err := getLsSrv6SIDList(nil, attr)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("non-LsAddrPrefix NLRI", func(t *testing.T) {
		t.Parallel()
		nlris := []*api.NLRI{{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{}}}}
		_, err := getLsSrv6SIDList(nlris, attr)
		require.Error(t, err)
	})
}

func TestMpReachNlris_MissingMpReach(t *testing.T) {
	t.Parallel()

	lsAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{Srv6Sid: &api.LsAttributeSrv6SID{}}}
	path := &api.Path{Pattrs: []*api.Attribute{{Attr: lsAttr}}}

	_, err := mpReachNlris(path)
	assert.EqualError(t, err, "MP-REACH NLRI Attribute is nil")
}

func TestConvertSrv6SID_InvalidNLRIInMpReach(t *testing.T) {
	t.Parallel()

	lsAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{Srv6Sid: &api.LsAttributeSrv6SID{}}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{}}}}

	_, err := convertSrv6SID(lsAttr, nlris)
	assert.Error(t, err)
}

func TestFindLsAttribute(t *testing.T) {
	t.Parallel()

	t.Run("found among other attributes", func(t *testing.T) {
		t.Parallel()
		lsAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{}}
		path := &api.Path{Pattrs: []*api.Attribute{
			{Attr: &api.Attribute_Origin{}},
			{Attr: lsAttr},
		}}

		assert.Same(t, lsAttr, findLsAttribute(path))
	})

	t.Run("not present", func(t *testing.T) {
		t.Parallel()
		path := &api.Path{Pattrs: []*api.Attribute{{Attr: &api.Attribute_Origin{}}}}
		assert.Nil(t, findLsAttribute(path))
	})
}

func TestFindMpReach(t *testing.T) {
	t.Parallel()

	t.Run("found among other attributes", func(t *testing.T) {
		t.Parallel()
		mpReach := &api.MpReachNLRIAttribute{}
		path := &api.Path{Pattrs: []*api.Attribute{
			{Attr: &api.Attribute_Origin{}},
			{Attr: &api.Attribute_MpReach{MpReach: mpReach}},
		}}

		assert.Same(t, mpReach, findMpReach(path))
	})

	t.Run("not present", func(t *testing.T) {
		t.Parallel()
		path := &api.Path{Pattrs: []*api.Attribute{{Attr: &api.Attribute_Origin{}}}}
		assert.Nil(t, findMpReach(path))
	})
}

func TestConvertToTEDElem(t *testing.T) {
	t.Parallel()

	nodeNLRI := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_NODE,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Node{
			Node: &api.LsNodeNLRI{LocalNode: &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1}},
		}},
	}
	linkNLRI := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_LINK,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Link{
			Link: &api.LsLinkNLRI{
				LocalNode:      &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1},
				RemoteNode:     &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID2},
				LinkDescriptor: &api.LsLinkDescriptor{},
			},
		}},
	}
	linkNLRIBadAddr := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_LINK,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Link{
			Link: &api.LsLinkNLRI{
				LocalNode:      &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1},
				RemoteNode:     &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID2},
				LinkDescriptor: &api.LsLinkDescriptor{InterfaceAddrIpv4: testBadIP},
			},
		}},
	}
	prefixNLRI := testLsAddrPrefixV4(t, "10.0.0.1/32")
	prefixNLRI.Type = api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V4
	prefixNLRIBadPrefix := testLsAddrPrefixV4(t, "not-a-prefix")
	prefixNLRIBadPrefix.Type = api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V4
	srv6NLRI := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_SRV6_SID,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Srv6Sid{
			Srv6Sid: &api.LsSrv6SIDNLRI{
				LocalNode:          &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: testRouterID1},
				Srv6SidInformation: &api.LsSrv6SIDInformation{Sids: []string{testSrv6SID}},
				MultiTopoId:        &api.LsMultiTopologyIdentifier{},
			},
		}},
	}

	lsNodeAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{Node: &api.LsAttributeNode{Name: "r1"}}}
	lsNodeAttrBadSR := &api.Attribute_Ls{Ls: &api.LsAttribute{Node: &api.LsAttributeNode{
		SrCapabilities: &api.LsSrCapabilities{Ranges: []*api.LsSrRange{{Begin: 16000, End: 23999}, {Begin: 24000, End: 25000}}},
	}}}
	lsLinkAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{Link: &api.LsAttributeLink{IgpMetric: 10}}}
	lsPrefixAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{Prefix: &api.LsAttributePrefix{SrPrefixSid: 100}}}
	lsSrv6Attr := &api.Attribute_Ls{Ls: &api.LsAttribute{Srv6Sid: &api.LsAttributeSrv6SID{}}}
	emptyLsAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{}}

	mpReachFor := func(nlri *api.LsAddrPrefix) *api.Attribute {
		return &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: &api.MpReachNLRIAttribute{
			Nlris: []*api.NLRI{{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: nlri}}},
		}}}
	}

	tests := []struct {
		name          string
		dst           *api.Destination
		wantErrSubstr string
		wantLen       int
	}{
		{
			name:          "zero paths",
			dst:           &api.Destination{Paths: nil},
			wantErrSubstr: "invalid path length",
		},
		{
			name:          "more than one path",
			dst:           &api.Destination{Paths: []*api.Path{{}, {}}},
			wantErrSubstr: "invalid path length",
		},
		{
			name:          "nil NLRI",
			dst:           &api.Destination{Paths: []*api.Path{{Nlri: nil}}},
			wantErrSubstr: "NLRI is nil",
		},
		{
			name:          "nil LSAddrPrefix",
			dst:           &api.Destination{Paths: []*api.Path{{Nlri: &api.NLRI{}}}},
			wantErrSubstr: "LSAddrPrefix is nil",
		},
		{
			name: "no BGP-LS attribute is silently ignored",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri: &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: nodeNLRI}},
			}}},
			wantLen: 0,
		},
		{
			name: "Node NLRI",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: nodeNLRI}},
				Pattrs: []*api.Attribute{{Attr: lsNodeAttr}},
			}}},
			wantLen: 1,
		},
		{
			name: "Node NLRI with nil Node attribute",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: nodeNLRI}},
				Pattrs: []*api.Attribute{{Attr: emptyLsAttr}},
			}}},
			wantErrSubstr: "LS Node Attribute is nil",
		},
		{
			name: "Node NLRI wraps a getLsNode error",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: nodeNLRI}},
				Pattrs: []*api.Attribute{{Attr: lsNodeAttrBadSR}},
			}}},
			wantErrSubstr: "failed to process LS Node NLRI",
		},
		{
			name: "Link NLRI",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: linkNLRI}},
				Pattrs: []*api.Attribute{{Attr: lsLinkAttr}},
			}}},
			wantLen: 1,
		},
		{
			name: "Link NLRI with nil Link attribute",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: linkNLRI}},
				Pattrs: []*api.Attribute{{Attr: emptyLsAttr}},
			}}},
			wantErrSubstr: "LS Link Attribute is nil",
		},
		{
			name: "Link NLRI wraps a getLsLink error",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: linkNLRIBadAddr}},
				Pattrs: []*api.Attribute{{Attr: lsLinkAttr}},
			}}},
			wantErrSubstr: "failed to process LS Link NLRI",
		},
		{
			name: "Prefix V4 NLRI",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: prefixNLRI}},
				Pattrs: []*api.Attribute{{Attr: lsPrefixAttr}, mpReachFor(prefixNLRI)},
			}}},
			wantLen: 1,
		},
		{
			name: "Prefix NLRI with nil Prefix attribute",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: prefixNLRI}},
				Pattrs: []*api.Attribute{{Attr: emptyLsAttr}, mpReachFor(prefixNLRI)},
			}}},
			wantErrSubstr: "LS Prefix Attribute is nil",
		},
		{
			name: "Prefix NLRI without MP_REACH_NLRI",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: prefixNLRI}},
				Pattrs: []*api.Attribute{{Attr: lsPrefixAttr}},
			}}},
			wantErrSubstr: "MP-REACH NLRI Attribute is nil",
		},
		{
			name: "Prefix NLRI wraps a getLsPrefixList error",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: prefixNLRIBadPrefix}},
				Pattrs: []*api.Attribute{{Attr: lsPrefixAttr}, mpReachFor(prefixNLRIBadPrefix)},
			}}},
			wantErrSubstr: "failed to process LS Prefix NLRI",
		},
		{
			name: "SRv6 SID NLRI",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: srv6NLRI}},
				Pattrs: []*api.Attribute{{Attr: lsSrv6Attr}, mpReachFor(srv6NLRI)},
			}}},
			wantLen: 1,
		},
		{
			name: "SRv6 SID NLRI with nil Srv6Sid attribute",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: srv6NLRI}},
				Pattrs: []*api.Attribute{{Attr: emptyLsAttr}, mpReachFor(srv6NLRI)},
			}}},
			wantErrSubstr: "LS SRv6 SID Attribute is nil",
		},
		{
			name: "SRv6 SID NLRI without MP_REACH_NLRI",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: srv6NLRI}},
				Pattrs: []*api.Attribute{{Attr: lsSrv6Attr}},
			}}},
			wantErrSubstr: "MP-REACH NLRI Attribute is nil",
		},
		{
			name: "unsupported LS NLRI type",
			dst: &api.Destination{Paths: []*api.Path{{
				Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{Nlri: &api.LsAddrPrefix_LsNLRI{}}}},
				Pattrs: []*api.Attribute{{Attr: emptyLsAttr}},
			}}},
			wantErrSubstr: "invalid LS NLRI type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ConvertToTEDElem(tt.dst)
			if tt.wantErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, tt.wantLen)
		})
	}
}

func TestNewWatchRequest(t *testing.T) {
	t.Parallel()

	want := &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{Type: api.WatchEventRequest_Table_Filter_TYPE_ADJIN, Init: false},
			},
		},
	}

	assert.Equal(t, want, newWatchRequest())
}

func TestNewGoBGPClient(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		cc, client, err := newGoBGPClient("127.0.0.1", "50051")
		require.NoError(t, err)
		require.NotNil(t, cc)
		require.NotNil(t, client)
		assert.NoError(t, cc.Close())
	})

	t.Run("unparsable target", func(t *testing.T) {
		t.Parallel()
		cc, client, err := newGoBGPClient("\x00", "50051")
		require.Error(t, err)
		assert.Nil(t, cc)
		assert.Nil(t, client)
	})
}

// fakeListPathStream implements grpc.ServerStreamingClient[api.ListPathResponse]
// by embedding a nil grpc.ClientStream: only Recv is exercised by GetBGPlsNLRIs.
type fakeListPathStream struct {
	grpc.ClientStream
	responses []*api.ListPathResponse
	idx       int
	err       error
}

func (s *fakeListPathStream) Recv() (*api.ListPathResponse, error) {
	if s.idx < len(s.responses) {
		r := s.responses[s.idx]
		s.idx++
		return r, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	return nil, io.EOF
}

type fakeGoBGPClient struct {
	api.GoBgpServiceClient
	listPathResp    []*api.ListPathResponse
	listPathErr     error
	recvErr         error
	lastListPathReq *api.ListPathRequest
	lastCtx         context.Context

	// watchEventErr, when set, is returned by every WatchEvent call.
	watchEventErr   error
	watchEventCalls atomic.Int32
}

func (f *fakeGoBGPClient) ListPath(ctx context.Context, in *api.ListPathRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[api.ListPathResponse], error) {
	f.lastCtx = ctx
	f.lastListPathReq = in
	if f.listPathErr != nil {
		return nil, f.listPathErr
	}
	return &fakeListPathStream{responses: f.listPathResp, err: f.recvErr}, nil
}

func (f *fakeGoBGPClient) WatchEvent(_ context.Context, _ *api.WatchEventRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[api.WatchEventResponse], error) {
	f.watchEventCalls.Add(1)
	return nil, f.watchEventErr
}

func testNodeDestination(t *testing.T, asn uint32, routerID, hostname string) *api.Destination {
	t.Helper()
	nlri := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_NODE,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Node{
			Node: &api.LsNodeNLRI{LocalNode: &api.LsNodeDescriptor{Asn: asn, IgpRouterId: routerID}},
		}},
	}
	return &api.Destination{
		Paths: []*api.Path{{
			Nlri:   &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: nlri}},
			Pattrs: []*api.Attribute{{Attr: &api.Attribute_Ls{Ls: &api.LsAttribute{Node: &api.LsAttributeNode{Name: hostname}}}}},
		}},
	}
}

func TestGetBGPlsNLRIs(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		client := &fakeGoBGPClient{listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
			{Destination: testNodeDestination(t, 65000, testRouterID2, "r2")},
		}}
		ctx := context.Background()

		got, err := GetBGPlsNLRIs(ctx, client)
		require.NoError(t, err)
		require.Len(t, got, 2)

		wantReq := &api.ListPathRequest{
			TableType: api.TableType_TABLE_TYPE_GLOBAL,
			Family:    &api.Family{Afi: api.Family_AFI_LS, Safi: api.Family_SAFI_LS},
			SortType:  api.ListPathRequest_SORT_TYPE_PREFIX,
		}
		assert.Equal(t, wantReq, client.lastListPathReq)
		assert.Equal(t, ctx, client.lastCtx) // the caller's context reaches the RPC
	})

	t.Run("no destinations", func(t *testing.T) {
		t.Parallel()
		got, err := GetBGPlsNLRIs(context.Background(), &fakeGoBGPClient{})
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("ListPath call fails", func(t *testing.T) {
		t.Parallel()
		client := &fakeGoBGPClient{listPathErr: errors.New("connection refused")}

		_, err := GetBGPlsNLRIs(context.Background(), client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve paths from gRPC server")
	})

	t.Run("stream receive fails", func(t *testing.T) {
		t.Parallel()
		client := &fakeGoBGPClient{recvErr: errors.New("stream broken")}

		_, err := GetBGPlsNLRIs(context.Background(), client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error receiving stream data")
	})

	t.Run("conversion error propagates", func(t *testing.T) {
		t.Parallel()
		client := &fakeGoBGPClient{listPathResp: []*api.ListPathResponse{
			{Destination: &api.Destination{Paths: nil}},
		}}

		_, err := GetBGPlsNLRIs(context.Background(), client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to convert path to TED element")
	})
}

func TestWaitForRetry(t *testing.T) {
	t.Parallel()

	t.Run("waits for the interval and reports true", func(t *testing.T) {
		t.Parallel()
		assert.True(t, waitForRetry(context.Background(), time.Millisecond))
	})

	t.Run("reports false without waiting for the interval when the context is done", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		done := make(chan bool, 1)
		go func() { done <- waitForRetry(ctx, time.Hour) }()

		select {
		case got := <-done:
			assert.False(t, got)
		case <-time.After(time.Second):
			t.Fatal("waitForRetry did not return after the context was canceled")
		}
	})
}

func TestEstablishWatchStream_RetriesThenGivesUpOnContextCancel(t *testing.T) {
	t.Parallel()

	client := &fakeGoBGPClient{watchEventErr: errors.New("watch unavailable")}
	ctx, cancel := context.WithCancel(context.Background())

	type result struct {
		stream grpc.ServerStreamingClient[api.WatchEventResponse]
		ok     bool
	}
	done := make(chan result, 1)
	go func() {
		stream, ok := establishWatchStream(ctx, client, newWatchRequest(), 5*time.Millisecond, logger.NewNop())
		done <- result{stream, ok}
	}()

	// Let a few retries happen before giving up via cancellation.
	require.Eventually(t, func() bool {
		return client.watchEventCalls.Load() >= 2
	}, time.Second, time.Millisecond)
	cancel()

	select {
	case r := <-done:
		assert.False(t, r.ok)
		assert.Nil(t, r.stream)
	case <-time.After(time.Second):
		t.Fatal("establishWatchStream did not return after the context was canceled")
	}
}

func TestInitialSync(t *testing.T) {
	t.Parallel()

	t.Run("success delivers the initial TED", func(t *testing.T) {
		t.Parallel()
		client := &fakeGoBGPClient{listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		}}
		tedChan := make(chan []table.TEDElem, 1)

		initialSync(context.Background(), client, tedChan, logger.NewNop())

		require.Len(t, tedChan, 1)
		assert.Len(t, <-tedChan, 1)
	})

	t.Run("logs and skips delivery on failure", func(t *testing.T) {
		t.Parallel()
		client := &fakeGoBGPClient{listPathErr: errors.New("connection refused")}
		lg, logs := logger.NewRecorder(logger.LevelError)
		tedChan := make(chan []table.TEDElem, 1)

		initialSync(context.Background(), client, tedChan, lg)

		assert.Empty(t, tedChan)
		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "failed to get initial TED info", logs.All()[0].Message)
	})

	t.Run("returns without blocking when the context ends before delivery", func(t *testing.T) {
		t.Parallel()
		client := &fakeGoBGPClient{listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		tedChan := make(chan []table.TEDElem) // unbuffered with no receiver

		done := make(chan struct{})
		go func() {
			initialSync(ctx, client, tedChan, logger.NewNop())
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("initialSync blocked instead of returning when the context was already done")
		}
	})
}

func TestReconnectWatchStream_GivesUpOnContextCancel(t *testing.T) {
	t.Parallel()

	client := &fakeGoBGPClient{watchEventErr: errors.New("watch unavailable")}
	ctx, cancel := context.WithCancel(context.Background())
	d := NewDebouncer(time.Hour)
	fetch := func() ([]table.TEDElem, error) { return nil, nil }
	deliver := func([]table.TEDElem) {}

	type result struct {
		stream grpc.ServerStreamingClient[api.WatchEventResponse]
		ok     bool
	}
	done := make(chan result, 1)
	go func() {
		stream, ok := reconnectWatchStream(ctx, client, newWatchRequest(), 5*time.Millisecond, logger.NewNop(), d, fetch, deliver)
		done <- result{stream, ok}
	}()

	// Let a few retries happen before giving up via cancellation.
	require.Eventually(t, func() bool {
		return client.watchEventCalls.Load() >= 2
	}, time.Second, time.Millisecond)
	cancel()

	select {
	case r := <-done:
		assert.False(t, r.ok)
		assert.Nil(t, r.stream)
	case <-time.After(time.Second):
		t.Fatal("reconnectWatchStream did not return after the context was canceled")
	}
}

func TestDebouncerTrigger(t *testing.T) {
	t.Parallel()

	t.Run("fetches once after the cooldown and delivers", testDebouncerTriggerFetchesOnceAfterCooldown)
	t.Run("collapses triggers within the cooldown window into one fetch", testDebouncerTriggerCollapsesTriggersWithinCooldown)
	t.Run("stops without fetching when the context is canceled first", testDebouncerTriggerStopsWithoutFetchingOnCancelFirst)
	t.Run("logs and skips delivery when the fetch fails", testDebouncerTriggerLogsAndSkipsOnFetchFailure)
	t.Run("skips delivery when the context ends during the fetch", testDebouncerTriggerSkipsDeliveryOnContextEndDuringFetch)
	t.Run("handles a trigger during delivery", testDebouncerTriggerHandlesTriggerDuringDelivery)
	t.Run("retries after a fetch failure when a trigger arrived during the fetch", testDebouncerTriggerRetriesAfterFetchFailure)
	t.Run("keeps looping when a trigger arrives while the context ends during a successful fetch", testDebouncerTriggerKeepsLoopingOnContextEndDuringSuccessfulFetch)
	t.Run("keeps looping when a trigger arrives while the context ends during the cooldown wait", testDebouncerTriggerKeepsLoopingOnContextEndDuringCooldownWait)
	t.Run("does not lose the last trigger when the worker completes", testDebouncerTriggerDoesNotLoseLastTrigger)
	t.Run("releases the worker lock if fetch panics", testDebouncerRunReleasesLockOnPanic)
}

func testDebouncerTriggerFetchesOnceAfterCooldown(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(20 * time.Millisecond)

	want := []table.TEDElem{table.NewLsNode(1, "r1")}
	var fetchCount atomic.Int32
	fetch := func() ([]table.TEDElem, error) {
		fetchCount.Add(1)
		return want, nil
	}
	delivered := make(chan []table.TEDElem, 1)

	d.Trigger(t.Context(), fetch, func(elems []table.TEDElem) { delivered <- elems }, logger.NewNop())

	select {
	case got := <-delivered:
		assert.Equal(t, want, got)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delivery")
	}
	assert.EqualValues(t, 1, fetchCount.Load())
}

func testDebouncerTriggerCollapsesTriggersWithinCooldown(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(50 * time.Millisecond)
	ctx := t.Context()

	var fetchCount atomic.Int32
	fetch := func() ([]table.TEDElem, error) {
		fetchCount.Add(1)
		return nil, nil
	}
	delivered := make(chan []table.TEDElem, 1)
	deliver := func(elems []table.TEDElem) { delivered <- elems }
	lg := logger.NewNop()

	d.Trigger(ctx, fetch, deliver, lg)
	time.Sleep(10 * time.Millisecond)
	d.Trigger(ctx, fetch, deliver, lg)

	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delivery")
	}
	assert.EqualValues(t, 1, fetchCount.Load())
}

func testDebouncerTriggerStopsWithoutFetchingOnCancelFirst(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(time.Hour)
	ctx, cancel := context.WithCancel(t.Context())

	var fetchCalled atomic.Int32
	fetch := func() ([]table.TEDElem, error) {
		fetchCalled.Store(1)
		return nil, nil
	}
	deliver := func([]table.TEDElem) { t.Fatal("deliver should not be called") }

	d.Trigger(ctx, fetch, deliver, logger.NewNop())
	cancel()

	require.Eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.active
	}, time.Second, time.Millisecond)
	assert.EqualValues(t, 0, fetchCalled.Load())
}

func testDebouncerTriggerLogsAndSkipsOnFetchFailure(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(10 * time.Millisecond)

	lg, logs := logger.NewRecorder(logger.LevelError)
	fetch := func() ([]table.TEDElem, error) { return nil, errors.New("fetch failed") }
	deliver := func([]table.TEDElem) { t.Fatal("deliver should not be called") }

	d.Trigger(t.Context(), fetch, deliver, lg)

	require.Eventually(t, func() bool { return logs.Len() > 0 }, time.Second, time.Millisecond)
	assert.Equal(t, "failed to get TED info", logs.All()[0].Message)
}

func testDebouncerTriggerSkipsDeliveryOnContextEndDuringFetch(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(10 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	lg, logs := logger.NewRecorder(logger.LevelDebug)
	fetch := func() ([]table.TEDElem, error) {
		cancel() // simulate the context ending while the fetch is in flight
		return []table.TEDElem{table.NewLsNode(1, "r1")}, nil
	}
	deliver := func([]table.TEDElem) { t.Fatal("deliver should not be called") }

	d.Trigger(ctx, fetch, deliver, lg)

	require.Eventually(t, func() bool { return logs.Len() > 0 }, time.Second, time.Millisecond)
	assert.Equal(t, "deliver aborted due to context cancel", logs.All()[0].Message)
}

func testDebouncerTriggerHandlesTriggerDuringDelivery(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(5 * time.Millisecond)
	ctx := t.Context()

	var fetchCount atomic.Int32
	fetch := func() ([]table.TEDElem, error) {
		fetchCount.Add(1)
		return nil, nil
	}

	var firstDeliver atomic.Bool
	firstDeliver.Store(true)
	deliverStarted := make(chan struct{})
	releaseDeliver := make(chan struct{})
	delivered := make(chan struct{}, 2)
	deliver := func([]table.TEDElem) {
		if firstDeliver.CompareAndSwap(true, false) {
			close(deliverStarted)
			<-releaseDeliver
		}
		delivered <- struct{}{}
	}
	lg := logger.NewNop()

	d.Trigger(ctx, fetch, deliver, lg)

	<-deliverStarted
	d.Trigger(ctx, fetch, deliver, lg)
	close(releaseDeliver)

	for range 2 {
		select {
		case <-delivered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for both delivery cycles")
		}
	}

	require.Eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.active
	}, time.Second, time.Millisecond)
	assert.EqualValues(t, 2, fetchCount.Load())
}

func testDebouncerTriggerRetriesAfterFetchFailure(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(5 * time.Millisecond)
	ctx := t.Context()

	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	var fetchCount atomic.Int32
	fetch := func() ([]table.TEDElem, error) {
		if fetchCount.Add(1) == 1 {
			close(fetchStarted)
			<-releaseFetch
			return nil, errors.New("boom")
		}
		return []table.TEDElem{table.NewLsNode(1, "r1")}, nil
	}
	delivered := make(chan []table.TEDElem, 1)
	deliver := func(elems []table.TEDElem) { delivered <- elems }
	lg, logs := logger.NewRecorder(logger.LevelError)

	d.Trigger(ctx, fetch, deliver, lg)
	<-fetchStarted
	d.Trigger(ctx, fetch, deliver, lg) // arrives while the failing fetch is in flight
	close(releaseFetch)

	select {
	case got := <-delivered:
		assert.Len(t, got, 1)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the retried fetch to deliver")
	}
	require.Eventually(t, func() bool { return logs.Len() > 0 }, time.Second, time.Millisecond)
	assert.Equal(t, "failed to get TED info", logs.All()[0].Message)
}

func testDebouncerTriggerKeepsLoopingOnContextEndDuringSuccessfulFetch(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(5 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	var fetchCount atomic.Int32
	fetch := func() ([]table.TEDElem, error) {
		if fetchCount.Add(1) == 1 {
			cancel()
			d.Trigger(ctx, nil, nil, nil) // arrives before the context-cancel check runs
		}
		return []table.TEDElem{table.NewLsNode(1, "r1")}, nil
	}
	deliver := func([]table.TEDElem) { t.Fatal("deliver should not be called") }

	d.Trigger(ctx, fetch, deliver, logger.NewNop())

	require.Eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.active
	}, time.Second, time.Millisecond)
	assert.EqualValues(t, 1, fetchCount.Load())
}

func testDebouncerTriggerKeepsLoopingOnContextEndDuringCooldownWait(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var fetchCalled atomic.Bool
	fetch := func() ([]table.TEDElem, error) {
		fetchCalled.Store(true)
		return nil, nil
	}
	deliver := func([]table.TEDElem) {}
	lg := logger.NewNop()

	// Set a pending cooldown deterministically to exercise the ctx.Done() path.
	d.mu.Lock()
	d.active = true
	d.last = time.Now().Add(50 * time.Millisecond)
	d.mu.Unlock()

	go d.run(ctx, fetch, deliver, lg)

	require.Eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return !d.active
	}, time.Second, time.Millisecond)

	assert.False(t, fetchCalled.Load(), "fetch should not run once the context is canceled")
}

func testDebouncerTriggerDoesNotLoseLastTrigger(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(time.Millisecond)
	ctx := t.Context()

	var generation atomic.Int64
	var observedGen atomic.Int64
	fetch := func() ([]table.TEDElem, error) {
		observedGen.Store(generation.Load())
		return nil, nil
	}
	deliver := func([]table.TEDElem) {}
	lg := logger.NewNop()

	const rounds = 500
	for i := int64(1); i <= rounds; i++ {
		generation.Store(i)
		d.Trigger(ctx, fetch, deliver, lg)
	}

	require.Eventually(t, func() bool {
		return observedGen.Load() == rounds
	}, 5*time.Second, time.Millisecond,
		"the last trigger before the worker went idle was lost")
}

func testDebouncerRunReleasesLockOnPanic(t *testing.T) {
	t.Parallel()

	d := NewDebouncer(time.Millisecond)
	d.active = true

	panicked := func() (recovered bool) {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
			}
		}()
		fetch := func() ([]table.TEDElem, error) { panic("boom") }
		d.run(context.Background(), fetch, func([]table.TEDElem) {}, logger.NewNop())
		return false
	}()
	require.True(t, panicked, "expected run to panic")

	d.mu.Lock()
	active := d.active
	d.mu.Unlock()
	require.False(t, active, "expected active to be reset to false after panic")
}

// testGoBGPServer implements api.GoBgpServiceServer for MonitorBGPLsEvents integration tests.
type testGoBGPServer struct {
	api.UnimplementedGoBgpServiceServer
	listPathResp       []*api.ListPathResponse
	listPathResps      [][]*api.ListPathResponse
	watchEvents        []*api.WatchEventResponse
	watchEventsPerCall [][]*api.WatchEventResponse
	watchEventHold     time.Duration
	watchEventHolds    []time.Duration
	watchEventErrs     []error
	listPathCalls      atomic.Int32
	watchEventCalls    atomic.Int32
}

func (s *testGoBGPServer) ListPath(_ *api.ListPathRequest, stream grpc.ServerStreamingServer[api.ListPathResponse]) error {
	call := int(s.listPathCalls.Add(1)) - 1
	resp := s.listPathResp
	if s.listPathResps != nil {
		resp = s.listPathResps[min(call, len(s.listPathResps)-1)]
	}
	for _, r := range resp {
		if err := stream.Send(r); err != nil {
			return err
		}
	}
	return nil
}

func (s *testGoBGPServer) WatchEvent(_ *api.WatchEventRequest, stream grpc.ServerStreamingServer[api.WatchEventResponse]) error {
	call := int(s.watchEventCalls.Add(1)) - 1
	if call < len(s.watchEventErrs) && s.watchEventErrs[call] != nil {
		return s.watchEventErrs[call]
	}
	events := s.watchEvents
	if s.watchEventsPerCall != nil {
		events = s.watchEventsPerCall[min(call, len(s.watchEventsPerCall)-1)]
	}
	for _, e := range events {
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	hold := s.watchEventHold
	if s.watchEventHolds != nil {
		hold = s.watchEventHolds[min(call, len(s.watchEventHolds)-1)]
	}
	time.Sleep(hold)
	return nil
}

// startTestGoBGPServer serves server on a loopback port and returns its host and port.
func startTestGoBGPServer(t *testing.T, server *testGoBGPServer) (host, port string) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	api.RegisterGoBgpServiceServer(srv, server)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	t.Cleanup(srv.Stop)

	host, port, err = net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)
	return host, port
}

func TestMonitorBGPLsEvents(t *testing.T) {
	t.Parallel()

	t.Run("returns immediately when the gRPC client cannot be created", testMonitorBGPLsEventsUnusableAddress)
	t.Run("reconnects and keeps monitoring after the watch stream ends", testMonitorBGPLsEventsReconnectsAfterStreamEnd)
	t.Run("returns when the caller's context is canceled", testMonitorBGPLsEventsContextCanceled)
	t.Run("returns immediately when the context is already canceled", testMonitorBGPLsEventsAlreadyCanceledContext)
	t.Run("triggers a debounced fetch and delivers the refreshed TED", testMonitorBGPLsEventsDebouncedFetch)
	t.Run("re-establishes the watch stream after a receive error", testMonitorBGPLsEventsReestablishesStream)
	t.Run("triggers a forced resync after reconnecting", testMonitorBGPLsEventsResyncsAfterReconnect)
}

func testMonitorBGPLsEventsAlreadyCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tedChan := make(chan []table.TEDElem, 1)
	done := make(chan struct{})

	go func() {
		MonitorBGPLsEvents(ctx, "127.0.0.1", "50051", tedChan, logger.NewNop())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("MonitorBGPLsEvents did not return immediately for an already-canceled context")
	}
}

func testMonitorBGPLsEventsUnusableAddress(t *testing.T) {
	t.Parallel()

	lg, logs := logger.NewRecorder(logger.LevelError)
	tedChan := make(chan []table.TEDElem, 1)
	done := make(chan struct{})

	go func() {
		MonitorBGPLsEvents(context.Background(), "\x00", "50051", tedChan, lg)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("MonitorBGPLsEvents did not return for an unusable server address")
	}
	require.Equal(t, 1, logs.Len())
	assert.Equal(t, "failed to create gRPC client", logs.All()[0].Message)
}

func testMonitorBGPLsEventsReconnectsAfterStreamEnd(t *testing.T) {
	t.Parallel()

	respInitial := []*api.ListPathResponse{
		{Destination: testNodeDestination(t, 65000, testRouterID1, "r0")},
	}
	respStream1 := []*api.ListPathResponse{
		{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		{Destination: testNodeDestination(t, 65000, testRouterID2, "r2")},
	}
	respStream2 := []*api.ListPathResponse{
		{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		{Destination: testNodeDestination(t, 65000, testRouterID2, "r2")},
		{Destination: testNodeDestination(t, 65000, "0000.0000.0003", "r3")},
	}
	tableEvent := &api.WatchEventResponse{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{}}}

	server := &testGoBGPServer{
		listPathResp:  respInitial,
		listPathResps: [][]*api.ListPathResponse{respInitial, respStream1, respStream2},
		watchEventsPerCall: [][]*api.WatchEventResponse{
			{tableEvent},
			{tableEvent},
		},
		watchEventHold: 200 * time.Millisecond,
	}
	host, port := startTestGoBGPServer(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	tedChan := make(chan []table.TEDElem, 32)

	var mu sync.Mutex
	var deliveries [][]table.TEDElem
	go func() {
		for elems := range tedChan {
			mu.Lock()
			deliveries = append(deliveries, elems)
			mu.Unlock()
		}
	}()
	hasDelivery := func(length int) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, d := range deliveries {
			if len(d) == length {
				return true
			}
		}
		return false
	}

	done := make(chan struct{})
	go func() {
		monitorBGPLsEvents(ctx, host, port, tedChan, logger.NewNop(), monitorOptions{
			debounceCooldown: 10 * time.Millisecond,
			retryInterval:    10 * time.Millisecond,
		})
		close(done)
	}()

	require.Eventually(t, func() bool { return hasDelivery(len(respInitial)) },
		5*time.Second, time.Millisecond, "the initial TED sync was not delivered")

	require.Eventually(t, func() bool { return hasDelivery(len(respStream1)) },
		5*time.Second, time.Millisecond, "stream #1's table event was not processed")

	require.Eventually(t, func() bool { return server.watchEventCalls.Load() >= 2 },
		5*time.Second, time.Millisecond, "the watch stream was not re-established after stream #1 ended")

	require.Eventually(t, func() bool { return hasDelivery(len(respStream2)) },
		5*time.Second, time.Millisecond, "stream #2's table event was not processed")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitorBGPLsEvents did not return after the context was canceled")
	}
}

func testMonitorBGPLsEventsContextCanceled(t *testing.T) {
	t.Parallel()

	host, port := startTestGoBGPServer(t, &testGoBGPServer{
		listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		},
		watchEventHold: 5 * time.Second, // keep the stream open until cancellation
	})

	ctx, cancel := context.WithCancel(context.Background())
	tedChan := make(chan []table.TEDElem, 1)
	done := make(chan struct{})

	go func() {
		MonitorBGPLsEvents(ctx, host, port, tedChan, logger.NewNop())
		close(done)
	}()

	select {
	case <-tedChan:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the initial TED sync")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("MonitorBGPLsEvents did not return after the caller's context was canceled")
	}
}

func testMonitorBGPLsEventsDebouncedFetch(t *testing.T) {
	t.Parallel()

	server := &testGoBGPServer{
		listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		},
		watchEvents: []*api.WatchEventResponse{
			{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{}}},
		},
		watchEventHold: 200 * time.Millisecond,
	}
	host, port := startTestGoBGPServer(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	tedChan := make(chan []table.TEDElem, 4)
	done := make(chan struct{})

	go func() {
		monitorBGPLsEvents(ctx, host, port, tedChan, logger.NewNop(), monitorOptions{
			debounceCooldown: 20 * time.Millisecond,
			retryInterval:    10 * time.Millisecond,
		})
		close(done)
	}()

	select {
	case got := <-tedChan:
		assert.Len(t, got, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the initial TED sync")
	}

	select {
	case got := <-tedChan:
		assert.Len(t, got, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the debounced fetch to deliver")
	}
	assert.GreaterOrEqual(t, server.listPathCalls.Load(), int32(2))

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitorBGPLsEvents did not return after the context was canceled")
	}
}

func testMonitorBGPLsEventsReestablishesStream(t *testing.T) {
	t.Parallel()

	server := &testGoBGPServer{
		listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		},
		watchEvents: []*api.WatchEventResponse{
			{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{}}},
		},
		watchEventErrs: []error{status.Error(codes.Unavailable, "watch stream broken")},
		watchEventHold: 200 * time.Millisecond,
	}
	host, port := startTestGoBGPServer(t, server)

	lg, logs := logger.NewRecorder(logger.LevelError)
	ctx, cancel := context.WithCancel(context.Background())
	tedChan := make(chan []table.TEDElem, 4)
	done := make(chan struct{})

	go func() {
		monitorBGPLsEvents(ctx, host, port, tedChan, lg, monitorOptions{
			debounceCooldown: 20 * time.Millisecond,
			retryInterval:    10 * time.Millisecond,
		})
		close(done)
	}()

	select {
	case got := <-tedChan:
		assert.Len(t, got, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the initial TED sync")
	}

	select {
	case got := <-tedChan:
		assert.Len(t, got, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the re-established stream to deliver")
	}
	assert.GreaterOrEqual(t, server.watchEventCalls.Load(), int32(2))
	require.GreaterOrEqual(t, logs.Len(), 1)
	assert.Equal(t, "error receiving BGP-LS event", logs.All()[0].Message)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitorBGPLsEvents did not return after the context was canceled")
	}
}

func testMonitorBGPLsEventsResyncsAfterReconnect(t *testing.T) {
	t.Parallel()

	respInitial := []*api.ListPathResponse{
		{Destination: testNodeDestination(t, 65000, testRouterID1, "r0")},
	}
	respStream1 := []*api.ListPathResponse{
		{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		{Destination: testNodeDestination(t, 65000, testRouterID2, "r2")},
	}
	respResync := []*api.ListPathResponse{
		{Destination: testNodeDestination(t, 65000, testRouterID1, "r1")},
		{Destination: testNodeDestination(t, 65000, testRouterID2, "r2")},
		{Destination: testNodeDestination(t, 65000, "0000.0000.0003", "r3")},
	}
	tableEvent := &api.WatchEventResponse{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{}}}

	server := &testGoBGPServer{
		listPathResp:  respInitial,
		listPathResps: [][]*api.ListPathResponse{respInitial, respStream1, respResync},
		watchEventsPerCall: [][]*api.WatchEventResponse{
			{tableEvent},
			{}, // No event on the reconnected stream; resync must be triggered explicitly.
		},
		watchEventHolds: []time.Duration{200 * time.Millisecond, 5 * time.Second},
	}
	host, port := startTestGoBGPServer(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	tedChan := make(chan []table.TEDElem, 16)

	var mu sync.Mutex
	var deliveries [][]table.TEDElem
	go func() {
		for elems := range tedChan {
			mu.Lock()
			deliveries = append(deliveries, elems)
			mu.Unlock()
		}
	}()
	hasDelivery := func(length int) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, d := range deliveries {
			if len(d) == length {
				return true
			}
		}
		return false
	}

	done := make(chan struct{})
	go func() {
		monitorBGPLsEvents(ctx, host, port, tedChan, logger.NewNop(), monitorOptions{
			debounceCooldown: 10 * time.Millisecond,
			retryInterval:    10 * time.Millisecond,
		})
		close(done)
	}()

	require.Eventually(t, func() bool { return hasDelivery(len(respInitial)) },
		5*time.Second, time.Millisecond, "the initial TED sync was not delivered")

	require.Eventually(t, func() bool { return hasDelivery(len(respStream1)) },
		5*time.Second, time.Millisecond, "stream #1's table event did not trigger a fetch")

	require.Eventually(t, func() bool { return server.watchEventCalls.Load() >= 2 },
		5*time.Second, time.Millisecond, "the watch stream was not re-established after stream #1 ended")

	require.Eventually(t, func() bool { return hasDelivery(len(respResync)) },
		5*time.Second, time.Millisecond,
		"reconnecting did not trigger a forced resync although stream #2 sent no table event")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitorBGPLsEvents did not return after the context was canceled")
	}
}
