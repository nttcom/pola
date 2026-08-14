// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package gobgp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nttcom/pola/pkg/table"
	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestGetLsPrefix_NLRITypesAndErrors(t *testing.T) {
	localNodeDesc := &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"}

	t.Run("PrefixV6 NLRI", func(t *testing.T) {
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

		want := table.NewLsPrefix(table.NewLsNode(65000, "0000.0000.0001"))
		want.Prefix = netip.MustParsePrefix("2001:db8::/64")
		want.SidIndex, want.HasSidIndex = 100, true
		assert.Equal(t, want, got)
	})

	t.Run("unsupported NLRI type", func(t *testing.T) {
		nlri := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Node{Node: &api.LsNodeNLRI{}},
			},
		}

		_, err := getLsPrefix(nlri, &api.LsAttributePrefix{})
		assert.EqualError(t, err, "invalid LS prefix NLRI type")
	})

	t.Run("nil NLRI", func(t *testing.T) {
		_, err := getLsPrefix(nil, &api.LsAttributePrefix{})
		require.EqualError(t, err, "LS Prefix NLRI is nil")
	})

	t.Run("nil NLRI field", func(t *testing.T) {
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
	attr := &api.LsAttributePrefix{SrPrefixSid: 100}

	t.Run("success", func(t *testing.T) {
		nlris := []*api.NLRI{
			{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: testLsAddrPrefixV4(t, "10.0.0.1/32")}},
			{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: testLsAddrPrefixV4(t, "10.0.0.2/32")}},
		}

		got, err := getLsPrefixList(nlris, attr)
		require.NoError(t, err)
		require.Len(t, got, 2)
	})

	t.Run("propagates a per-prefix error", func(t *testing.T) {
		nlris := []*api.NLRI{
			{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: testLsAddrPrefixV4(t, "not-a-prefix")}},
		}

		_, err := getLsPrefixList(nlris, attr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get LS Prefix")
	})

	t.Run("no NLRIs", func(t *testing.T) {
		got, err := getLsPrefixList(nil, attr)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestFormatIsisAreaID(t *testing.T) {
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
			assert.Equal(t, tt.want, formatIsisAreaID(tt.area))
		})
	}
}

func TestGetLsNode(t *testing.T) {
	nlri := &api.LsAddrPrefix{
		Nlri: &api.LsAddrPrefix_LsNLRI{
			Nlri: &api.LsAddrPrefix_LsNLRI_Node{
				Node: &api.LsNodeNLRI{
					LocalNode: &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"},
				},
			},
		},
	}

	t.Run("no SR Capabilities TLV", func(t *testing.T) {
		attr := &api.LsAttributeNode{Name: "r1", IsisArea: []byte{0x49, 0x00}}

		got, err := getLsNode(nlri, attr)
		require.NoError(t, err)

		want := table.NewLsNode(65000, "0000.0000.0001")
		want.Hostname = "r1"
		want.IsisAreaID = "4900"
		assert.Equal(t, want, got)
	})

	t.Run("one SR Capability Range TLV", func(t *testing.T) {
		attr := &api.LsAttributeNode{
			Name:           "r1",
			SrCapabilities: &api.LsSrCapabilities{Ranges: []*api.LsSrRange{{Begin: 16000, End: 23999}}},
		}

		got, err := getLsNode(nlri, attr)
		require.NoError(t, err)

		want := table.NewLsNode(65000, "0000.0000.0001")
		want.Hostname = "r1"
		want.SrgbBegin, want.SrgbEnd = 16000, 23999
		assert.Equal(t, want, got)
	})

	t.Run("SR Capabilities present with no Range TLV", func(t *testing.T) {
		attr := &api.LsAttributeNode{SrCapabilities: &api.LsSrCapabilities{}}

		_, err := getLsNode(nlri, attr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 1 SR Capability TLV, got: 0")
	})

	t.Run("SR Capabilities with more than one Range TLV", func(t *testing.T) {
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
	localDesc := &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"}
	remoteDesc := &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0002"}
	expectedLocal := table.NewLsNode(65000, "0000.0000.0001")
	expectedRemote := table.NewLsNode(65000, "0000.0000.0002")

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
						Sids:             []string{"2001:db8::1:0"},
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
						Sids:             []string{"2001:db8::1:0"},
						Srv6SIDStructure: table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
					},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := getLsLink(newNLRI(tt.desc), tt.attr)
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("address parse errors", func(t *testing.T) {
		tests := []struct {
			name    string
			desc    *api.LsLinkDescriptor
			wantErr string
		}{
			{"invalid local IPv4 address", &api.LsLinkDescriptor{InterfaceAddrIpv4: "bad-ip"}, "failed to parse local IPv4 address"},
			{"invalid local IPv6 address", &api.LsLinkDescriptor{InterfaceAddrIpv6: "bad-ip"}, "failed to parse local IPv6 address"},
			{"invalid remote IPv4 address", &api.LsLinkDescriptor{NeighborAddrIpv4: "bad-ip"}, "failed to parse remote IPv4 address"},
			{"invalid remote IPv6 address", &api.LsLinkDescriptor{NeighborAddrIpv6: "bad-ip"}, "failed to parse remote IPv6 address"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := getLsLink(newNLRI(tt.desc), &api.LsAttributeLink{})
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})

	t.Run("invalid NLRI", func(t *testing.T) {
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
				_, err := getLsLink(tt.nlri, &api.LsAttributeLink{})
				require.Error(t, err)
			})
		}
	})
}

func TestGetLsSrv6SID(t *testing.T) {
	attr := &api.LsAttributeSrv6SID{
		Srv6EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: uint32(table.BehaviorEND)},
		Srv6SidStructure:     &api.LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
	}

	t.Run("success", func(t *testing.T) {
		nlri := &api.LsAddrPrefix{
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Srv6Sid{
					Srv6Sid: &api.LsSrv6SIDNLRI{
						LocalNode:          &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"},
						Srv6SidInformation: &api.LsSrv6SIDInformation{Sids: []string{"2001:db8:1::"}},
						MultiTopoId:        &api.LsMultiTopologyIdentifier{MultiTopoIds: []uint32{0}},
					},
				},
			},
		}

		got, err := getLsSrv6SID(nlri, attr)
		require.NoError(t, err)

		want := table.NewLsSrv6SID(table.NewLsNode(65000, "0000.0000.0001"))
		want.Sids = []string{"2001:db8:1::"}
		want.MultiTopoIDs = []uint32{0}
		want.SIDStructure = table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0}
		want.EndpointBehavior = table.EndpointBehavior{Behavior: table.BehaviorEND}
		assert.Equal(t, want, got)
	})

	t.Run("invalid NLRI", func(t *testing.T) {
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
				_, err := getLsSrv6SID(tt.nlri, attr)
				require.Error(t, err)
			})
		}
	})
}

func TestGetLsSrv6SIDList(t *testing.T) {
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
		got, err := getLsSrv6SIDList([]*api.NLRI{newNLRI("0000.0000.0001"), newNLRI("0000.0000.0002")}, attr)
		require.NoError(t, err)
		require.Len(t, got, 2)
	})

	t.Run("no NLRIs", func(t *testing.T) {
		got, err := getLsSrv6SIDList(nil, attr)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("non-LsAddrPrefix NLRI", func(t *testing.T) {
		nlris := []*api.NLRI{{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{}}}}
		_, err := getLsSrv6SIDList(nlris, attr)
		require.Error(t, err)
	})
}

func TestMpReachNlris_MissingMpReach(t *testing.T) {
	lsAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{Srv6Sid: &api.LsAttributeSrv6SID{}}}
	path := &api.Path{Pattrs: []*api.Attribute{{Attr: lsAttr}}}

	_, err := mpReachNlris(path)
	assert.EqualError(t, err, "MP-REACH NLRI Attribute is nil")
}

func TestConvertSrv6SID_InvalidNLRIInMpReach(t *testing.T) {
	lsAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{Srv6Sid: &api.LsAttributeSrv6SID{}}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{}}}}

	_, err := convertSrv6SID(lsAttr, nlris)
	assert.Error(t, err)
}

func TestFindLsAttribute(t *testing.T) {
	t.Run("found among other attributes", func(t *testing.T) {
		lsAttr := &api.Attribute_Ls{Ls: &api.LsAttribute{}}
		path := &api.Path{Pattrs: []*api.Attribute{
			{Attr: &api.Attribute_Origin{}},
			{Attr: lsAttr},
		}}

		assert.Same(t, lsAttr, findLsAttribute(path))
	})

	t.Run("not present", func(t *testing.T) {
		path := &api.Path{Pattrs: []*api.Attribute{{Attr: &api.Attribute_Origin{}}}}
		assert.Nil(t, findLsAttribute(path))
	})
}

func TestFindMpReach(t *testing.T) {
	t.Run("found among other attributes", func(t *testing.T) {
		mpReach := &api.MpReachNLRIAttribute{}
		path := &api.Path{Pattrs: []*api.Attribute{
			{Attr: &api.Attribute_Origin{}},
			{Attr: &api.Attribute_MpReach{MpReach: mpReach}},
		}}

		assert.Same(t, mpReach, findMpReach(path))
	})

	t.Run("not present", func(t *testing.T) {
		path := &api.Path{Pattrs: []*api.Attribute{{Attr: &api.Attribute_Origin{}}}}
		assert.Nil(t, findMpReach(path))
	})
}

func TestConvertToTEDElem(t *testing.T) {
	nodeNLRI := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_NODE,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Node{
			Node: &api.LsNodeNLRI{LocalNode: &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"}},
		}},
	}
	linkNLRI := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_LINK,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Link{
			Link: &api.LsLinkNLRI{
				LocalNode:      &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"},
				RemoteNode:     &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0002"},
				LinkDescriptor: &api.LsLinkDescriptor{},
			},
		}},
	}
	linkNLRIBadAddr := &api.LsAddrPrefix{
		Type: api.LsNLRIType_LS_NLRI_TYPE_LINK,
		Nlri: &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Link{
			Link: &api.LsLinkNLRI{
				LocalNode:      &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"},
				RemoteNode:     &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0002"},
				LinkDescriptor: &api.LsLinkDescriptor{InterfaceAddrIpv4: "bad-ip"},
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
				LocalNode:          &api.LsNodeDescriptor{Asn: 65000, IgpRouterId: "0000.0000.0001"},
				Srv6SidInformation: &api.LsSrv6SIDInformation{Sids: []string{"2001:db8:1::"}},
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
	t.Run("success", func(t *testing.T) {
		cc, client, err := newGoBGPClient("127.0.0.1", "50051")
		require.NoError(t, err)
		require.NotNil(t, cc)
		require.NotNil(t, client)
		assert.NoError(t, cc.Close())
	})

	t.Run("unparsable target", func(t *testing.T) {
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
	t.Run("success", func(t *testing.T) {
		client := &fakeGoBGPClient{listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, "0000.0000.0001", "r1")},
			{Destination: testNodeDestination(t, 65000, "0000.0000.0002", "r2")},
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
		got, err := GetBGPlsNLRIs(context.Background(), &fakeGoBGPClient{})
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("ListPath call fails", func(t *testing.T) {
		client := &fakeGoBGPClient{listPathErr: errors.New("connection refused")}

		_, err := GetBGPlsNLRIs(context.Background(), client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve paths from gRPC server")
	})

	t.Run("stream receive fails", func(t *testing.T) {
		client := &fakeGoBGPClient{recvErr: errors.New("stream broken")}

		_, err := GetBGPlsNLRIs(context.Background(), client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error receiving stream data")
	})

	t.Run("conversion error propagates", func(t *testing.T) {
		client := &fakeGoBGPClient{listPathResp: []*api.ListPathResponse{
			{Destination: &api.Destination{Paths: nil}},
		}}

		_, err := GetBGPlsNLRIs(context.Background(), client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to convert path to TED element")
	})
}

func TestWaitForRetry(t *testing.T) {
	t.Run("waits for the interval and reports true", func(t *testing.T) {
		assert.True(t, waitForRetry(context.Background(), time.Millisecond))
	})

	t.Run("reports false without waiting for the interval when the context is done", func(t *testing.T) {
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
	client := &fakeGoBGPClient{watchEventErr: errors.New("watch unavailable")}
	ctx, cancel := context.WithCancel(context.Background())

	type result struct {
		stream grpc.ServerStreamingClient[api.WatchEventResponse]
		ok     bool
	}
	done := make(chan result, 1)
	go func() {
		stream, ok := establishWatchStream(ctx, client, newWatchRequest(), 5*time.Millisecond, zap.NewNop())
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
	t.Run("success delivers the initial TED", func(t *testing.T) {
		client := &fakeGoBGPClient{listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, "0000.0000.0001", "r1")},
		}}
		tedChan := make(chan []table.TEDElem, 1)

		initialSync(context.Background(), client, tedChan, zap.NewNop())

		require.Len(t, tedChan, 1)
		assert.Len(t, <-tedChan, 1)
	})

	t.Run("logs and skips delivery on failure", func(t *testing.T) {
		client := &fakeGoBGPClient{listPathErr: errors.New("connection refused")}
		core, logs := observer.New(zap.ErrorLevel)
		tedChan := make(chan []table.TEDElem, 1)

		initialSync(context.Background(), client, tedChan, zap.New(core))

		assert.Empty(t, tedChan)
		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "failed to get initial TED info", logs.All()[0].Message)
	})
}

func TestDebouncerTrigger(t *testing.T) {
	t.Run("fetches once after the cooldown and delivers", func(t *testing.T) {
		d := NewDebouncer(20 * time.Millisecond)

		want := []table.TEDElem{table.NewLsNode(1, "r1")}
		var fetchCount atomic.Int32
		fetch := func() ([]table.TEDElem, error) {
			fetchCount.Add(1)
			return want, nil
		}
		delivered := make(chan []table.TEDElem, 1)

		d.Trigger(t.Context(), fetch, func(elems []table.TEDElem) { delivered <- elems }, zap.NewNop())

		select {
		case got := <-delivered:
			assert.Equal(t, want, got)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for delivery")
		}
		assert.EqualValues(t, 1, fetchCount.Load())
	})

	t.Run("collapses triggers within the cooldown window into one fetch", func(t *testing.T) {
		d := NewDebouncer(50 * time.Millisecond)
		ctx := t.Context()

		var fetchCount atomic.Int32
		fetch := func() ([]table.TEDElem, error) {
			fetchCount.Add(1)
			return nil, nil
		}
		delivered := make(chan []table.TEDElem, 1)
		deliver := func(elems []table.TEDElem) { delivered <- elems }
		logger := zap.NewNop()

		d.Trigger(ctx, fetch, deliver, logger)
		time.Sleep(10 * time.Millisecond)
		d.Trigger(ctx, fetch, deliver, logger)

		select {
		case <-delivered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for delivery")
		}
		assert.EqualValues(t, 1, fetchCount.Load())
	})

	t.Run("stops without fetching when the context is canceled first", func(t *testing.T) {
		d := NewDebouncer(time.Hour)
		ctx, cancel := context.WithCancel(t.Context())

		var fetchCalled atomic.Int32
		fetch := func() ([]table.TEDElem, error) {
			fetchCalled.Store(1)
			return nil, nil
		}
		deliver := func([]table.TEDElem) { t.Fatal("deliver should not be called") }

		d.Trigger(ctx, fetch, deliver, zap.NewNop())
		cancel()

		require.Eventually(t, func() bool {
			d.mu.Lock()
			defer d.mu.Unlock()
			return !d.active
		}, time.Second, time.Millisecond)
		assert.EqualValues(t, 0, fetchCalled.Load())
	})

	t.Run("logs and skips delivery when the fetch fails", func(t *testing.T) {
		d := NewDebouncer(10 * time.Millisecond)

		core, logs := observer.New(zap.ErrorLevel)
		fetch := func() ([]table.TEDElem, error) { return nil, errors.New("fetch failed") }
		deliver := func([]table.TEDElem) { t.Fatal("deliver should not be called") }

		d.Trigger(t.Context(), fetch, deliver, zap.New(core))

		require.Eventually(t, func() bool { return logs.Len() > 0 }, time.Second, time.Millisecond)
		assert.Equal(t, "failed to get TED info", logs.All()[0].Message)
	})

	t.Run("skips delivery when the context ends during the fetch", func(t *testing.T) {
		d := NewDebouncer(10 * time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())

		core, logs := observer.New(zap.DebugLevel)
		fetch := func() ([]table.TEDElem, error) {
			cancel() // simulate the context ending while the fetch is in flight
			return []table.TEDElem{table.NewLsNode(1, "r1")}, nil
		}
		deliver := func([]table.TEDElem) { t.Fatal("deliver should not be called") }

		d.Trigger(ctx, fetch, deliver, zap.New(core))

		require.Eventually(t, func() bool { return logs.Len() > 0 }, time.Second, time.Millisecond)
		assert.Equal(t, "deliver aborted due to context cancel", logs.All()[0].Message)
	})
}

// testGoBGPServer implements api.GoBgpServiceServer for MonitorBGPLsEvents integration tests.
// Only ListPath and WatchEvent are exercised by the code under test.
type testGoBGPServer struct {
	api.UnimplementedGoBgpServiceServer
	listPathResp []*api.ListPathResponse
	watchEvents  []*api.WatchEventResponse
	// Keeps the WatchEvent stream open after sending watchEvents so the
	// debounced fetch has time to run before the stream ends.
	watchEventHold time.Duration
	// Errors returned by successive WatchEvent calls.
	watchEventErrs  []error
	listPathCalls   atomic.Int32
	watchEventCalls atomic.Int32
}

func (s *testGoBGPServer) ListPath(_ *api.ListPathRequest, stream grpc.ServerStreamingServer[api.ListPathResponse]) error {
	s.listPathCalls.Add(1)
	for _, r := range s.listPathResp {
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
	for _, e := range s.watchEvents {
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	time.Sleep(s.watchEventHold)
	return nil
}

// startTestGoBGPServer serves server on a loopback port and returns its host and port.
func startTestGoBGPServer(t *testing.T, server *testGoBGPServer) (string, string) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	api.RegisterGoBgpServiceServer(srv, server)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	host, port, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)
	return host, port
}

func TestMonitorBGPLsEvents(t *testing.T) {
	t.Run("returns immediately when the gRPC client cannot be created", testMonitorBGPLsEventsUnusableAddress)
	t.Run("syncs the TED and processes watch events until the stream ends", testMonitorBGPLsEventsUntilStreamEnds)
	t.Run("returns when the caller's context is canceled", testMonitorBGPLsEventsContextCanceled)
	t.Run("returns immediately when the context is already canceled", testMonitorBGPLsEventsAlreadyCanceledContext)
	t.Run("triggers a debounced fetch and delivers the refreshed TED", testMonitorBGPLsEventsDebouncedFetch)
	t.Run("re-establishes the watch stream after a receive error", testMonitorBGPLsEventsReestablishesStream)
}

func testMonitorBGPLsEventsAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tedChan := make(chan []table.TEDElem, 1)
	done := make(chan struct{})

	go func() {
		MonitorBGPLsEvents(ctx, "127.0.0.1", "50051", tedChan, zap.NewNop())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("MonitorBGPLsEvents did not return immediately for an already-canceled context")
	}
}

func testMonitorBGPLsEventsUnusableAddress(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	tedChan := make(chan []table.TEDElem, 1)
	done := make(chan struct{})

	go func() {
		MonitorBGPLsEvents(context.Background(), "\x00", "50051", tedChan, zap.New(core))
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

func testMonitorBGPLsEventsUntilStreamEnds(t *testing.T) {
	host, port := startTestGoBGPServer(t, &testGoBGPServer{
		listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, "0000.0000.0001", "r1")},
		},
		watchEvents: []*api.WatchEventResponse{
			{},
			{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{}}},
		},
	})

	tedChan := make(chan []table.TEDElem, 2)
	done := make(chan struct{})

	go func() {
		MonitorBGPLsEvents(context.Background(), host, port, tedChan, zap.NewNop())
		close(done)
	}()

	select {
	case got := <-tedChan:
		assert.Len(t, got, 1) // initial TED sync
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the initial TED sync")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("MonitorBGPLsEvents did not return after the watch stream ended")
	}
}

func testMonitorBGPLsEventsContextCanceled(t *testing.T) {
	host, port := startTestGoBGPServer(t, &testGoBGPServer{
		listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, "0000.0000.0001", "r1")},
		},
		watchEventHold: 5 * time.Second, // keep the stream open until cancellation
	})

	ctx, cancel := context.WithCancel(context.Background())
	tedChan := make(chan []table.TEDElem, 1)
	done := make(chan struct{})

	go func() {
		MonitorBGPLsEvents(ctx, host, port, tedChan, zap.NewNop())
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
	server := &testGoBGPServer{
		listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, "0000.0000.0001", "r1")},
		},
		watchEvents: []*api.WatchEventResponse{
			{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{}}},
		},
		watchEventHold: 200 * time.Millisecond,
	}
	host, port := startTestGoBGPServer(t, server)

	tedChan := make(chan []table.TEDElem, 2)
	done := make(chan struct{})

	go func() {
		monitorBGPLsEvents(context.Background(), host, port, tedChan, zap.NewNop(), monitorOptions{
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

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitorBGPLsEvents did not return after the watch stream ended")
	}
}

func testMonitorBGPLsEventsReestablishesStream(t *testing.T) {
	server := &testGoBGPServer{
		listPathResp: []*api.ListPathResponse{
			{Destination: testNodeDestination(t, 65000, "0000.0000.0001", "r1")},
		},
		watchEvents: []*api.WatchEventResponse{
			{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{}}},
		},
		watchEventErrs: []error{status.Error(codes.Unavailable, "watch stream broken")},
		watchEventHold: 200 * time.Millisecond,
	}
	host, port := startTestGoBGPServer(t, server)

	core, logs := observer.New(zap.ErrorLevel)
	tedChan := make(chan []table.TEDElem, 2)
	done := make(chan struct{})

	go func() {
		monitorBGPLsEvents(context.Background(), host, port, tedChan, zap.New(core), monitorOptions{
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
	assert.EqualValues(t, 2, server.watchEventCalls.Load())
	require.GreaterOrEqual(t, logs.Len(), 1)
	assert.Equal(t, "error receiving BGP-LS event", logs.All()[0].Message)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitorBGPLsEvents did not return after the watch stream ended")
	}
}
