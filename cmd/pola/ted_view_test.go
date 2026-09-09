// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

func TestNewTEDNodeViews_SortedByRouterID(t *testing.T) {
	t.Parallel()

	nodes := map[string]*table.LsNode{
		testRouterID2: {ASN: 65000, RouterID: testRouterID2},
		testRouterID1: {ASN: 65000, RouterID: testRouterID1},
		"nil-entry":   nil,
	}

	views := newTEDNodeViews(nodes)
	require.Len(t, views, 2)
	assert.Equal(t, testRouterID1, views[0].RouterID)
	assert.Equal(t, testRouterID2, views[1].RouterID)
}

func TestNewTEDLinkView_OmitsUnsetIPs(t *testing.T) {
	t.Parallel()

	link := &table.LsLink{Remote: table.LinkEndpoint{Node: &table.LsNode{RouterID: testRouterID2}}}
	v := newTEDLinkView(link)
	assert.Empty(t, v.Local.IPv4)
	assert.Empty(t, v.Local.IPv6)
	assert.Empty(t, v.Remote.IPv4)
	assert.Empty(t, v.Remote.IPv6)
	assert.Equal(t, testRouterID2, v.Remote.RouterID)
}

func TestNewTEDLinkView_IPv6Only(t *testing.T) {
	t.Parallel()

	link := &table.LsLink{
		Local:  table.LinkEndpoint{IPv6: netip.MustParseAddr("2001:db8::1")},
		Remote: table.LinkEndpoint{IPv6: netip.MustParseAddr("2001:db8::2")},
	}
	v := newTEDLinkView(link)
	assert.Empty(t, v.Local.IPv4)
	assert.Equal(t, "2001:db8::1", v.Local.IPv6)
	assert.Empty(t, v.Remote.IPv4)
	assert.Equal(t, "2001:db8::2", v.Remote.IPv6)
}

func TestNewTEDLinkView_DualStack(t *testing.T) {
	t.Parallel()

	ifaceID := uint32(7)
	link := &table.LsLink{
		Local: table.LinkEndpoint{
			IPv4:        netip.MustParseAddr(testPeerAddr1),
			IPv6:        netip.MustParseAddr("2001:db8::1"),
			InterfaceID: &ifaceID,
		},
		Remote: table.LinkEndpoint{
			IPv4: netip.MustParseAddr(testPeerAddr2),
			IPv6: netip.MustParseAddr("2001:db8::2"),
		},
	}
	v := newTEDLinkView(link)
	assert.Equal(t, testPeerAddr1, v.Local.IPv4)
	assert.Equal(t, "2001:db8::1", v.Local.IPv6)
	require.NotNil(t, v.Local.InterfaceID)
	assert.Equal(t, ifaceID, *v.Local.InterfaceID)
	assert.Equal(t, testPeerAddr2, v.Remote.IPv4)
	assert.Equal(t, "2001:db8::2", v.Remote.IPv6)
}

func TestNewTEDAdjSidViews(t *testing.T) {
	t.Parallel()

	views := newTEDAdjSidViews([]table.AdjSID{
		{Family: table.AFIPv4, Sid: 100},
		{Family: table.AFIPv6, Sid: 200},
		{Sid: 300},
	})
	require.Len(t, views, 3)
	assert.Equal(t, tedAdjSidView{Family: "ipv4", Sid: 100}, views[0])
	assert.Equal(t, tedAdjSidView{Family: "ipv6", Sid: 200}, views[1])
	assert.Equal(t, tedAdjSidView{Family: "unspecified", Sid: 300}, views[2])
}

func TestEndpointBehaviorViewFrom_IncludesFlagsAndAlgorithm(t *testing.T) {
	t.Parallel()

	v := endpointBehaviorViewFrom(table.EndpointBehavior{Behavior: table.BehaviorEND, Flags: 1, Algorithm: 2})
	assert.Equal(t, table.BehaviorEND, v.Behavior)
	assert.Equal(t, uint8(1), v.Flags)
	assert.Equal(t, uint8(2), v.Algorithm)
}

func TestNewTEDSrv6EndXSIDView_IncludesFlagsAlgorithmAndWeight(t *testing.T) {
	t.Parallel()

	v := newTEDSrv6EndXSIDView(&table.Srv6EndXSID{
		EndpointBehavior: table.EndpointBehavior{
			Behavior: table.BehaviorENDX, Flags: 0xC0, Algorithm: 128,
		},
		Weight: 7,
	})
	assert.Equal(t, table.BehaviorENDX, v.EndpointBehavior.Behavior)
	assert.Equal(t, uint8(0xC0), v.EndpointBehavior.Flags)
	assert.Equal(t, uint8(128), v.EndpointBehavior.Algorithm)
	assert.Equal(t, uint8(7), v.Weight)
}

func TestNewTEDPrefixViews_SkipsNilEntries(t *testing.T) {
	t.Parallel()

	p := &table.LsPrefix{Prefix: netip.MustParsePrefix("10.0.0.0/24")}
	views := newTEDPrefixViews([]*table.LsPrefix{nil, p})
	require.Len(t, views, 1)
	assert.Equal(t, "10.0.0.0/24", views[0].Prefix)
}

func TestNewTEDLinkViews_SkipsNilEntries(t *testing.T) {
	t.Parallel()

	l := &table.LsLink{Remote: table.LinkEndpoint{Node: &table.LsNode{RouterID: testRouterID2}}}
	views := newTEDLinkViews([]*table.LsLink{nil, l})
	require.Len(t, views, 1)
	assert.Equal(t, testRouterID2, views[0].Remote.RouterID)
}

func TestNewTEDLinkView_IncludesSrv6EndXSID(t *testing.T) {
	t.Parallel()

	link := &table.LsLink{
		Srv6EndXSIDs: []*table.Srv6EndXSID{{
			EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorENDX},
			Sids:             []string{testSrv6EndXSID},
			Srv6SIDStructure: &table.SIDStructure{LocalBlock: 1, LocalNode: 2, LocalFunc: 3, LocalArg: 4},
		}},
	}

	v := newTEDLinkView(link)
	require.Len(t, v.Srv6EndXSIDs, 1)
	assert.Equal(t, []string{testSrv6EndXSID}, v.Srv6EndXSIDs[0].Sids)
	assert.Equal(t, table.BehaviorENDX, v.Srv6EndXSIDs[0].EndpointBehavior.Behavior)
	assert.Equal(t, uint8(1), v.Srv6EndXSIDs[0].SidStructure.LocalBlock)
}

func TestNewTEDLinkView_MultipleSrv6EndXSIDs(t *testing.T) {
	t.Parallel()

	link := &table.LsLink{
		Srv6EndXSIDs: []*table.Srv6EndXSID{
			{EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorENDX}, Sids: []string{"fc00:0:1:1::"}},
			{EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorENDX}, Sids: []string{"fc00:0:1:2::"}},
			nil,
		},
	}

	v := newTEDLinkView(link)
	require.Len(t, v.Srv6EndXSIDs, 2)
	assert.Equal(t, []string{"fc00:0:1:1::"}, v.Srv6EndXSIDs[0].Sids)
	assert.Equal(t, []string{"fc00:0:1:2::"}, v.Srv6EndXSIDs[1].Sids)
}

func TestNewTEDMetricViews_SkipsNilEntries(t *testing.T) {
	t.Parallel()

	m := table.NewMetric(table.IGPMetric, 10)
	views := newTEDMetricViews([]*table.Metric{nil, m})
	require.Len(t, views, 1)
	assert.Equal(t, metricTypeIGP, views[0].Type)
	assert.Equal(t, uint32(10), views[0].Value)
}

func TestNewTEDSrv6SIDViews_SkipsNilEntries(t *testing.T) {
	t.Parallel()

	s := &table.LsSrv6SID{Sids: []string{"fc00:0:1::"}}
	views := newTEDSrv6SIDViews([]*table.LsSrv6SID{nil, s})
	require.Len(t, views, 1)
	assert.Equal(t, []string{"fc00:0:1::"}, views[0].Sids)
	assert.Nil(t, views[0].SidStructure, "no SID Structure TLV was advertised")
}

func TestNewTEDSrv6SIDViews_DistinguishesAbsentFromPresentZero(t *testing.T) {
	t.Parallel()

	views := newTEDSrv6SIDViews([]*table.LsSrv6SID{
		{Sids: []string{"fc00:0:1::"}},
		{Sids: []string{"fc00:0:2::"}, SIDStructure: &table.SIDStructure{}},
	})
	require.Len(t, views, 2)
	assert.Nil(t, views[0].SidStructure, "absent structure must not render as present-zero")
	assert.Equal(t, &table.SIDStructure{}, views[1].SidStructure, "present-but-zero structure must still render")
}
