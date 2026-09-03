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

	link := &table.LsLink{RemoteNode: &table.LsNode{RouterID: testRouterID2}}
	v := newTEDLinkView(link)
	assert.Empty(t, v.LocalIP)
	assert.Empty(t, v.RemoteIP)
	assert.Equal(t, testRouterID2, v.RemoteRouterID)
}

func TestEndpointBehaviorViewFrom_IncludesFlagsAndAlgorithm(t *testing.T) {
	t.Parallel()

	v := endpointBehaviorViewFrom(table.EndpointBehavior{Behavior: table.BehaviorEND, Flags: 1, Algorithm: 2})
	assert.Equal(t, table.BehaviorEND, v.Behavior)
	require.NotNil(t, v.Flags)
	assert.Equal(t, uint8(1), *v.Flags)
	require.NotNil(t, v.Algorithm)
	assert.Equal(t, uint8(2), *v.Algorithm)
}

func TestEndpointBehaviorViewFromBehavior_OmitsFlagsAndAlgorithm(t *testing.T) {
	t.Parallel()

	v := endpointBehaviorViewFromBehavior(table.BehaviorENDX)
	assert.Equal(t, table.BehaviorENDX, v.Behavior)
	assert.Nil(t, v.Flags)
	assert.Nil(t, v.Algorithm)
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

	l := &table.LsLink{RemoteNode: &table.LsNode{RouterID: testRouterID2}}
	views := newTEDLinkViews([]*table.LsLink{nil, l})
	require.Len(t, views, 1)
	assert.Equal(t, testRouterID2, views[0].RemoteRouterID)
}

func TestNewTEDLinkView_IncludesSrv6EndXSID(t *testing.T) {
	t.Parallel()

	link := &table.LsLink{
		Srv6EndXSID: &table.Srv6EndXSID{
			EndpointBehavior: table.BehaviorENDX,
			Sids:             []string{testSrv6EndXSID},
			Srv6SIDStructure: table.SIDStructure{LocalBlock: 1, LocalNode: 2, LocalFunc: 3, LocalArg: 4},
		},
	}

	v := newTEDLinkView(link)
	require.NotNil(t, v.Srv6EndXSID)
	assert.Equal(t, []string{testSrv6EndXSID}, v.Srv6EndXSID.Sids)
	assert.Equal(t, table.BehaviorENDX, v.Srv6EndXSID.EndpointBehavior.Behavior)
	assert.Equal(t, uint8(1), v.Srv6EndXSID.SidStructure.LocalBlock)
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
}
