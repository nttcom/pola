// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

// fullTEDNodeViewFixture exercises the rendering branches in ted_text.go.
func fullTEDNodeViewFixture() tedNodeView {
	sidIdx := uint32(7)
	ifaceID := uint32(5)

	return tedNodeView{
		RouterID:   testRouterID1,
		Hostname:   "router1",
		IsisAreaID: "49.0001",
		Srgb:       srgbView{Begin: 16000, End: 23999},
		Prefixes: []tedPrefixView{
			{Prefix: "10.0.0.1/32"},
			{Prefix: "10.0.0.2/32", SidIndex: &sidIdx},
		},
		Links: []tedLinkView{
			{
				AdjSids: []tedAdjSidView{{Family: "ipv4", Sid: 100}},
			},
			{
				Local:   tedLinkEndpointView{IPv4: testPeerAddr2, IPv6: "2001:db8::2", InterfaceID: &ifaceID},
				Remote:  tedLinkEndpointView{IPv4: "192.0.2.3", IPv6: "2001:db8::3", RouterID: testRouterID2},
				Metrics: []tedMetricView{{Type: metricTypeIGP, Value: 10}},
				AdjSids: []tedAdjSidView{{Family: "ipv6", Sid: 200}},
				Srv6EndXSIDs: []tedSrv6EndXSIDView{
					{
						EndpointBehavior: endpointBehaviorView{Name: "END-X-BEHAVIOR", Flags: 0xC0, Algorithm: 128},
						Weight:           7,
						Sids:             []string{testSrv6EndXSID},
						SidStructure:     &table.SIDStructure{LocalBlock: 21, LocalNode: 22, LocalFunc: 23, LocalArg: 24},
					},
				},
			},
		},
		SRv6SIDs: []tedSrv6SIDView{
			{
				Sids:             []string{"fc00:0:2:node1::"},
				EndpointBehavior: endpointBehaviorView{Name: "NODE-SID-BEHAVIOR-1"},
				SidStructure:     &table.SIDStructure{LocalBlock: 31, LocalNode: 32, LocalFunc: 33, LocalArg: 34},
				MultiTopoIDs:     []uint32{1},
			},
			{
				Sids:             []string{"fc00:0:2:node2::"},
				EndpointBehavior: endpointBehaviorView{Name: "NODE-SID-BEHAVIOR-2", Flags: 1, Algorithm: 2},
				SidStructure:     &table.SIDStructure{LocalBlock: 41, LocalNode: 42, LocalFunc: 43, LocalArg: 44},
				MultiTopoIDs:     []uint32{2, 3},
			},
		},
	}
}

func TestWriteTEDText_EmptyTED(t *testing.T) {
	t.Parallel()

	w := &condFailWriter{}
	require.NoError(t, writeTEDText(w, nil))
	require.Equal(t, "TED is empty\n", w.buf.String())
}

func TestWriteTEDText_FullRenderSucceeds(t *testing.T) {
	t.Parallel()

	w := &condFailWriter{}
	require.NoError(t, writeTEDText(w, []tedNodeView{fullTEDNodeViewFixture()}))
}

func TestWriteTEDText_SidStructureNotAdvertised(t *testing.T) {
	t.Parallel()

	node := tedNodeView{
		RouterID: testRouterID1,
		Links: []tedLinkView{
			{
				Remote: tedLinkEndpointView{RouterID: testRouterID2},
				Srv6EndXSIDs: []tedSrv6EndXSIDView{
					{
						EndpointBehavior: endpointBehaviorView{Name: "END-X-BEHAVIOR"},
						Sids:             []string{testSrv6EndXSID},
					},
				},
			},
		},
		SRv6SIDs: []tedSrv6SIDView{
			{
				Sids:             []string{"fc00:0:2:node1::"},
				EndpointBehavior: endpointBehaviorView{Name: "NODE-SID-BEHAVIOR-1"},
			},
		},
	}

	w := &condFailWriter{}
	require.NoError(t, writeTEDText(w, []tedNodeView{node}))
	require.Equal(t, 2, strings.Count(w.buf.String(), "SID Structure: (not advertised)"))
}

func TestWriteTEDText_PropagatesWriteErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fail func(string) bool
	}{
		{"node header", containsFail("Node #0: 0000.0aff.0001")},
		{"hostname", containsFail("Hostname: router1")},
		{"isis area id", containsFail("ISIS Area ID: 49.0001")},
		{"prefixes header", containsFail("Prefixes:")},
		{"prefix line", containsFail("10.0.0.1/32")},
		{"prefix sid index", containsFail("index: 7")},
		{"links header", containsFail("  Links:")},
		{"link local/remote", containsFail("Local: None Remote: None")},
		{"link remote router id", containsFail("RemoteRouterID: None")},
		{"link metrics header", containsFail("      Metrics:")},
		{"link metric line", containsFail("igp: 10")},
		{"link adj-sids header", containsFail("Adj-SIDs:")},
		{"link adj-sid line", containsFail("ipv4: 100")},
		{"link interface id", containsFail("interface 5")},
		{"srv6 end.x sid header", containsFail("SRv6 End.X SID:")},
		{"srv6 end.x endpoint behavior", containsFail("EndpointBehavior: END-X-BEHAVIOR")},
		{"srv6 end.x sids", containsFail(testSrv6EndXSID)},
		{"node srv6 sids header", containsFail("SRv6 SIDs:")},
		{"node srv6 sid sids", containsFail("fc00:0:2:node1::")},
		{"node srv6 sid structure", containsFail("Block: 31")},
		{"node srv6 sid endpoint behavior", containsFail("EndpointBehavior: NODE-SID-BEHAVIOR-1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := &condFailWriter{fail: tt.fail}
			err := writeTEDText(w, []tedNodeView{fullTEDNodeViewFixture()})
			require.Error(t, err)
		})
	}
}

func TestWriteTEDText_PropagatesSeparatorWriteError(t *testing.T) {
	t.Parallel()

	w := &condFailWriter{fail: exactFail("\n")}
	err := writeTEDText(w, []tedNodeView{fullTEDNodeViewFixture(), fullTEDNodeViewFixture()})
	require.Error(t, err)
}

func TestWriteTEDText_SeparatesMultipleNodesWithBlankLine(t *testing.T) {
	t.Parallel()

	w := &condFailWriter{}
	require.NoError(t, writeTEDText(w, []tedNodeView{fullTEDNodeViewFixture(), fullTEDNodeViewFixture()}))
	require.False(t, strings.HasSuffix(w.buf.String(), "\n\n"), "output must not end with a blank line")
	require.Contains(t, w.buf.String(), "\n\nNode #1:")
}
