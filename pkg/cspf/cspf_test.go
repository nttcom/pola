// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/cspf"
	"github.com/nttcom/pola/pkg/table"
)

const (
	testGhostRouterID = "GHOST"
	testInvalidSID    = "not-an-address"
	testOverrideSID   = "2001:db8::ffff"
)

var (
	scopeV4SRMPLS = cspf.PathScope{Plane: table.Plane{Family: table.AFIPv4, DataPlane: table.DPSRMPLS}}
	scopeV6SRMPLS = cspf.PathScope{Plane: table.Plane{Family: table.AFIPv6, DataPlane: table.DPSRMPLS}}
	scopeV6SRv6   = cspf.PathScope{Plane: table.Plane{Family: table.AFIPv6, DataPlane: table.DPSRv6}}
)

var (
	testLinkLocalIPv4  = netip.MustParseAddr("192.0.2.101")
	testLinkRemoteIPv4 = netip.MustParseAddr("192.0.2.102")
	testLinkLocalIPv6  = netip.MustParseAddr("2001:db8:f::1")
	testLinkRemoteIPv6 = netip.MustParseAddr("2001:db8:f::2")
)

func srMPLSNode(routerID string, sidIndex uint32) *table.LsNode {
	return &table.LsNode{
		RouterID:  routerID,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("192.0.2.1/32"), SidIndex: sidIndex, HasSidIndex: true},
		},
	}
}

func srMPLSNodeV6(routerID string, sidIndex uint32) *table.LsNode {
	return &table.LsNode{
		RouterID:  routerID,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("2001:db8::1/128"), SidIndex: sidIndex, HasSidIndex: true},
		},
	}
}

func dualStackNode(routerID string, v4SidIndex, v6SidIndex uint32, srv6Sid string) *table.LsNode {
	return &table.LsNode{
		RouterID:  routerID,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{Prefix: netip.MustParsePrefix("192.0.2.1/32"), SidIndex: v4SidIndex, HasSidIndex: true},
			{Prefix: netip.MustParsePrefix("2001:db8::1/128"), SidIndex: v6SidIndex, HasSidIndex: true},
		},
		SRv6SIDs: []*table.LsSrv6SID{
			{
				Sids:             []string{srv6Sid},
				EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorEND},
				SIDStructure:     &table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
			},
		},
	}
}

func mplsSeg(sidIndex uint32) table.Segment {
	return table.NewSegmentSRMPLS(16000 + sidIndex)
}

func srv6Node(routerID, sid string) *table.LsNode {
	return &table.LsNode{
		RouterID: routerID,
		SRv6SIDs: []*table.LsSrv6SID{
			{
				Sids:             []string{sid},
				EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorEND},
				SIDStructure:     &table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
			},
		},
	}
}

func srv6DefaultSeg(sid string) table.SegmentSRv6 {
	addr := netip.MustParseAddr(sid)

	return table.SegmentSRv6{
		Sid:       table.SRv6SID(addr),
		LocalAddr: addr,
		Behavior:  table.BehaviorEND,
		Structure: &table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16},
	}
}

func nodeWithoutSID(routerID string) *table.LsNode {
	return &table.LsNode{RouterID: routerID}
}

// connect is a single-cost alias for connectV4 where the address family
// and cost are irrelevant to the test.
func connect(local, remote *table.LsNode) {
	connectV4(local, remote, 1)
}

func connectV4(local, remote *table.LsNode, igpCost uint32) {
	local.Links = append(local.Links, &table.LsLink{
		Local:   table.LinkEndpoint{Node: local, IPv4: testLinkLocalIPv4},
		Remote:  table.LinkEndpoint{Node: remote, IPv4: testLinkRemoteIPv4},
		Metrics: []*table.Metric{table.NewMetric(table.IGPMetric, igpCost)},
	})
}

func connectV6(local, remote *table.LsNode, igpCost uint32) {
	local.Links = append(local.Links, &table.LsLink{
		Local:   table.LinkEndpoint{Node: local, IPv6: testLinkLocalIPv6},
		Remote:  table.LinkEndpoint{Node: remote, IPv6: testLinkRemoteIPv6},
		Metrics: []*table.Metric{table.NewMetric(table.IGPMetric, igpCost)},
	})
}

// connectMultiTopo creates an IPv4/IPv6 dual-stack LsLink for a single multi-topology ID.
func connectMultiTopo(local, remote *table.LsNode, mtID uint16, igpCost uint32) {
	local.Links = append(local.Links, &table.LsLink{
		Local:        table.LinkEndpoint{Node: local, IPv4: testLinkLocalIPv4, IPv6: testLinkLocalIPv6},
		Remote:       table.LinkEndpoint{Node: remote, IPv4: testLinkRemoteIPv4, IPv6: testLinkRemoteIPv6},
		Metrics:      []*table.Metric{table.NewMetric(table.IGPMetric, igpCost)},
		MultiTopoIDs: map[uint16]struct{}{mtID: {}},
	})
}

func buildTED(nodes ...*table.LsNode) *table.LsTED {
	m := make(map[string]*table.LsNode, len(nodes))
	for _, n := range nodes {
		m[n.RouterID] = n
	}

	return &table.LsTED{Nodes: m}
}

func TestCSPF_PathSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		buildTED func() *table.LsTED
		src, dst string
		metric   table.MetricType
		scope    cspf.PathScope
		want     []table.Segment
	}{
		{
			name: "source equal to destination returns an empty segment list",
			buildTED: func() *table.LsTED {
				return buildTED(srMPLSNode("A", 0))
			},
			src: "A", dst: "A", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{},
		},
		{
			name: "IGP metric selects the lowest cumulative cost path over a longer detour",
			buildTED: func() *table.LsTED {
				a, b, c, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("C", 2), srMPLSNode("D", 3)
				connectV4(a, b, 1)
				connectV4(b, d, 1)
				connectV4(a, c, 3)
				connectV4(c, d, 1)

				return buildTED(a, b, c, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(1), mplsSeg(3)},
		},
		{
			name: "IGP metric prefers the cheaper multi-hop path over a costly shortcut",
			buildTED: func() *table.LsTED {
				a, b, e, f, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("E", 4), srMPLSNode("F", 5), srMPLSNode("D", 3)
				connectV4(a, b, 100)
				connectV4(b, d, 100)
				connectV4(a, e, 1)
				connectV4(e, f, 1)
				connectV4(f, d, 1)

				return buildTED(a, b, e, f, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(4), mplsSeg(5), mplsSeg(3)},
		},
		{
			name: "hopcount metric ignores link weights and picks the fewest hops",
			buildTED: func() *table.LsTED {
				a, b, e, f, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("E", 4), srMPLSNode("F", 5), srMPLSNode("D", 3)
				connectV4(a, b, 100)
				connectV4(b, d, 100)
				connectV4(a, e, 1)
				connectV4(e, f, 1)
				connectV4(f, d, 1)

				return buildTED(a, b, e, f, d)
			},
			src: "A", dst: "D", metric: table.HopcountMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(1), mplsSeg(3)},
		},
		{
			name: "a cheaper path to an already-discovered node replaces the recorded cost",
			buildTED: func() *table.LsTED {
				a, b, c, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("C", 2), srMPLSNode("D", 3)
				connectV4(a, b, 1)
				connectV4(a, c, 2)
				connectV4(b, d, 10)
				connectV4(c, d, 1)

				return buildTED(a, b, c, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(2), mplsSeg(3)},
		},
		{
			name: "a costlier path to an already-discovered node keeps the recorded cost",
			buildTED: func() *table.LsTED {
				a, b, c, d, e := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("C", 2), srMPLSNode("D", 3), srMPLSNode("E", 4)
				connectV4(a, b, 1)
				connectV4(a, c, 3)
				connectV4(b, d, 1)
				connectV4(c, d, 1)
				connectV4(d, e, 5)

				return buildTED(a, b, c, d, e)
			},
			src: "A", dst: "E", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(1), mplsSeg(3), mplsSeg(4)},
		},
		{
			name: "IPv6 SR-MPLS node segments are used end-to-end",
			buildTED: func() *table.LsTED {
				a, b := srMPLSNodeV6("A", 0), srMPLSNodeV6("B", 1)
				connectV6(a, b, 1)

				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV6SRMPLS,
			want: []table.Segment{mplsSeg(1)},
		},
		{
			name: "SRv6 node segments are used end-to-end",
			buildTED: func() *table.LsTED {
				a, b := srv6Node("A", "2001:db8::a"), srv6Node("B", "2001:db8::b")
				connectV6(a, b, 1)

				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV6SRv6,
			want: []table.Segment{srv6DefaultSeg("2001:db8::b")},
		},
		{
			name: "mixed SR-MPLS/SRv6 TED resolves SR-MPLS labels under an SR-MPLS scope",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				connectV6(a, b, 1)

				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV6SRMPLS,
			want: []table.Segment{mplsSeg(11)},
		},
		{
			name: "mixed SR-MPLS/SRv6 TED resolves SRv6 SIDs under an SRv6 scope",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				connectV6(a, b, 1)

				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV6SRv6,
			want: []table.Segment{srv6DefaultSeg("2001:db8::b")},
		},
		{
			name: "dual-stack routers with per-family parallel links use the IPv4 label under an IPv4 scope",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				connectV4(a, b, 10)
				connectV6(a, b, 100)

				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(1)},
		},
		{
			name: "dual-stack routers with per-family parallel links use the IPv6 label under an IPv6 scope",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				connectV4(a, b, 10)
				connectV6(a, b, 100)

				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV6SRMPLS,
			want: []table.Segment{mplsSeg(11)},
		},
		{
			name: "multi-topology per-family metrics are not conflated across parallel transit paths",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				p1 := dualStackNode("P1", 2, 12, "2001:db8::c") // true IPv4 cost 10
				p2 := dualStackNode("P2", 3, 13, "2001:db8::d") // true IPv4 cost 200, IPv6 cost 1

				connectMultiTopo(a, p1, 0, 10)
				connectMultiTopo(a, p1, 2, 500)
				connectMultiTopo(p1, b, 0, 10)
				connectMultiTopo(p1, b, 2, 500)

				connectMultiTopo(a, p2, 0, 200)
				connectMultiTopo(a, p2, 2, 1)
				connectMultiTopo(p2, b, 0, 200)
				connectMultiTopo(p2, b, 2, 1)

				return buildTED(a, b, p1, p2)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(2), mplsSeg(1)},
		},
		{
			name: "multi-topology per-family metrics are not conflated across parallel transit paths (IPv6)",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				p1 := dualStackNode("P1", 2, 12, "2001:db8::c") // true IPv4 cost 1, IPv6 cost 500
				p2 := dualStackNode("P2", 3, 13, "2001:db8::d") // true IPv6 cost 10

				connectMultiTopo(a, p1, 0, 1)
				connectMultiTopo(a, p1, 2, 500)
				connectMultiTopo(p1, b, 0, 1)
				connectMultiTopo(p1, b, 2, 500)

				connectMultiTopo(a, p2, 0, 500)
				connectMultiTopo(a, p2, 2, 10)
				connectMultiTopo(p2, b, 0, 500)
				connectMultiTopo(p2, b, 2, 10)

				return buildTED(a, b, p1, p2)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV6SRMPLS,
			want: []table.Segment{mplsSeg(13), mplsSeg(11)},
		},
		{
			name: "an IPv6 scope never selects a cheaper IPv4-only edge",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				c := srMPLSNodeV6("C", 12)

				connectV4(a, b, 1)
				connectV6(a, c, 5)
				connectV6(c, b, 5)

				return buildTED(a, b, c)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV6SRMPLS,
			want: []table.Segment{mplsSeg(12), mplsSeg(11)},
		},
		{
			name: "an IPv4 scope on the same mixed topology takes the direct IPv4 edge",
			buildTED: func() *table.LsTED {
				a := dualStackNode("A", 0, 10, "2001:db8::a")
				b := dualStackNode("B", 1, 11, "2001:db8::b")
				c := srMPLSNodeV6("C", 12)

				connectV4(a, b, 1)
				connectV6(a, c, 5)
				connectV6(c, b, 5)

				return buildTED(a, b, c)
			},
			src: "A", dst: "B", metric: table.IGPMetric, scope: scopeV4SRMPLS,
			want: []table.Segment{mplsSeg(1)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ted := tt.buildTED()
			got, err := cspf.CSPF(tt.src, tt.dst, tt.metric, tt.scope, ted)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCSPF_PlaneScopingUnreachable(t *testing.T) {
	t.Parallel()

	a := dualStackNode("A", 0, 10, "2001:db8::a")
	b := srMPLSNode("B", 1) // IPv4-only node
	connectV4(a, b, 1)
	ted := buildTED(a, b)

	got, err := cspf.CSPF("A", "B", table.IGPMetric, scopeV6SRMPLS, ted)
	assert.Nil(t, got)
	require.Error(t, err)

	var topoErr *cspf.TopologyLimitationError
	require.ErrorAs(t, err, &topoErr)
	assert.Equal(t, "DESTINATION_UNREACHABLE", topoErr.Reason)
}

func TestCSPF_EndpointFamilyIndependentOfUnderlay(t *testing.T) {
	t.Parallel()

	a := dualStackNode("A", 0, 10, "2001:db8::a")
	b := dualStackNode("B", 1, 11, "2001:db8::b")
	connectV6(a, b, 1)
	ted := buildTED(a, b)

	t.Run("I8: IPv4 endpoint over an IPv6 SR-MPLS underlay", func(t *testing.T) {
		t.Parallel()

		segs, err := cspf.CSPF("A", "B", table.IGPMetric, scopeV6SRMPLS, ted)
		require.NoError(t, err)
		assert.Equal(t, []table.Segment{mplsSeg(11)}, segs)

		endpoint, err := b.LoopbackAddr(table.AFIPv4)
		require.NoError(t, err)
		assert.Equal(t, netip.MustParseAddr("192.0.2.1"), endpoint)
	})

	t.Run("I9: IPv6 endpoint over an IPv4 SR-MPLS underlay", func(t *testing.T) {
		t.Parallel()

		connectV4(a, b, 1)

		segs, err := cspf.CSPF("A", "B", table.IGPMetric, scopeV4SRMPLS, ted)
		require.NoError(t, err)
		assert.Equal(t, []table.Segment{mplsSeg(1)}, segs)

		endpoint, err := b.LoopbackAddr(table.AFIPv6)
		require.NoError(t, err)
		assert.Equal(t, netip.MustParseAddr("2001:db8::1"), endpoint)
	})
}

func TestCSPF_MetricValidation(t *testing.T) {
	t.Parallel()

	linked := func() *table.LsTED {
		a, b := srMPLSNode("A", 0), srMPLSNode("B", 1)
		connect(a, b)

		return buildTED(a, b)
	}

	t.Run("an unrecognized metric type is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "B", table.MetricType(99), scopeV4SRMPLS, linked())
		assert.EqualError(t, err, "unsupported metric type 99")
	})

	t.Run("the unspecified metric is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "B", table.UnspecifiedMetric, scopeV4SRMPLS, linked())
		assert.EqualError(t, err, "metric type must be specified for path computation")
	})

	t.Run("an unrecognized metric is rejected even when source equals destination", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "A", table.MetricType(99), scopeV4SRMPLS, linked())
		assert.EqualError(t, err, "unsupported metric type 99")
	})

	t.Run("loose source routing rejects the metric before checking waypoints", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: testGhostRouterID}}
		_, err := cspf.WithLooseSourceRouting("A", "B", waypoints, table.MetricType(99), scopeV4SRMPLS, linked())
		assert.EqualError(t, err, "unsupported metric type 99")
	})

	t.Run("a nil TED is reported before the metric", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "B", table.MetricType(99), scopeV4SRMPLS, nil)
		assert.EqualError(t, err, "ted is nil")
	})
}

func TestCSPF_ScopeValidation(t *testing.T) {
	t.Parallel()

	linked := func() *table.LsTED {
		a, b := srMPLSNode("A", 0), srMPLSNode("B", 1)
		connect(a, b)

		return buildTED(a, b)
	}

	t.Run("an unspecified plane is rejected by CSPF", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "B", table.IGPMetric, cspf.PathScope{}, linked())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid scope")

		var invalidInput *cspf.InvalidInputError
		require.ErrorAs(t, err, &invalidInput)
	})

	t.Run("an unspecified plane is rejected by WithLooseSourceRouting", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.WithLooseSourceRouting("A", "B", nil, table.IGPMetric, cspf.PathScope{}, linked())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid scope")
	})

	t.Run("SRv6 over IPv4 is rejected", func(t *testing.T) {
		t.Parallel()

		invalidScope := cspf.PathScope{Plane: table.Plane{Family: table.AFIPv4, DataPlane: table.DPSRv6}}
		_, err := cspf.CSPF("A", "B", table.IGPMetric, invalidScope, linked())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid scope")
	})
}

func TestCSPF_InvalidInputClassification(t *testing.T) {
	t.Parallel()

	linear := func() *table.LsTED {
		a, b := srMPLSNode("A", 0), srMPLSNode("B", 1)
		connect(a, b)

		return buildTED(a, b)
	}

	tests := []struct {
		name        string
		run         func() error
		wantInvalid bool
	}{
		{"unknown source router is caller input", func() error { _, err := cspf.CSPF("Z", "B", table.IGPMetric, scopeV4SRMPLS, linear()); return err }, true},
		{"unknown destination router is caller input", func() error { _, err := cspf.CSPF("A", "Z", table.IGPMetric, scopeV4SRMPLS, linear()); return err }, true},
		{"unknown waypoint is caller input", func() error {
			_, err := cspf.WithLooseSourceRouting("A", "B", []table.Waypoint{{RouterID: "Z"}}, table.IGPMetric, scopeV4SRMPLS, linear())
			return err
		}, true},
		{"malformed explicit waypoint SID is caller input", func() error {
			_, err := cspf.WithLooseSourceRouting("A", "B", []table.Waypoint{{RouterID: "B", SID: testInvalidSID}}, table.IGPMetric, scopeV4SRMPLS, linear())
			return err
		}, true},
		{"unusable metric is caller input", func() error {
			_, err := cspf.CSPF("A", "B", table.UnspecifiedMetric, scopeV4SRMPLS, linear())
			return err
		}, true},
		{"an invalid scope is caller input", func() error { _, err := cspf.CSPF("A", "B", table.IGPMetric, cspf.PathScope{}, linear()); return err }, true},
		{"an unreachable destination is not caller input", func() error {
			_, err := cspf.CSPF("A", "B", table.IGPMetric, scopeV4SRMPLS, buildTED(srMPLSNode("A", 0), srMPLSNode("B", 1)))
			return err
		}, false},
		{"a metric absent from a traversed link is not caller input", func() error { _, err := cspf.CSPF("A", "B", table.TEMetric, scopeV4SRMPLS, linear()); return err }, false},
		{"a node without a Node SID is not caller input", func() error {
			a, b := nodeWithoutSID("A"), srMPLSNode("B", 0)
			connect(a, b)
			_, err := cspf.CSPF("A", "B", table.IGPMetric, scopeV4SRMPLS, buildTED(a, b))

			return err
		}, false},
		{"a nil TED is not classified as caller input", func() error { _, err := cspf.CSPF("A", "B", table.IGPMetric, scopeV4SRMPLS, nil); return err }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.run()
			require.Error(t, err)

			var invalidInput *cspf.InvalidInputError
			assert.Equal(t, tt.wantInvalid, errors.As(err, &invalidInput))
		})
	}
}

func TestCSPF_NilTED(t *testing.T) {
	t.Parallel()

	_, err := cspf.CSPF("A", "B", table.IGPMetric, scopeV4SRMPLS, nil)
	require.EqualError(t, err, "ted is nil")

	_, err = cspf.WithLooseSourceRouting("A", "B", nil, table.IGPMetric, scopeV4SRMPLS, nil)
	assert.EqualError(t, err, "ted is nil")
}

func TestInvalidInputError_Unwrap(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	err := &cspf.InvalidInputError{Err: sentinel}

	assert.Same(t, sentinel, errors.Unwrap(err))
	assert.ErrorIs(t, err, sentinel)
}

func TestTopologyLimitationError_Unwrap(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	err := &cspf.TopologyLimitationError{Err: sentinel}

	assert.Same(t, sentinel, errors.Unwrap(err))
	assert.ErrorIs(t, err, sentinel)
}

func TestWithLooseSourceRouting(t *testing.T) {
	t.Parallel()

	linearChain := func() *table.LsTED {
		s, w1, m, w2, d := srMPLSNode("S", 0), srMPLSNode("W1", 1), srMPLSNode("M", 2), srMPLSNode("W2", 3), srMPLSNode("D", 4)
		connect(s, w1)
		connect(w1, m)
		connect(m, w2)
		connect(w2, d)

		return buildTED(s, w1, m, w2, d)
	}
	fullChainSegs := []table.Segment{mplsSeg(1), mplsSeg(2), mplsSeg(3), mplsSeg(4)}

	t.Run("no waypoints behaves like a direct CSPF call", func(t *testing.T) {
		t.Parallel()

		got, err := cspf.WithLooseSourceRouting("S", "D", nil, table.IGPMetric, scopeV4SRMPLS, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("a waypoint already on the shortest path does not duplicate its segment", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: "W1"}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, scopeV4SRMPLS, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("multiple ordered waypoints route through each waypoint in sequence", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: "W1"}, {RouterID: "W2"}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, scopeV4SRMPLS, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("an explicit waypoint SID that differs from the node's default is kept as a separate segment", func(t *testing.T) {
		t.Parallel()

		s2, w, d2 := srv6Node("S2", "2001:db8::1"), srv6Node("W", "2001:db8::2"), srv6Node("D2", "2001:db8::3")
		connectV6(s2, w, 1)
		connectV6(w, d2, 1)
		ted := buildTED(s2, w, d2)

		waypoints := []table.Waypoint{{RouterID: "W", SID: "2001:db8::2ff"}}
		got, err := cspf.WithLooseSourceRouting("S2", "D2", waypoints, table.IGPMetric, scopeV6SRv6, ted)
		require.NoError(t, err)

		want := []table.Segment{
			srv6DefaultSeg("2001:db8::2"),
			table.SegmentSRv6{
				Sid:       table.SRv6SID(netip.MustParseAddr("2001:db8::2ff")),
				LocalAddr: netip.MustParseAddr("2001:db8::2"),
				Behavior:  table.BehaviorEND,
				Structure: &table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16},
			},
			srv6DefaultSeg("2001:db8::3"),
		}
		assert.Equal(t, want, got)
	})

	t.Run("an explicit SR-MPLS waypoint SID that differs from the node's default is kept as a separate segment", func(t *testing.T) {
		t.Parallel()

		s5, w5, d5 := srMPLSNode("S5", 0), srMPLSNode("W5", 1), srMPLSNode("D5", 2)
		connect(s5, w5)
		connect(w5, d5)
		ted := buildTED(s5, w5, d5)

		waypoints := []table.Waypoint{{RouterID: "W5", SID: "20000"}}
		got, err := cspf.WithLooseSourceRouting("S5", "D5", waypoints, table.IGPMetric, scopeV4SRMPLS, ted)
		require.NoError(t, err)

		want := []table.Segment{
			mplsSeg(1),
			table.NewSegmentSRMPLS(20000),
			mplsSeg(2),
		}
		assert.Equal(t, want, got)
	})

	t.Run("a leg computation failure is wrapped with the router pair", func(t *testing.T) {
		t.Parallel()

		ted := buildTED(srMPLSNode("S3", 0))
		got, err := cspf.WithLooseSourceRouting("S3", "D3", nil, table.IGPMetric, scopeV4SRMPLS, ted)
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CSPF failed between S3 and D3")
	})

	t.Run("a waypoint absent from the TED node map is rejected before any section is computed", func(t *testing.T) {
		t.Parallel()
		// Intentionally leaves GHOST out of ted.Nodes while keeping it on the link.
		s4 := srMPLSNode("S4", 0)
		ghost := srMPLSNode(testGhostRouterID, 1)
		connect(s4, ghost)
		ted := buildTED(s4)

		waypoints := []table.Waypoint{{RouterID: testGhostRouterID}}
		got, err := cspf.WithLooseSourceRouting("S4", testGhostRouterID, waypoints, table.IGPMetric, scopeV4SRMPLS, ted)
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "waypoint router GHOST not found in TED")
	})

	t.Run("an unknown waypoint is rejected even when the destination is reachable", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: testGhostRouterID}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, scopeV4SRMPLS, linearChain())
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "waypoint router GHOST not found in TED")
	})

	t.Run("an invalid explicit waypoint SID is wrapped with the router", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: "W1", SID: testInvalidSID}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, scopeV4SRMPLS, linearChain())
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to build segment for waypoint W1")
	})
}

func TestWithLooseSourceRouting_PlaneScoping(t *testing.T) {
	t.Parallel()

	a := dualStackNode("A", 0, 10, "2001:db8::a")
	b := dualStackNode("B", 1, 11, "2001:db8::b")
	w := srv6Node("W", "2001:db8::9")

	connectV4(a, b, 1)
	connectV6(a, w, 5)
	connectV6(w, b, 5)
	ted := buildTED(a, b, w)

	waypoints := []table.Waypoint{{RouterID: "W"}}
	got, err := cspf.WithLooseSourceRouting("A", "B", waypoints, table.IGPMetric, scopeV6SRv6, ted)
	require.NoError(t, err)

	want := []table.Segment{
		srv6DefaultSeg("2001:db8::9"),
		srv6DefaultSeg("2001:db8::b"),
	}
	assert.Equal(t, want, got)
}
