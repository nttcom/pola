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

// srMPLSNode uses an SRGB starting at 16000.
func srMPLSNode(routerID string, sidIndex uint32) *table.LsNode {
	return &table.LsNode{
		RouterID:  routerID,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{SidIndex: sidIndex, HasSidIndex: true},
		},
	}
}

func mplsSeg(sidIndex uint32) table.Segment {
	return table.NewSegmentSRMPLS(16000 + sidIndex)
}

// srv6Node returns a node advertising an End SID with a 32/16/16/0 SID structure.
func srv6Node(routerID, sid string) *table.LsNode {
	return &table.LsNode{
		RouterID: routerID,
		SRv6SIDs: []*table.LsSrv6SID{
			{
				Sids:             []string{sid},
				EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorEND},
				SIDStructure:     table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
			},
		},
	}
}

func srv6DefaultSeg(sid string) table.SegmentSRv6 {
	addr := netip.MustParseAddr(sid)

	return table.SegmentSRv6{
		Sid:       addr,
		LocalAddr: addr,
		Structure: table.SIDStructureBytes{32, 16, 16, 0},
	}
}

func nodeWithoutSID(routerID string) *table.LsNode {
	return &table.LsNode{RouterID: routerID}
}

func connect(local, remote *table.LsNode, igpCost uint32) {
	local.Links = append(local.Links, &table.LsLink{
		LocalNode:  local,
		RemoteNode: remote,
		Metrics:    []*table.Metric{table.NewMetric(table.IGPMetric, igpCost)},
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
		want     []table.Segment
	}{
		{
			name: "source equal to destination returns an empty segment list",
			buildTED: func() *table.LsTED {
				return buildTED(srMPLSNode("A", 0))
			},
			src: "A", dst: "A", metric: table.IGPMetric,
			want: []table.Segment{},
		},
		{
			name: "IGP metric selects the lowest cumulative cost path over a longer detour",
			buildTED: func() *table.LsTED {
				a, b, c, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("C", 2), srMPLSNode("D", 3)
				connect(a, b, 1)
				connect(b, d, 1)
				connect(a, c, 3)
				connect(c, d, 1)

				return buildTED(a, b, c, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric,
			want: []table.Segment{mplsSeg(1), mplsSeg(3)},
		},
		{
			name: "IGP metric prefers the cheaper multi-hop path over a costly shortcut",
			buildTED: func() *table.LsTED {
				a, b, e, f, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("E", 4), srMPLSNode("F", 5), srMPLSNode("D", 3)
				connect(a, b, 100)
				connect(b, d, 100)
				connect(a, e, 1)
				connect(e, f, 1)
				connect(f, d, 1)

				return buildTED(a, b, e, f, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric,
			want: []table.Segment{mplsSeg(4), mplsSeg(5), mplsSeg(3)},
		},
		{
			name: "hopcount metric ignores link weights and picks the fewest hops",
			buildTED: func() *table.LsTED {
				a, b, e, f, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("E", 4), srMPLSNode("F", 5), srMPLSNode("D", 3)
				connect(a, b, 100)
				connect(b, d, 100)
				connect(a, e, 1)
				connect(e, f, 1)
				connect(f, d, 1)

				return buildTED(a, b, e, f, d)
			},
			src: "A", dst: "D", metric: table.HopcountMetric,
			want: []table.Segment{mplsSeg(1), mplsSeg(3)},
		},
		{
			name: "a cheaper path to an already-discovered node replaces the recorded cost",
			buildTED: func() *table.LsTED {
				a, b, c, d := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("C", 2), srMPLSNode("D", 3)
				connect(a, b, 1)
				connect(a, c, 2)
				connect(b, d, 10)
				connect(c, d, 1)

				return buildTED(a, b, c, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric,
			want: []table.Segment{mplsSeg(2), mplsSeg(3)},
		},
		{
			name: "a costlier path to an already-discovered node keeps the recorded cost",
			buildTED: func() *table.LsTED {
				a, b, c, d, e := srMPLSNode("A", 0), srMPLSNode("B", 1), srMPLSNode("C", 2), srMPLSNode("D", 3), srMPLSNode("E", 4)
				connect(a, b, 1)
				connect(a, c, 3)
				connect(b, d, 1)
				connect(c, d, 1)
				connect(d, e, 5)

				return buildTED(a, b, c, d, e)
			},
			src: "A", dst: "E", metric: table.IGPMetric,
			want: []table.Segment{mplsSeg(1), mplsSeg(3), mplsSeg(4)},
		},
		{
			name: "SRv6 node segments are used end-to-end",
			buildTED: func() *table.LsTED {
				a, b := srv6Node("A", "2001:db8::a"), srv6Node("B", "2001:db8::b")
				connect(a, b, 1)

				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric,
			want: []table.Segment{srv6DefaultSeg("2001:db8::b")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ted := tt.buildTED()
			got, err := cspf.CSPF(tt.src, tt.dst, tt.metric, ted)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCSPF_MetricValidation(t *testing.T) {
	t.Parallel()

	linked := func() *table.LsTED {
		a, b := srMPLSNode("A", 0), srMPLSNode("B", 1)
		connect(a, b, 1)

		return buildTED(a, b)
	}

	t.Run("an unrecognized metric type is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "B", table.MetricType(99), linked())
		assert.EqualError(t, err, "unsupported metric type 99")
	})

	t.Run("the unspecified metric is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "B", table.UnspecifiedMetric, linked())
		assert.EqualError(t, err, "metric type must be specified for path computation")
	})

	t.Run("an unrecognized metric is rejected even when source equals destination", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "A", table.MetricType(99), linked())
		assert.EqualError(t, err, "unsupported metric type 99")
	})

	t.Run("loose source routing rejects the metric before checking waypoints", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: testGhostRouterID}}
		_, err := cspf.WithLooseSourceRouting("A", "B", waypoints, table.MetricType(99), linked())
		assert.EqualError(t, err, "unsupported metric type 99")
	})

	t.Run("a nil TED is reported before the metric", func(t *testing.T) {
		t.Parallel()

		_, err := cspf.CSPF("A", "B", table.MetricType(99), nil)
		assert.EqualError(t, err, "ted is nil")
	})
}

func TestCSPF_InvalidInputClassification(t *testing.T) {
	t.Parallel()

	linear := func() *table.LsTED {
		a, b := srMPLSNode("A", 0), srMPLSNode("B", 1)
		connect(a, b, 1)

		return buildTED(a, b)
	}

	tests := []struct {
		name        string
		run         func() error
		wantInvalid bool
	}{
		{"unknown source router is caller input", func() error { _, err := cspf.CSPF("Z", "B", table.IGPMetric, linear()); return err }, true},
		{"unknown destination router is caller input", func() error { _, err := cspf.CSPF("A", "Z", table.IGPMetric, linear()); return err }, true},
		{"unknown waypoint is caller input", func() error {
			_, err := cspf.WithLooseSourceRouting("A", "B", []table.Waypoint{{RouterID: "Z"}}, table.IGPMetric, linear())
			return err
		}, true},
		{"malformed explicit waypoint SID is caller input", func() error {
			_, err := cspf.WithLooseSourceRouting("A", "B", []table.Waypoint{{RouterID: "B", SID: testInvalidSID}}, table.IGPMetric, linear())
			return err
		}, true},
		{"unusable metric is caller input", func() error { _, err := cspf.CSPF("A", "B", table.UnspecifiedMetric, linear()); return err }, true},
		{"an unreachable destination is not caller input", func() error {
			_, err := cspf.CSPF("A", "B", table.IGPMetric, buildTED(srMPLSNode("A", 0), srMPLSNode("B", 1)))
			return err
		}, false},
		{"a metric absent from a traversed link is not caller input", func() error { _, err := cspf.CSPF("A", "B", table.TEMetric, linear()); return err }, false},
		{"a node without a Node SID is not caller input", func() error {
			a, b := nodeWithoutSID("A"), srMPLSNode("B", 0)
			connect(a, b, 1)
			_, err := cspf.CSPF("A", "B", table.IGPMetric, buildTED(a, b))

			return err
		}, false},
		{"a nil TED is not classified as caller input", func() error { _, err := cspf.CSPF("A", "B", table.IGPMetric, nil); return err }, false},
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

	_, err := cspf.CSPF("A", "B", table.IGPMetric, nil)
	require.EqualError(t, err, "ted is nil")

	_, err = cspf.WithLooseSourceRouting("A", "B", nil, table.IGPMetric, nil)
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
		connect(s, w1, 1)
		connect(w1, m, 1)
		connect(m, w2, 1)
		connect(w2, d, 1)

		return buildTED(s, w1, m, w2, d)
	}
	fullChainSegs := []table.Segment{mplsSeg(1), mplsSeg(2), mplsSeg(3), mplsSeg(4)}

	t.Run("no waypoints behaves like a direct CSPF call", func(t *testing.T) {
		t.Parallel()

		got, err := cspf.WithLooseSourceRouting("S", "D", nil, table.IGPMetric, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("a waypoint already on the shortest path does not duplicate its segment", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: "W1"}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("multiple ordered waypoints route through each waypoint in sequence", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: "W1"}, {RouterID: "W2"}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("an explicit waypoint SID that differs from the node's default is kept as a separate segment", func(t *testing.T) {
		t.Parallel()

		s2, w, d2 := srv6Node("S2", "2001:db8::1"), srv6Node("W", "2001:db8::2"), srv6Node("D2", "2001:db8::3")
		connect(s2, w, 1)
		connect(w, d2, 1)
		ted := buildTED(s2, w, d2)

		waypoints := []table.Waypoint{{RouterID: "W", SID: "2001:db8::2ff"}}
		got, err := cspf.WithLooseSourceRouting("S2", "D2", waypoints, table.IGPMetric, ted)
		require.NoError(t, err)

		want := []table.Segment{
			srv6DefaultSeg("2001:db8::2"),
			table.SegmentSRv6{
				Sid:       netip.MustParseAddr("2001:db8::2ff"),
				LocalAddr: netip.MustParseAddr("2001:db8::2"),
				Structure: table.SIDStructureBytes{32, 16, 16, 0},
			},
			srv6DefaultSeg("2001:db8::3"),
		}
		assert.Equal(t, want, got)
	})

	t.Run("a leg computation failure is wrapped with the router pair", func(t *testing.T) {
		t.Parallel()

		ted := buildTED(srMPLSNode("S3", 0))
		got, err := cspf.WithLooseSourceRouting("S3", "D3", nil, table.IGPMetric, ted)
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CSPF failed between S3 and D3")
	})

	t.Run("a waypoint absent from the TED node map is rejected before any section is computed", func(t *testing.T) {
		t.Parallel()
		// Intentionally leaves GHOST out of ted.Nodes while keeping it on the link.
		s4 := srMPLSNode("S4", 0)
		ghost := srMPLSNode(testGhostRouterID, 1)
		connect(s4, ghost, 1)
		ted := buildTED(s4)

		waypoints := []table.Waypoint{{RouterID: testGhostRouterID}}
		got, err := cspf.WithLooseSourceRouting("S4", testGhostRouterID, waypoints, table.IGPMetric, ted)
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "waypoint router GHOST not found in TED")
	})

	t.Run("an unknown waypoint is rejected even when the destination is reachable", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: testGhostRouterID}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "waypoint router GHOST not found in TED")
	})

	t.Run("an invalid explicit waypoint SID is wrapped with the router", func(t *testing.T) {
		t.Parallel()

		waypoints := []table.Waypoint{{RouterID: "W1", SID: testInvalidSID}}
		got, err := cspf.WithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to build segment for waypoint W1")
	})
}
