// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package cspf

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
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
			ted := tt.buildTED()
			got, err := CSPF(tt.src, tt.dst, tt.metric, ted)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCSPF_Errors(t *testing.T) {
	tests := []struct {
		name     string
		buildTED func() *table.LsTED
		src, dst string
		metric   table.MetricType
		wantErr  string
	}{
		{
			name: "requested metric is not defined on a traversed link",
			buildTED: func() *table.LsTED {
				a, b := srMPLSNode("A", 0), srMPLSNode("B", 1)
				connect(a, b, 1)
				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.TEMetric,
			wantErr: "metric METRIC_TYPE_TE not defined",
		},
		{
			name: "source node has no Node SID",
			buildTED: func() *table.LsTED {
				a, b := nodeWithoutSID("A"), srMPLSNode("B", 0)
				connect(a, b, 1)
				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric,
			wantErr: "node doesn't have a Node SID",
		},
		{
			name: "a newly discovered neighbor has no Node SID",
			buildTED: func() *table.LsTED {
				a, b := srMPLSNode("A", 0), nodeWithoutSID("B")
				connect(a, b, 1)
				return buildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric,
			wantErr: "node doesn't have a Node SID",
		},
		{
			name: "destination router is absent from the TED",
			buildTED: func() *table.LsTED {
				return buildTED(srMPLSNode("A", 0))
			},
			src: "A", dst: "Z", metric: table.IGPMetric,
			wantErr: "destination router Z not found in TED",
		},
		{
			name: "destination is unreachable from the source",
			buildTED: func() *table.LsTED {
				return buildTED(srMPLSNode("A", 0), srMPLSNode("B", 1))
			},
			src: "A", dst: "B", metric: table.IGPMetric,
			wantErr: "next node not found",
		},
		{
			name: "source router is absent from the TED",
			buildTED: func() *table.LsTED {
				return buildTED(srMPLSNode("A", 0))
			},
			src: "Z", dst: "A", metric: table.IGPMetric,
			wantErr: "source router Z not found in TED",
		},
		{
			name: "source router check takes priority when both endpoints are absent",
			buildTED: func() *table.LsTED {
				return buildTED(srMPLSNode("A", 0))
			},
			src: "Y", dst: "Z", metric: table.IGPMetric,
			wantErr: "source router Y not found in TED",
		},
		{
			name: "a router registered as a nil node is treated as absent from the TED",
			buildTED: func() *table.LsTED {
				return &table.LsTED{Nodes: map[string]*table.LsNode{"A": nil}}
			},
			src: "A", dst: "A", metric: table.IGPMetric,
			wantErr: "source router A not found in TED",
		},
		{
			name: "a dangling adjacency reached during exploration does not panic",
			buildTED: func() *table.LsTED {
				// GHOST is deliberately left out of ted.Nodes while remaining on the links,
				// simulating a TED inconsistency.
				a, ghost, d := srMPLSNode("A", 0), srMPLSNode("GHOST", 1), srMPLSNode("D", 3)
				connect(a, ghost, 1)
				connect(ghost, d, 1)
				return buildTED(a, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric,
			wantErr: "next node not found",
		},
		{
			name: "a link with a nil remote node is skipped instead of panicking",
			buildTED: func() *table.LsTED {
				a, d := srMPLSNode("A", 0), srMPLSNode("D", 3)
				a.Links = append(a.Links, &table.LsLink{LocalNode: a, RemoteNode: nil})
				return buildTED(a, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric,
			wantErr: "next node not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ted := tt.buildTED()
			got, err := CSPF(tt.src, tt.dst, tt.metric, ted)
			assert.Nil(t, got)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestCSPF_NilTED(t *testing.T) {
	_, err := CSPF("A", "B", table.IGPMetric, nil)
	assert.EqualError(t, err, "ted is nil")

	_, err = CSPFWithLooseSourceRouting("A", "B", nil, table.IGPMetric, nil)
	assert.EqualError(t, err, "ted is nil")
}

func TestUpdateNeighborCosts_UnknownCalcNode(t *testing.T) {
	err := updateNeighborCosts("Z", map[string]*node{}, map[string]*table.LsNode{}, table.IGPMetric)
	assert.EqualError(t, err, "router Z not found in TED")
}

func TestBuildWaypointSegment(t *testing.T) {
	tests := []struct {
		name        string
		node        *table.LsNode
		explicitSID string
		want        table.Segment
		wantErr     string
	}{
		{
			name:        "empty SID falls back to the node's default SR-MPLS segment",
			node:        srMPLSNode("A", 0),
			explicitSID: "",
			want:        mplsSeg(0),
		},
		{
			name:        "empty SID falls back to the node's default SRv6 segment",
			node:        srv6Node("A", "2001:db8::a"),
			explicitSID: "",
			want:        srv6DefaultSeg("2001:db8::a"),
		},
		{
			name:        "empty SID returns an error when the node has no Node SID",
			node:        nodeWithoutSID("A"),
			explicitSID: "",
			wantErr:     "node doesn't have a Node SID",
		},
		{
			name:        "explicit SID overrides the SID but keeps the node's SID structure",
			node:        srv6Node("A", "2001:db8::a"),
			explicitSID: "2001:db8::ffff",
			want: table.SegmentSRv6{
				Sid:       netip.MustParseAddr("2001:db8::ffff"),
				LocalAddr: netip.MustParseAddr("2001:db8::a"),
				Structure: table.SIDStructureBytes{32, 16, 16, 0},
			},
		},
		{
			// RFC 8986: BehaviorUN indicates a uSID carrier and must set USid=true.
			name: "explicit SID on a uSID node sets the uSID flag",
			node: &table.LsNode{
				RouterID: "A",
				SRv6SIDs: []*table.LsSrv6SID{
					{
						Sids:             []string{"2001:db8::a"},
						EndpointBehavior: table.EndpointBehavior{Behavior: table.BehaviorUN},
						SIDStructure:     table.SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
					},
				},
			},
			explicitSID: "2001:db8::ffff",
			want: table.SegmentSRv6{
				Sid:       netip.MustParseAddr("2001:db8::ffff"),
				LocalAddr: netip.MustParseAddr("2001:db8::a"),
				Structure: table.SIDStructureBytes{32, 16, 16, 0},
				USid:      true,
			},
		},
		{
			name:        "invalid explicit SID returns a parse error",
			node:        srMPLSNode("A", 0),
			explicitSID: "not-an-address",
			wantErr:     `invalid explicit SID "not-an-address": ParseAddr("not-an-address"): unable to parse IP`,
		},
		{
			name:        "explicit SID on a node without any SRv6 SIDs returns an error",
			node:        srMPLSNode("A", 0),
			explicitSID: "2001:db8::ffff",
			wantErr:     "no SRv6 SIDs available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildWaypointSegment(tt.node, tt.explicitSID)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRemoveDuplicateFirst(t *testing.T) {
	segX := table.NewSegmentSRMPLS(100)
	segY := table.NewSegmentSRMPLS(200)

	tests := []struct {
		name     string
		fullList []table.Segment
		section  []table.Segment
		want     []table.Segment
	}{
		{
			name:     "empty fullList leaves the section unchanged",
			fullList: nil,
			section:  []table.Segment{segX, segY},
			want:     []table.Segment{segX, segY},
		},
		{
			name:     "empty section stays empty",
			fullList: []table.Segment{segX},
			section:  []table.Segment{},
			want:     []table.Segment{},
		},
		{
			name:     "section's first segment duplicating fullList's last is dropped",
			fullList: []table.Segment{segX},
			section:  []table.Segment{table.NewSegmentSRMPLS(100), segY},
			want:     []table.Segment{segY},
		},
		{
			name:     "section's first segment differing from fullList's last is kept",
			fullList: []table.Segment{segX},
			section:  []table.Segment{segY},
			want:     []table.Segment{segY},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, removeDuplicateFirst(tt.fullList, tt.section))
		})
	}
}

func TestAppendIfNotDuplicate(t *testing.T) {
	segX := table.NewSegmentSRMPLS(100)
	segY := table.NewSegmentSRMPLS(200)

	tests := []struct {
		name string
		list []table.Segment
		seg  table.Segment
		want []table.Segment
	}{
		{
			name: "appends to an empty list",
			list: nil,
			seg:  segX,
			want: []table.Segment{segX},
		},
		{
			name: "appends when different from the last segment",
			list: []table.Segment{segX},
			seg:  segY,
			want: []table.Segment{segX, segY},
		},
		{
			name: "skips when equal to the last segment",
			list: []table.Segment{segX},
			seg:  table.NewSegmentSRMPLS(100),
			want: []table.Segment{segX},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, appendIfNotDuplicate(tt.list, tt.seg))
		})
	}
}

func TestCSPFWithLooseSourceRouting(t *testing.T) {
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
		got, err := CSPFWithLooseSourceRouting("S", "D", nil, table.IGPMetric, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("a waypoint already on the shortest path does not duplicate its segment", func(t *testing.T) {
		waypoints := []table.Waypoint{{RouterID: "W1"}}
		got, err := CSPFWithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("multiple ordered waypoints route through each waypoint in sequence", func(t *testing.T) {
		waypoints := []table.Waypoint{{RouterID: "W1"}, {RouterID: "W2"}}
		got, err := CSPFWithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		require.NoError(t, err)
		assert.Equal(t, fullChainSegs, got)
	})

	t.Run("an explicit waypoint SID that differs from the node's default is kept as a separate segment", func(t *testing.T) {
		s2, w, d2 := srv6Node("S2", "2001:db8::1"), srv6Node("W", "2001:db8::2"), srv6Node("D2", "2001:db8::3")
		connect(s2, w, 1)
		connect(w, d2, 1)
		ted := buildTED(s2, w, d2)

		waypoints := []table.Waypoint{{RouterID: "W", SID: "2001:db8::2ff"}}
		got, err := CSPFWithLooseSourceRouting("S2", "D2", waypoints, table.IGPMetric, ted)
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
		ted := buildTED(srMPLSNode("S3", 0))
		got, err := CSPFWithLooseSourceRouting("S3", "D3", nil, table.IGPMetric, ted)
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CSPF failed between S3 and D3")
	})

	t.Run("a waypoint absent from the TED node map is rejected before any section is computed", func(t *testing.T) {
		// Intentionally leaves GHOST out of ted.Nodes while keeping it on the link.
		s4 := srMPLSNode("S4", 0)
		ghost := srMPLSNode("GHOST", 1)
		connect(s4, ghost, 1)
		ted := buildTED(s4)

		waypoints := []table.Waypoint{{RouterID: "GHOST"}}
		got, err := CSPFWithLooseSourceRouting("S4", "GHOST", waypoints, table.IGPMetric, ted)
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "waypoint router GHOST not found in TED")
	})

	t.Run("an unknown waypoint is rejected even when the destination is reachable", func(t *testing.T) {
		waypoints := []table.Waypoint{{RouterID: "GHOST"}}
		got, err := CSPFWithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "waypoint router GHOST not found in TED")
	})

	t.Run("an invalid explicit waypoint SID is wrapped with the router", func(t *testing.T) {
		waypoints := []table.Waypoint{{RouterID: "W1", SID: "not-an-address"}}
		got, err := CSPFWithLooseSourceRouting("S", "D", waypoints, table.IGPMetric, linearChain())
		assert.Nil(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to build segment for waypoint W1")
	})
}
