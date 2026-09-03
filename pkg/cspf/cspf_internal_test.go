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

const (
	cspfInternalTestGhostRouterID = "GHOST"
	cspfInternalTestInvalidSID    = "not-an-address"
	cspfInternalTestOverrideSID   = "2001:db8::ffff"
)

func cspfInternalTestSRMPLSNode(routerID string, sidIndex uint32) *table.LsNode {
	return &table.LsNode{
		RouterID:  routerID,
		SrgbBegin: 16000,
		Prefixes: []*table.LsPrefix{
			{SidIndex: sidIndex, HasSidIndex: true},
		},
	}
}

func cspfInternalTestMPLSSeg(sidIndex uint32) table.Segment {
	return table.NewSegmentSRMPLS(16000 + sidIndex)
}

func cspfInternalTestSRv6Node(routerID, sid string) *table.LsNode {
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

func cspfInternalTestSRv6DefaultSeg(sid string) table.SegmentSRv6 {
	addr := netip.MustParseAddr(sid)

	return table.SegmentSRv6{
		Sid:       addr,
		LocalAddr: addr,
		Structure: table.SIDStructureBytes{32, 16, 16, 0},
	}
}

func cspfInternalTestNodeWithoutSID(routerID string) *table.LsNode {
	return &table.LsNode{RouterID: routerID}
}

func cspfInternalTestConnect(local, remote *table.LsNode, igpCost uint32) {
	local.Links = append(local.Links, &table.LsLink{
		LocalNode:  local,
		RemoteNode: remote,
		Metrics:    []*table.Metric{table.NewMetric(table.IGPMetric, igpCost)},
	})
}

func cspfInternalTestBuildTED(nodes ...*table.LsNode) *table.LsTED {
	m := make(map[string]*table.LsNode, len(nodes))
	for _, n := range nodes {
		m[n.RouterID] = n
	}

	return &table.LsTED{Nodes: m}
}

func TestCSPF_Errors(t *testing.T) {
	t.Parallel()

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
				a, b := cspfInternalTestSRMPLSNode("A", 0), cspfInternalTestSRMPLSNode("B", 1)
				cspfInternalTestConnect(a, b, 1)

				return cspfInternalTestBuildTED(a, b)
			},
			src: "A", dst: "B", metric: table.TEMetric,
			wantErr: "metric METRIC_TYPE_TE not defined",
		},
		{
			name: "source node has no Node SID",
			buildTED: func() *table.LsTED {
				a, b := cspfInternalTestNodeWithoutSID("A"), cspfInternalTestSRMPLSNode("B", 0)
				cspfInternalTestConnect(a, b, 1)

				return cspfInternalTestBuildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric,
			wantErr: "node doesn't have a Node SID",
		},
		{
			name: "a newly discovered neighbor has no Node SID",
			buildTED: func() *table.LsTED {
				a, b := cspfInternalTestSRMPLSNode("A", 0), cspfInternalTestNodeWithoutSID("B")
				cspfInternalTestConnect(a, b, 1)

				return cspfInternalTestBuildTED(a, b)
			},
			src: "A", dst: "B", metric: table.IGPMetric,
			wantErr: "node doesn't have a Node SID",
		},
		{
			name: "destination router is absent from the TED",
			buildTED: func() *table.LsTED {
				return cspfInternalTestBuildTED(cspfInternalTestSRMPLSNode("A", 0))
			},
			src: "A", dst: "Z", metric: table.IGPMetric,
			wantErr: "destination router Z not found in TED",
		},
		{
			name: "destination is unreachable from the source",
			buildTED: func() *table.LsTED {
				return cspfInternalTestBuildTED(cspfInternalTestSRMPLSNode("A", 0), cspfInternalTestSRMPLSNode("B", 1))
			},
			src: "A", dst: "B", metric: table.IGPMetric,
			wantErr: errNextNodeNotFound,
		},
		{
			name: "source router is absent from the TED",
			buildTED: func() *table.LsTED {
				return cspfInternalTestBuildTED(cspfInternalTestSRMPLSNode("A", 0))
			},
			src: "Z", dst: "A", metric: table.IGPMetric,
			wantErr: "source router Z not found in TED",
		},
		{
			name: "source router check takes priority when both endpoints are absent",
			buildTED: func() *table.LsTED {
				return cspfInternalTestBuildTED(cspfInternalTestSRMPLSNode("A", 0))
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
				a, ghost, d := cspfInternalTestSRMPLSNode("A", 0), cspfInternalTestSRMPLSNode(cspfInternalTestGhostRouterID, 1), cspfInternalTestSRMPLSNode("D", 3)
				cspfInternalTestConnect(a, ghost, 1)
				cspfInternalTestConnect(ghost, d, 1)

				return cspfInternalTestBuildTED(a, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric,
			wantErr: errNextNodeNotFound,
		},
		{
			name: "a link with a nil remote node is skipped instead of panicking",
			buildTED: func() *table.LsTED {
				a, d := cspfInternalTestSRMPLSNode("A", 0), cspfInternalTestSRMPLSNode("D", 3)
				a.Links = append(a.Links, &table.LsLink{LocalNode: a, RemoteNode: nil})

				return cspfInternalTestBuildTED(a, d)
			},
			src: "A", dst: "D", metric: table.IGPMetric,
			wantErr: errNextNodeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ted := tt.buildTED()
			got, err := CSPF(tt.src, tt.dst, tt.metric, ted)
			assert.Nil(t, got)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestCSPF_TopologyLimitationClassification(t *testing.T) {
	t.Parallel()

	linear := func() *table.LsTED {
		a, b := cspfInternalTestSRMPLSNode("A", 0), cspfInternalTestSRMPLSNode("B", 1)
		cspfInternalTestConnect(a, b, 1)

		return cspfInternalTestBuildTED(a, b)
	}

	tests := []struct {
		name       string
		run        func() error
		wantReason string
	}{
		{"an unreachable destination", func() error {
			_, err := CSPF("A", "B", table.IGPMetric, cspfInternalTestBuildTED(cspfInternalTestSRMPLSNode("A", 0), cspfInternalTestSRMPLSNode("B", 1)))
			return err
		}, reasonDestinationUnreachable},
		{"a metric absent from a traversed link", func() error { _, err := CSPF("A", "B", table.TEMetric, linear()); return err }, reasonMetricNotCarried},
		{"a node without a Node SID", func() error {
			a, b := cspfInternalTestNodeWithoutSID("A"), cspfInternalTestSRMPLSNode("B", 0)
			cspfInternalTestConnect(a, b, 1)
			_, err := CSPF("A", "B", table.IGPMetric, cspfInternalTestBuildTED(a, b))

			return err
		}, reasonTEDDataIncomplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.run()
			require.Error(t, err)

			var topoLimit *TopologyLimitationError
			require.ErrorAs(t, err, &topoLimit)
			assert.Equal(t, tt.wantReason, topoLimit.Reason)
		})
	}
}

func TestUpdateNeighborCosts_UnknownCalcNode(t *testing.T) {
	t.Parallel()

	err := updateNeighborCosts("Z", map[string]*node{}, map[string]*table.LsNode{}, table.IGPMetric)
	assert.EqualError(t, err, "router Z not found in TED")
}

func TestBuildWaypointSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		node           *table.LsNode
		explicitSID    string
		want           table.Segment
		wantErr        string
		wantTopoReason string
	}{
		{
			name:        "empty SID falls back to the node's default SR-MPLS segment",
			node:        cspfInternalTestSRMPLSNode("A", 0),
			explicitSID: "",
			want:        cspfInternalTestMPLSSeg(0),
		},
		{
			name:        "empty SID falls back to the node's default SRv6 segment",
			node:        cspfInternalTestSRv6Node("A", "2001:db8::a"),
			explicitSID: "",
			want:        cspfInternalTestSRv6DefaultSeg("2001:db8::a"),
		},
		{
			name:           "empty SID returns an error when the node has no Node SID",
			node:           cspfInternalTestNodeWithoutSID("A"),
			explicitSID:    "",
			wantErr:        "node doesn't have a Node SID",
			wantTopoReason: reasonTEDDataIncomplete,
		},
		{
			name:        "explicit SID overrides the SID but keeps the node's SID structure",
			node:        cspfInternalTestSRv6Node("A", "2001:db8::a"),
			explicitSID: cspfInternalTestOverrideSID,
			want: table.SegmentSRv6{
				Sid:       netip.MustParseAddr(cspfInternalTestOverrideSID),
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
			explicitSID: cspfInternalTestOverrideSID,
			want: table.SegmentSRv6{
				Sid:       netip.MustParseAddr(cspfInternalTestOverrideSID),
				LocalAddr: netip.MustParseAddr("2001:db8::a"),
				Structure: table.SIDStructureBytes{32, 16, 16, 0},
				USid:      true,
			},
		},
		{
			name:        "invalid explicit SID returns a parse error",
			node:        cspfInternalTestSRMPLSNode("A", 0),
			explicitSID: cspfInternalTestInvalidSID,
			wantErr:     `invalid explicit SID "not-an-address": ParseAddr("not-an-address"): unable to parse IP`,
		},
		{
			name:           "explicit SID on a node without any SRv6 SIDs returns an error",
			node:           cspfInternalTestSRMPLSNode("A", 0),
			explicitSID:    cspfInternalTestOverrideSID,
			wantErr:        "no SRv6 SIDs available",
			wantTopoReason: reasonTEDDataIncomplete,
		},
		{
			name:        "IPv4 explicit SID is rejected",
			node:        cspfInternalTestSRv6Node("A", "2001:db8::a"),
			explicitSID: "10.0.0.1",
			wantErr:     `explicit SID "10.0.0.1" must be an IPv6 SRv6 SID`,
		},
		{
			name:        "IPv4-mapped explicit SID is rejected",
			node:        cspfInternalTestSRv6Node("A", "2001:db8::a"),
			explicitSID: "::ffff:10.0.0.1",
			wantErr:     `explicit SID "::ffff:10.0.0.1" must be an IPv6 SRv6 SID`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := buildWaypointSegment(tt.node, tt.explicitSID)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)

				if tt.wantTopoReason != "" {
					var topoErr *TopologyLimitationError
					require.ErrorAs(t, err, &topoErr)
					assert.Equal(t, tt.wantTopoReason, topoErr.Reason)
				} else {
					var inputErr *InvalidInputError
					require.ErrorAs(t, err, &inputErr)
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRemoveDuplicateFirst(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			assert.Equal(t, tt.want, removeDuplicateFirst(tt.fullList, tt.section))
		})
	}
}

func TestAppendIfNotDuplicate(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			assert.Equal(t, tt.want, appendIfNotDuplicate(tt.list, tt.seg))
		})
	}
}
