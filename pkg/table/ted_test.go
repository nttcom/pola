// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table_test

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

func TestLsNodeNodeSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node *table.LsNode
		want string
	}{
		{
			name: "PrefixSIDIndexZero",
			node: &table.LsNode{
				RouterID:  testRouterID1,
				SrgbBegin: 16000,
				Prefixes: []*table.LsPrefix{
					{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
				},
			},
			want: "16000",
		},
		{
			name: "SRv6 Node SID is used when no Prefix-SID is present",
			node: &table.LsNode{
				RouterID: testRouterID1,
				Prefixes: []*table.LsPrefix{
					{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
				},
				SRv6SIDs: []*table.LsSrv6SID{
					{Sids: []string{testSRv6SID1}},
				},
			},
			want: testSRv6SID1,
		},
		{
			name: "SRv6 SID entries with no Sids are skipped",
			node: &table.LsNode{
				RouterID: testRouterID1,
				SRv6SIDs: []*table.LsSrv6SID{
					{Sids: []string{}},
					{Sids: []string{testSRv6SID2}},
				},
			},
			want: testSRv6SID2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			seg, err := tt.node.NodeSegment()
			require.NoError(t, err)
			assert.Equal(t, tt.want, seg.SidString())
		})
	}
}

func TestLsNodeNodeSegment_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node *table.LsNode
	}{
		{
			name: "NoPrefixSID",
			node: &table.LsNode{
				RouterID:  testRouterID1,
				SrgbBegin: 16000,
				Prefixes: []*table.LsPrefix{
					{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
				},
			},
		},
		{
			name: "SRv6 SID cannot be parsed as an address",
			node: &table.LsNode{
				RouterID: testRouterID1,
				SRv6SIDs: []*table.LsSrv6SID{
					{Sids: []string{testInvalidAddr}},
				},
			},
		},
		{
			name: "SRv6 SID is an IPv4 address",
			node: &table.LsNode{
				RouterID: testRouterID1,
				SRv6SIDs: []*table.LsSrv6SID{
					{Sids: []string{"192.0.2.1"}},
				},
			},
		},
		{
			name: "SRv6 SID is an IPv4-mapped IPv6 address",
			node: &table.LsNode{
				RouterID: testRouterID1,
				SRv6SIDs: []*table.LsSrv6SID{
					{Sids: []string{"::ffff:192.0.2.1"}},
				},
			},
		},
		{
			name: "Prefix-SID index without an SRGB",
			node: &table.LsNode{
				RouterID: testRouterID1,
				Prefixes: []*table.LsPrefix{{SidIndex: 10, HasSidIndex: true}},
			},
		},
		{
			name: "no Prefix-SID and no SRv6 SIDs",
			node: &table.LsNode{RouterID: testRouterID1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := tt.node.NodeSegment()
			assert.Error(t, err, "expected an error for a node without a Node SID")
		})
	}
}

func TestNodeSegment_PrefixSIDOutsideSRGB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node *table.LsNode
	}{
		{
			name: "label overflows the maximum MPLS label",
			node: &table.LsNode{
				RouterID:  testRouterID1,
				SrgbBegin: 0xFFFFF,
				Prefixes:  []*table.LsPrefix{{SidIndex: 10, HasSidIndex: true}},
			},
		},
		{
			name: "label reaches a bounded SRGB end",
			node: &table.LsNode{
				RouterID:  testRouterID1,
				SrgbBegin: 16000,
				SrgbEnd:   16010,
				Prefixes:  []*table.LsPrefix{{SidIndex: 100, HasSidIndex: true}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := tt.node.NodeSegment()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "out of range for SRGB")
		})
	}
}

func TestLsNodeLoopbackAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		node    *table.LsNode
		want    netip.Addr
		wantErr bool
	}{
		{
			name: "IPv4 /32 is a loopback address",
			node: &table.LsNode{Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}}},
			want: netip.MustParseAddr("10.0.0.1"),
		},
		{
			name:    "IPv4 non-/32 is not a loopback address",
			node:    &table.LsNode{Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.0/24")}}},
			wantErr: true,
		},
		{
			name: "IPv6 /128 is a loopback address",
			node: &table.LsNode{Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("2001:db8::1/128")}}},
			want: netip.MustParseAddr(testSRv6SID1),
		},
		{
			name:    "IPv6 non-/128 is not a loopback address",
			node:    &table.LsNode{Prefixes: []*table.LsPrefix{{Prefix: netip.MustParsePrefix("2001:db8::/64")}}},
			wantErr: true,
		},
		{
			name:    "no prefixes",
			node:    &table.LsNode{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.node.LoopbackAddr()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewLsNode(t *testing.T) {
	t.Parallel()

	assert.Equal(t, &table.LsNode{ASN: 1, RouterID: testRouterID1}, table.NewLsNode(1, testRouterID1))
}

func TestLsNodeUpdateTED_ASNMismatch(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	node := &table.LsNode{ASN: 2, RouterID: "R1", Hostname: "h1"}
	node.UpdateTED(ted, 1)
	assert.Empty(t, ted.Nodes, "expected a node with a different ASN to be ignored")
}

func TestLsNodeUpdateTED_NewNode(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	node := &table.LsNode{ASN: 1, RouterID: "R1", Hostname: "h1"}
	node.UpdateTED(ted, 1)
	assert.Same(t, node, ted.Nodes["R1"], "expected a previously unknown node to be added as-is")
}

func TestLsNodeUpdateTED_ExistingNode(t *testing.T) {
	t.Parallel()

	existing := &table.LsNode{ASN: 1, RouterID: "R1", Hostname: "old", Links: []*table.LsLink{{}}}
	ted := newTestTED(existing)

	update := &table.LsNode{
		ASN: 1, RouterID: "R1", Hostname: "new", IsisAreaID: "49.0001",
		SrgbBegin: 16000, SrgbEnd: 24000,
	}
	update.UpdateTED(ted, 1)

	assert.Same(t, existing, ted.Nodes["R1"], "expected the existing node object to be updated in place")
	assert.Equal(t, "new", existing.Hostname)
	assert.Equal(t, "49.0001", existing.IsisAreaID)
	assert.Equal(t, uint32(16000), existing.SrgbBegin)
	assert.Equal(t, uint32(24000), existing.SrgbEnd)
	assert.Len(t, existing.Links, 1, "expected fields not covered by the update to be preserved")
}

func TestLsNodeAddLink(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{RouterID: "R1"}
	link := &table.LsLink{}
	node.AddLink(link)
	assert.Equal(t, []*table.LsLink{link}, node.Links)
}

func TestNewLsLink(t *testing.T) {
	t.Parallel()

	local := &table.LsNode{RouterID: "R1"}
	remote := &table.LsNode{RouterID: "R2"}
	assert.Equal(t, &table.LsLink{LocalNode: local, RemoteNode: remote}, table.NewLsLink(local, remote))
}

func TestLsLinkMetric(t *testing.T) {
	t.Parallel()

	link := &table.LsLink{Metrics: []*table.Metric{{Type: table.IGPMetric, Value: 10}}}

	t.Run("metric is defined", func(t *testing.T) {
		t.Parallel()

		got, err := link.Metric(table.IGPMetric)
		require.NoError(t, err)
		assert.Equal(t, uint32(10), got)
	})

	t.Run("metric is not defined", func(t *testing.T) {
		t.Parallel()

		_, err := link.Metric(table.TEMetric)
		assert.EqualError(t, err, "metric METRIC_TYPE_TE not defined")
	})

	t.Run("hopcount is always 1 regardless of Metrics", func(t *testing.T) {
		t.Parallel()

		got, err := link.Metric(table.HopcountMetric)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), got)
	})
}

func TestLsLinkUpdateTED_ASNMismatch(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	local := &table.LsNode{ASN: 1, RouterID: "R1"}
	remote := &table.LsNode{ASN: 2, RouterID: "R2"}
	link := table.NewLsLink(local, remote)

	link.UpdateTED(ted, 1)

	assert.Empty(t, ted.Nodes, "expected mismatched ASN link to be ignored")
	assert.Empty(t, local.Links)
}

func TestLsLinkUpdateTED_CreatesNodesAndAddsLink(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	local := &table.LsNode{ASN: 1, RouterID: "R1"}
	remote := &table.LsNode{ASN: 1, RouterID: "R2"}
	link := table.NewLsLink(local, remote)

	link.UpdateTED(ted, 1)

	require.Contains(t, ted.Nodes, "R1")
	require.Contains(t, ted.Nodes, "R2")
	assert.Same(t, ted.Nodes["R1"], link.LocalNode)
	assert.Same(t, ted.Nodes["R2"], link.RemoteNode)
	assert.Equal(t, []*table.LsLink{link}, ted.Nodes["R1"].Links)
}

func TestLsLinkUpdateTED_ReusesExistingNodes(t *testing.T) {
	t.Parallel()

	existingLocal := &table.LsNode{ASN: 1, RouterID: "R1", Hostname: "local-host"}
	existingRemote := &table.LsNode{ASN: 1, RouterID: "R2", Hostname: "remote-host"}
	preexistingLink := &table.LsLink{}
	existingLocal.Links = []*table.LsLink{preexistingLink}
	ted := newTestTED(existingLocal, existingRemote)

	link := table.NewLsLink(&table.LsNode{ASN: 1, RouterID: "R1"}, &table.LsNode{ASN: 1, RouterID: "R2"})
	link.UpdateTED(ted, 1)

	assert.Same(t, existingLocal, link.LocalNode, "expected the link to reference the existing node object")
	assert.Same(t, existingRemote, link.RemoteNode)
	assert.Equal(t, []*table.LsLink{preexistingLink, link}, existingLocal.Links, "expected the link to be appended to existing links")
}

func TestNewLsPrefix(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{RouterID: "R1"}
	assert.Equal(t, &table.LsPrefix{LocalNode: node}, table.NewLsPrefix(node))
}

func TestLsPrefixUpdateTED_ASNMismatch(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	prefix := &table.LsPrefix{LocalNode: &table.LsNode{ASN: 2, RouterID: "R1"}, Prefix: netip.MustParsePrefix("10.0.0.1/32")}

	prefix.UpdateTED(ted, 1)

	assert.Empty(t, ted.Nodes, "expected mismatched ASN prefix to be ignored")
}

func TestLsPrefixUpdateTED_CreatesNodeAndAddsPrefix(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	prefix := &table.LsPrefix{LocalNode: &table.LsNode{ASN: 1, RouterID: "R1"}, Prefix: netip.MustParsePrefix("10.0.0.1/32")}

	prefix.UpdateTED(ted, 1)

	require.Contains(t, ted.Nodes, "R1")
	assert.Equal(t, []*table.LsPrefix{prefix}, ted.Nodes["R1"].Prefixes)
}

func TestLsPrefixUpdateTED_DuplicatePrefixIsIgnored(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{ASN: 1, RouterID: "R1"}
	ted := newTestTED(node)

	first := &table.LsPrefix{LocalNode: node, Prefix: netip.MustParsePrefix("10.0.0.1/32")}
	first.UpdateTED(ted, 1)

	second := &table.LsPrefix{LocalNode: node, Prefix: netip.MustParsePrefix("10.0.0.1/32")}
	second.UpdateTED(ted, 1)

	assert.Equal(t, []*table.LsPrefix{first}, ted.Nodes["R1"].Prefixes, "expected a prefix already present on the node not to be added again")
}

func TestNewLsSrv6SID(t *testing.T) {
	t.Parallel()

	node := &table.LsNode{RouterID: "R1"}
	assert.Equal(t, &table.LsSrv6SID{LocalNode: node}, table.NewLsSrv6SID(node))
}

func TestLsSrv6SIDUpdateTED_ASNMismatch(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	sid := &table.LsSrv6SID{LocalNode: &table.LsNode{ASN: 2, RouterID: "R1"}}

	sid.UpdateTED(ted, 1)

	assert.Empty(t, ted.Nodes, "expected mismatched ASN SRv6 SID to be ignored")
}

func TestLsSrv6SIDUpdateTED_CreatesNodeAndAddsSID(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	sid := &table.LsSrv6SID{LocalNode: &table.LsNode{ASN: 1, RouterID: "R1"}, Sids: []string{testSRv6SID1}}

	sid.UpdateTED(ted, 1)

	require.Contains(t, ted.Nodes, "R1")
	assert.Same(t, ted.Nodes["R1"], sid.LocalNode)
	assert.Equal(t, []*table.LsSrv6SID{sid}, ted.Nodes["R1"].SRv6SIDs)
}

func TestLsSrv6SIDUpdateTED_ReusesExistingNode(t *testing.T) {
	t.Parallel()

	existing := &table.LsNode{ASN: 1, RouterID: "R1"}
	ted := newTestTED(existing)

	first := &table.LsSrv6SID{LocalNode: &table.LsNode{ASN: 1, RouterID: "R1"}, Sids: []string{testSRv6SID1}}
	first.UpdateTED(ted, 1)

	second := &table.LsSrv6SID{LocalNode: &table.LsNode{ASN: 1, RouterID: "R1"}, Sids: []string{testSRv6SID2}}
	second.UpdateTED(ted, 1)

	assert.Same(t, existing, first.LocalNode)
	assert.Equal(t, []*table.LsSrv6SID{first, second}, existing.SRv6SIDs)
}

func TestNewMetric(t *testing.T) {
	t.Parallel()

	assert.Equal(t, &table.Metric{Type: table.IGPMetric, Value: 10}, table.NewMetric(table.IGPMetric, 10))
}

func TestMetricTypeIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    table.MetricType
		want bool
	}{
		{"unspecified", table.UnspecifiedMetric, true},
		{"IGP", table.IGPMetric, true},
		{"TE", table.TEMetric, true},
		{"delay", table.DelayMetric, true},
		{"hopcount", table.HopcountMetric, true},
		{"above the defined range", table.MetricType(99), false},
		{"negative", table.MetricType(-1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.m.IsValid())
		})
	}
}

func TestMetricTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    table.MetricType
		want string
	}{
		{"unspecified", table.UnspecifiedMetric, "METRIC_TYPE_UNSPECIFIED"},
		{"IGP", table.IGPMetric, "METRIC_TYPE_IGP"},
		{"TE", table.TEMetric, "METRIC_TYPE_TE"},
		{"delay", table.DelayMetric, "METRIC_TYPE_DELAY"},
		{"hopcount", table.HopcountMetric, "METRIC_TYPE_HOPCOUNT"},
		{"unknown value", table.MetricType(99), "METRIC_TYPE_UNSPECIFIED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.m.String())
		})
	}
}

func TestMetricTypeDisplayString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    table.MetricType
		want string
	}{
		{"unspecified", table.UnspecifiedMetric, ""},
		{"IGP", table.IGPMetric, "igp"},
		{"TE", table.TEMetric, "te"},
		{"delay", table.DelayMetric, "delay"},
		{"hopcount", table.HopcountMetric, "hopcount"},
		{"unknown value", table.MetricType(99), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.m.DisplayString())
		})
	}
}

func TestMetricTypeMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    table.MetricType
		want string
	}{
		{"IGP", table.IGPMetric, `"igp"`},
		{"unspecified", table.UnspecifiedMetric, `""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := tt.m.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(b))
		})
	}
}

func TestLsTEDUpdate(t *testing.T) {
	t.Parallel()

	ted := newTestTED()
	node := &table.LsNode{ASN: 1, RouterID: "R1"}
	link := table.NewLsLink(&table.LsNode{ASN: 1, RouterID: "R1"}, &table.LsNode{ASN: 1, RouterID: "R2"})

	ted.Update([]table.TEDElem{node, link}, 1)

	assert.Same(t, node, ted.Nodes["R1"])
	require.Contains(t, ted.Nodes, "R2")
}

func TestLsTEDRouterIDIndex(t *testing.T) {
	t.Parallel()

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}

	v4Node := table.NewLsNode(65000, "router-v4")
	v4Prefix := table.NewLsPrefix(v4Node)
	v4Prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	v4Node.Prefixes = append(v4Node.Prefixes, v4Prefix)
	ted.Nodes[v4Node.RouterID] = v4Node

	v6Node := table.NewLsNode(65000, "router-v6")
	v6Prefix := table.NewLsPrefix(v6Node)
	v6Prefix.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	v6Node.Prefixes = append(v6Node.Prefixes, v6Prefix)
	ted.Nodes[v6Node.RouterID] = v6Node

	// A node without a loopback (host) prefix must not appear in the index.
	noLoopbackNode := table.NewLsNode(65000, "router-no-loopback")
	nonHostPrefix := table.NewLsPrefix(noLoopbackNode)
	nonHostPrefix.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	noLoopbackNode.Prefixes = append(noLoopbackNode.Prefixes, nonHostPrefix)
	ted.Nodes[noLoopbackNode.RouterID] = noLoopbackNode
	ted.Nodes["router-nil"] = nil

	index := ted.RouterIDIndex()
	assert.Equal(t, "router-v4", index[netip.MustParseAddr("192.0.2.10")])
	assert.Equal(t, "router-v6", index[netip.MustParseAddr(testSRv6SID1)])
	assert.Empty(t, index[netip.MustParseAddr("192.0.2.0")])

	var nilTED *table.LsTED
	assert.Nil(t, nilTED.RouterIDIndex())
}

func TestLsTEDAddressRouterIDIndex(t *testing.T) {
	t.Parallel()

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}

	v4Node := table.NewLsNode(65000, "router-v4")
	v4Prefix := table.NewLsPrefix(v4Node)
	v4Prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	v4Node.Prefixes = append(v4Node.Prefixes, v4Prefix)
	ted.Nodes[v4Node.RouterID] = v4Node

	v6Node := table.NewLsNode(65000, "router-v6")
	v6Prefix := table.NewLsPrefix(v6Node)
	v6Prefix.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	v6Node.Prefixes = append(v6Node.Prefixes, v6Prefix)
	ted.Nodes[v6Node.RouterID] = v6Node

	// Non-host prefixes are indexed too, by their network address.
	subnetNode := table.NewLsNode(65000, "router-subnet")
	subnetPrefix := table.NewLsPrefix(subnetNode)
	subnetPrefix.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	subnetNode.Prefixes = append(subnetNode.Prefixes, subnetPrefix)
	ted.Nodes[subnetNode.RouterID] = subnetNode
	ted.Nodes["router-nil"] = nil

	index := ted.AddressRouterIDIndex()
	assert.Equal(t, "router-v4", index[netip.MustParseAddr("192.0.2.10")])
	assert.Equal(t, "router-v6", index[netip.MustParseAddr(testSRv6SID1)])
	assert.Equal(t, "router-subnet", index[netip.MustParseAddr("192.0.2.0")])

	var nilTED *table.LsTED
	assert.Nil(t, nilTED.AddressRouterIDIndex())
}

func TestLsTEDFindRouterIDByLoopback(t *testing.T) {
	t.Parallel()

	ted := &table.LsTED{Nodes: map[string]*table.LsNode{}}

	node := table.NewLsNode(65000, "router-v4")
	prefix := table.NewLsPrefix(node)
	prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	node.Prefixes = append(node.Prefixes, prefix)
	ted.Nodes[node.RouterID] = node

	routerID, ok := ted.FindRouterIDByLoopback(netip.MustParseAddr("192.0.2.10"))
	require.True(t, ok)
	assert.Equal(t, "router-v4", routerID)

	_, ok = ted.FindRouterIDByLoopback(netip.MustParseAddr("192.0.2.99"))
	assert.False(t, ok)
}

func TestLsTEDPrint(t *testing.T) {
	t.Parallel()

	t.Run("nil TED", func(t *testing.T) {
		t.Parallel()

		var (
			ted *table.LsTED
			buf bytes.Buffer
		)
		ted.Print(&buf)
		assert.Equal(t, "TED is empty\n", buf.String())
	})

	t.Run("empty TED", func(t *testing.T) {
		t.Parallel()

		ted := &table.LsTED{Nodes: make(map[string]*table.LsNode)}

		var buf bytes.Buffer
		ted.Print(&buf)
		assert.Empty(t, buf.String())
	})

	t.Run("TED with nodes and links", func(t *testing.T) {
		t.Parallel()

		ted := &table.LsTED{Nodes: map[string]*table.LsNode{
			"R1": {
				RouterID: "R1",
				Hostname: "router1",
				Links: []*table.LsLink{
					{RemoteNode: &table.LsNode{RouterID: "R2"}},
				},
			},
		}}

		var buf bytes.Buffer
		ted.Print(&buf)
		assert.Contains(t, buf.String(), "R1")
		assert.Contains(t, buf.String(), "router1")
	})
}
