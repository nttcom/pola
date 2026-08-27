// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLsNodeNodeSegment(t *testing.T) {
	tests := []struct {
		name string
		node *LsNode
		want string
	}{
		{
			name: "PrefixSIDIndexZero",
			node: &LsNode{
				RouterID:  "0000.0000.0001",
				SrgbBegin: 16000,
				Prefixes: []*LsPrefix{
					{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
				},
			},
			want: "16000",
		},
		{
			name: "SRv6 Node SID is used when no Prefix-SID is present",
			node: &LsNode{
				RouterID: "0000.0000.0001",
				Prefixes: []*LsPrefix{
					{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
				},
				SRv6SIDs: []*LsSrv6SID{
					{Sids: []string{"2001:db8::1"}},
				},
			},
			want: "2001:db8::1",
		},
		{
			name: "SRv6 SID entries with no Sids are skipped",
			node: &LsNode{
				RouterID: "0000.0000.0001",
				SRv6SIDs: []*LsSrv6SID{
					{Sids: []string{}},
					{Sids: []string{"2001:db8::2"}},
				},
			},
			want: "2001:db8::2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := tt.node.NodeSegment()
			require.NoError(t, err)
			assert.Equal(t, tt.want, seg.SidString())
		})
	}
}

func TestLsNodeNodeSegment_Errors(t *testing.T) {
	tests := []struct {
		name string
		node *LsNode
	}{
		{
			name: "NoPrefixSID",
			node: &LsNode{
				RouterID:  "0000.0000.0001",
				SrgbBegin: 16000,
				Prefixes: []*LsPrefix{
					{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
				},
			},
		},
		{
			name: "SRv6 SID cannot be parsed as an address",
			node: &LsNode{
				RouterID: "0000.0000.0001",
				SRv6SIDs: []*LsSrv6SID{
					{Sids: []string{"not-an-address"}},
				},
			},
		},
		{
			name: "SRv6 SID is an IPv4 address",
			node: &LsNode{
				RouterID: "0000.0000.0001",
				SRv6SIDs: []*LsSrv6SID{
					{Sids: []string{"192.0.2.1"}},
				},
			},
		},
		{
			name: "SRv6 SID is an IPv4-mapped IPv6 address",
			node: &LsNode{
				RouterID: "0000.0000.0001",
				SRv6SIDs: []*LsSrv6SID{
					{Sids: []string{"::ffff:192.0.2.1"}},
				},
			},
		},
		{
			name: "Prefix-SID index without an SRGB",
			node: &LsNode{
				RouterID: "0000.0000.0001",
				Prefixes: []*LsPrefix{{SidIndex: 10, HasSidIndex: true}},
			},
		},
		{
			name: "no Prefix-SID and no SRv6 SIDs",
			node: &LsNode{RouterID: "0000.0000.0001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.node.NodeSegment()
			assert.Error(t, err, "expected an error for a node without a Node SID")
		})
	}
}

func TestNodeSegment_PrefixSIDOutsideSRGB(t *testing.T) {
	tests := []struct {
		name string
		node *LsNode
	}{
		{
			name: "label overflows the maximum MPLS label",
			node: &LsNode{
				RouterID:  "0000.0000.0001",
				SrgbBegin: 0xFFFFF,
				Prefixes:  []*LsPrefix{{SidIndex: 10, HasSidIndex: true}},
			},
		},
		{
			name: "label reaches a bounded SRGB end",
			node: &LsNode{
				RouterID:  "0000.0000.0001",
				SrgbBegin: 16000,
				SrgbEnd:   16010,
				Prefixes:  []*LsPrefix{{SidIndex: 100, HasSidIndex: true}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.node.NodeSegment()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "out of range for SRGB")
		})
	}
}

func TestLsNodeLoopbackAddr(t *testing.T) {
	tests := []struct {
		name    string
		node    *LsNode
		want    netip.Addr
		wantErr bool
	}{
		{
			name: "IPv4 /32 is a loopback address",
			node: &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}}},
			want: netip.MustParseAddr("10.0.0.1"),
		},
		{
			name:    "IPv4 non-/32 is not a loopback address",
			node:    &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.0/24")}}},
			wantErr: true,
		},
		{
			name: "IPv6 /128 is a loopback address",
			node: &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("2001:db8::1/128")}}},
			want: netip.MustParseAddr("2001:db8::1"),
		},
		{
			name:    "IPv6 non-/128 is not a loopback address",
			node:    &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("2001:db8::/64")}}},
			wantErr: true,
		},
		{
			name:    "no prefixes",
			node:    &LsNode{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	assert.Equal(t, &LsNode{ASN: 1, RouterID: "0000.0000.0001"}, NewLsNode(1, "0000.0000.0001"))
}

func TestLsNodeUpdateTED_ASNMismatch(t *testing.T) {
	ted := newTestTED()
	node := &LsNode{ASN: 2, RouterID: "R1", Hostname: "h1"}
	node.UpdateTED(ted, 1)
	assert.Empty(t, ted.Nodes, "expected a node with a different ASN to be ignored")
}

func TestLsNodeUpdateTED_NewNode(t *testing.T) {
	ted := newTestTED()
	node := &LsNode{ASN: 1, RouterID: "R1", Hostname: "h1"}
	node.UpdateTED(ted, 1)
	assert.Same(t, node, ted.Nodes["R1"], "expected a previously unknown node to be added as-is")
}

func TestLsNodeUpdateTED_ExistingNode(t *testing.T) {
	existing := &LsNode{ASN: 1, RouterID: "R1", Hostname: "old", Links: []*LsLink{{}}}
	ted := newTestTED(existing)

	update := &LsNode{
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
	node := &LsNode{RouterID: "R1"}
	link := &LsLink{}
	node.AddLink(link)
	assert.Equal(t, []*LsLink{link}, node.Links)
}

func TestNewLsLink(t *testing.T) {
	local := &LsNode{RouterID: "R1"}
	remote := &LsNode{RouterID: "R2"}
	assert.Equal(t, &LsLink{LocalNode: local, RemoteNode: remote}, NewLsLink(local, remote))
}

func TestLsLinkMetric(t *testing.T) {
	link := &LsLink{Metrics: []*Metric{{Type: IGPMetric, Value: 10}}}

	t.Run("metric is defined", func(t *testing.T) {
		got, err := link.Metric(IGPMetric)
		require.NoError(t, err)
		assert.Equal(t, uint32(10), got)
	})

	t.Run("metric is not defined", func(t *testing.T) {
		_, err := link.Metric(TEMetric)
		assert.EqualError(t, err, "metric METRIC_TYPE_TE not defined")
	})

	t.Run("hopcount is always 1 regardless of Metrics", func(t *testing.T) {
		got, err := link.Metric(HopcountMetric)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), got)
	})
}

func TestLsLinkUpdateTED_ASNMismatch(t *testing.T) {
	ted := newTestTED()
	local := &LsNode{ASN: 1, RouterID: "R1"}
	remote := &LsNode{ASN: 2, RouterID: "R2"}
	link := NewLsLink(local, remote)

	link.UpdateTED(ted, 1)

	assert.Empty(t, ted.Nodes, "expected mismatched ASN link to be ignored")
	assert.Empty(t, local.Links)
}

func TestLsLinkUpdateTED_CreatesNodesAndAddsLink(t *testing.T) {
	ted := newTestTED()
	local := &LsNode{ASN: 1, RouterID: "R1"}
	remote := &LsNode{ASN: 1, RouterID: "R2"}
	link := NewLsLink(local, remote)

	link.UpdateTED(ted, 1)

	require.Contains(t, ted.Nodes, "R1")
	require.Contains(t, ted.Nodes, "R2")
	assert.Same(t, ted.Nodes["R1"], link.LocalNode)
	assert.Same(t, ted.Nodes["R2"], link.RemoteNode)
	assert.Equal(t, []*LsLink{link}, ted.Nodes["R1"].Links)
}

func TestLsLinkUpdateTED_ReusesExistingNodes(t *testing.T) {
	existingLocal := &LsNode{ASN: 1, RouterID: "R1", Hostname: "local-host"}
	existingRemote := &LsNode{ASN: 1, RouterID: "R2", Hostname: "remote-host"}
	preexistingLink := &LsLink{}
	existingLocal.Links = []*LsLink{preexistingLink}
	ted := newTestTED(existingLocal, existingRemote)

	link := NewLsLink(&LsNode{ASN: 1, RouterID: "R1"}, &LsNode{ASN: 1, RouterID: "R2"})
	link.UpdateTED(ted, 1)

	assert.Same(t, existingLocal, link.LocalNode, "expected the link to reference the existing node object")
	assert.Same(t, existingRemote, link.RemoteNode)
	assert.Equal(t, []*LsLink{preexistingLink, link}, existingLocal.Links, "expected the link to be appended to existing links")
}

func TestNewLsPrefix(t *testing.T) {
	node := &LsNode{RouterID: "R1"}
	assert.Equal(t, &LsPrefix{LocalNode: node}, NewLsPrefix(node))
}

func TestLsPrefixUpdateTED_ASNMismatch(t *testing.T) {
	ted := newTestTED()
	prefix := &LsPrefix{LocalNode: &LsNode{ASN: 2, RouterID: "R1"}, Prefix: netip.MustParsePrefix("10.0.0.1/32")}

	prefix.UpdateTED(ted, 1)

	assert.Empty(t, ted.Nodes, "expected mismatched ASN prefix to be ignored")
}

func TestLsPrefixUpdateTED_CreatesNodeAndAddsPrefix(t *testing.T) {
	ted := newTestTED()
	prefix := &LsPrefix{LocalNode: &LsNode{ASN: 1, RouterID: "R1"}, Prefix: netip.MustParsePrefix("10.0.0.1/32")}

	prefix.UpdateTED(ted, 1)

	require.Contains(t, ted.Nodes, "R1")
	assert.Equal(t, []*LsPrefix{prefix}, ted.Nodes["R1"].Prefixes)
}

func TestLsPrefixUpdateTED_DuplicatePrefixIsIgnored(t *testing.T) {
	node := &LsNode{ASN: 1, RouterID: "R1"}
	ted := newTestTED(node)

	first := &LsPrefix{LocalNode: node, Prefix: netip.MustParsePrefix("10.0.0.1/32")}
	first.UpdateTED(ted, 1)

	second := &LsPrefix{LocalNode: node, Prefix: netip.MustParsePrefix("10.0.0.1/32")}
	second.UpdateTED(ted, 1)

	assert.Equal(t, []*LsPrefix{first}, ted.Nodes["R1"].Prefixes, "expected a prefix already present on the node not to be added again")
}

func TestNewLsSrv6SID(t *testing.T) {
	node := &LsNode{RouterID: "R1"}
	assert.Equal(t, &LsSrv6SID{LocalNode: node}, NewLsSrv6SID(node))
}

func TestLsSrv6SIDUpdateTED_ASNMismatch(t *testing.T) {
	ted := newTestTED()
	sid := &LsSrv6SID{LocalNode: &LsNode{ASN: 2, RouterID: "R1"}}

	sid.UpdateTED(ted, 1)

	assert.Empty(t, ted.Nodes, "expected mismatched ASN SRv6 SID to be ignored")
}

func TestLsSrv6SIDUpdateTED_CreatesNodeAndAddsSID(t *testing.T) {
	ted := newTestTED()
	sid := &LsSrv6SID{LocalNode: &LsNode{ASN: 1, RouterID: "R1"}, Sids: []string{"2001:db8::1"}}

	sid.UpdateTED(ted, 1)

	require.Contains(t, ted.Nodes, "R1")
	assert.Same(t, ted.Nodes["R1"], sid.LocalNode)
	assert.Equal(t, []*LsSrv6SID{sid}, ted.Nodes["R1"].SRv6SIDs)
}

func TestLsSrv6SIDUpdateTED_ReusesExistingNode(t *testing.T) {
	existing := &LsNode{ASN: 1, RouterID: "R1"}
	ted := newTestTED(existing)

	first := &LsSrv6SID{LocalNode: &LsNode{ASN: 1, RouterID: "R1"}, Sids: []string{"2001:db8::1"}}
	first.UpdateTED(ted, 1)
	second := &LsSrv6SID{LocalNode: &LsNode{ASN: 1, RouterID: "R1"}, Sids: []string{"2001:db8::2"}}
	second.UpdateTED(ted, 1)

	assert.Same(t, existing, first.LocalNode)
	assert.Equal(t, []*LsSrv6SID{first, second}, existing.SRv6SIDs)
}

func TestNewMetric(t *testing.T) {
	assert.Equal(t, &Metric{Type: IGPMetric, Value: 10}, NewMetric(IGPMetric, 10))
}

func TestMetricTypeIsValid(t *testing.T) {
	tests := []struct {
		name string
		m    MetricType
		want bool
	}{
		{"unspecified", UnspecifiedMetric, true},
		{"IGP", IGPMetric, true},
		{"TE", TEMetric, true},
		{"delay", DelayMetric, true},
		{"hopcount", HopcountMetric, true},
		{"above the defined range", MetricType(99), false},
		{"negative", MetricType(-1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.m.IsValid())
		})
	}
}

func TestMetricTypeString(t *testing.T) {
	tests := []struct {
		name string
		m    MetricType
		want string
	}{
		{"unspecified", UnspecifiedMetric, "METRIC_TYPE_UNSPECIFIED"},
		{"IGP", IGPMetric, "METRIC_TYPE_IGP"},
		{"TE", TEMetric, "METRIC_TYPE_TE"},
		{"delay", DelayMetric, "METRIC_TYPE_DELAY"},
		{"hopcount", HopcountMetric, "METRIC_TYPE_HOPCOUNT"},
		{"unknown value", MetricType(99), "METRIC_TYPE_UNSPECIFIED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.m.String())
		})
	}
}

func TestMetricTypeDisplayString(t *testing.T) {
	tests := []struct {
		name string
		m    MetricType
		want string
	}{
		{"unspecified", UnspecifiedMetric, ""},
		{"IGP", IGPMetric, "igp"},
		{"TE", TEMetric, "te"},
		{"delay", DelayMetric, "delay"},
		{"hopcount", HopcountMetric, "hopcount"},
		{"unknown value", MetricType(99), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.m.DisplayString())
		})
	}
}

func TestMetricTypeMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		m    MetricType
		want string
	}{
		{"IGP", IGPMetric, `"igp"`},
		{"unspecified", UnspecifiedMetric, `""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.m.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(b))
		})
	}
}

func TestLsTEDUpdate(t *testing.T) {
	ted := newTestTED()
	node := &LsNode{ASN: 1, RouterID: "R1"}
	link := NewLsLink(&LsNode{ASN: 1, RouterID: "R1"}, &LsNode{ASN: 1, RouterID: "R2"})

	ted.Update([]TEDElem{node, link}, 1)

	assert.Same(t, node, ted.Nodes["R1"])
	require.Contains(t, ted.Nodes, "R2")
}

func TestLsTEDRouterIDIndex(t *testing.T) {
	ted := &LsTED{Nodes: map[string]*LsNode{}}

	v4Node := NewLsNode(65000, "router-v4")
	v4Prefix := NewLsPrefix(v4Node)
	v4Prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	v4Node.Prefixes = append(v4Node.Prefixes, v4Prefix)
	ted.Nodes[v4Node.RouterID] = v4Node

	v6Node := NewLsNode(65000, "router-v6")
	v6Prefix := NewLsPrefix(v6Node)
	v6Prefix.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	v6Node.Prefixes = append(v6Node.Prefixes, v6Prefix)
	ted.Nodes[v6Node.RouterID] = v6Node

	// A node without a loopback (host) prefix must not appear in the index.
	noLoopbackNode := NewLsNode(65000, "router-no-loopback")
	nonHostPrefix := NewLsPrefix(noLoopbackNode)
	nonHostPrefix.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	noLoopbackNode.Prefixes = append(noLoopbackNode.Prefixes, nonHostPrefix)
	ted.Nodes[noLoopbackNode.RouterID] = noLoopbackNode
	ted.Nodes["router-nil"] = nil

	index := ted.RouterIDIndex()
	assert.Equal(t, "router-v4", index[netip.MustParseAddr("192.0.2.10")])
	assert.Equal(t, "router-v6", index[netip.MustParseAddr("2001:db8::1")])
	assert.Empty(t, index[netip.MustParseAddr("192.0.2.0")])

	var nilTED *LsTED
	assert.Nil(t, nilTED.RouterIDIndex())
}

func TestLsTEDAddressRouterIDIndex(t *testing.T) {
	ted := &LsTED{Nodes: map[string]*LsNode{}}

	v4Node := NewLsNode(65000, "router-v4")
	v4Prefix := NewLsPrefix(v4Node)
	v4Prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	v4Node.Prefixes = append(v4Node.Prefixes, v4Prefix)
	ted.Nodes[v4Node.RouterID] = v4Node

	v6Node := NewLsNode(65000, "router-v6")
	v6Prefix := NewLsPrefix(v6Node)
	v6Prefix.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	v6Node.Prefixes = append(v6Node.Prefixes, v6Prefix)
	ted.Nodes[v6Node.RouterID] = v6Node

	// Non-host prefixes are indexed too, by their network address.
	subnetNode := NewLsNode(65000, "router-subnet")
	subnetPrefix := NewLsPrefix(subnetNode)
	subnetPrefix.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	subnetNode.Prefixes = append(subnetNode.Prefixes, subnetPrefix)
	ted.Nodes[subnetNode.RouterID] = subnetNode
	ted.Nodes["router-nil"] = nil

	index := ted.AddressRouterIDIndex()
	assert.Equal(t, "router-v4", index[netip.MustParseAddr("192.0.2.10")])
	assert.Equal(t, "router-v6", index[netip.MustParseAddr("2001:db8::1")])
	assert.Equal(t, "router-subnet", index[netip.MustParseAddr("192.0.2.0")])

	var nilTED *LsTED
	assert.Nil(t, nilTED.AddressRouterIDIndex())
}

func TestLsTEDFindRouterIDByLoopback(t *testing.T) {
	ted := &LsTED{Nodes: map[string]*LsNode{}}

	node := NewLsNode(65000, "router-v4")
	prefix := NewLsPrefix(node)
	prefix.Prefix = netip.MustParsePrefix("192.0.2.10/32")
	node.Prefixes = append(node.Prefixes, prefix)
	ted.Nodes[node.RouterID] = node

	routerID, ok := ted.FindRouterIDByLoopback(netip.MustParseAddr("192.0.2.10"))
	require.True(t, ok)
	assert.Equal(t, "router-v4", routerID)

	_, ok = ted.FindRouterIDByLoopback(netip.MustParseAddr("192.0.2.99"))
	assert.False(t, ok)
}
