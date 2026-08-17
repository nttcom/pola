// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"bytes"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout while fn runs and returns everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	fn()

	require.NoError(t, w.Close())
	os.Stdout = old
	<-done
	return buf.String()
}

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

func TestLsTEDPrint_Empty(t *testing.T) {
	tests := []struct {
		name string
		ted  *LsTED
	}{
		{"nil TED", nil},
		{"TED with nil Nodes map", &LsTED{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, tt.ted.Print)
			assert.Equal(t, "TED is empty\n", out)
		})
	}
}

func TestLsTEDPrint_Populated(t *testing.T) {
	minimalNode := &LsNode{RouterID: "0000.0000.0002"}

	remoteNode := &LsNode{RouterID: "0000.0000.0003"}
	fullNode := &LsNode{
		RouterID:   "0000.0000.0001",
		Hostname:   "full-host",
		IsisAreaID: "49.0001",
		SrgbBegin:  16000,
		SrgbEnd:    24000,
		Prefixes: []*LsPrefix{
			nil,
			{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
			{Prefix: netip.MustParsePrefix("10.0.0.2/32"), SidIndex: 5, HasSidIndex: true},
		},
		Links: []*LsLink{
			nil,
			{},
			{
				LocalIP:    netip.MustParseAddr("10.0.0.1"),
				RemoteIP:   netip.MustParseAddr("10.0.0.2"),
				RemoteNode: remoteNode,
				Metrics:    []*Metric{nil, {Type: IGPMetric, Value: 10}},
				AdjSid:     24001,
				Srv6EndXSID: &Srv6EndXSID{
					EndpointBehavior: BehaviorENDX,
					Sids:             []string{"2001:db8:1::1"},
					Srv6SIDStructure: SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
				},
			},
		},
		SRv6SIDs: []*LsSrv6SID{
			nil,
			{
				Sids:             []string{"2001:db8:1::"},
				SIDStructure:     SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 0},
				EndpointBehavior: EndpointBehavior{Behavior: BehaviorUN, Flags: 1, Algorithm: 0},
				MultiTopoIDs:     []uint32{1},
			},
		},
	}

	ted := newTestTED(minimalNode, fullNode)
	ted.Nodes["0000.0000.0004"] = nil

	out := captureStdout(t, ted.Print)

	nodeHeaders := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Node: ") {
			nodeHeaders++
		}
	}
	assert.Equal(t, 2, nodeHeaders, "expected exactly the two non-nil nodes to be printed")
	assert.Contains(t, out, "Hostname: full-host")
	assert.Contains(t, out, "ISIS Area ID: 49.0001")
	assert.Contains(t, out, "SRGB: 16000 - 24000")
	assert.Contains(t, out, "10.0.0.1/32")
	assert.Contains(t, out, "10.0.0.2/32")
	assert.Contains(t, out, "index: 5")
	assert.Contains(t, out, "Local: 10.0.0.1 Remote: 10.0.0.2")
	assert.Contains(t, out, "Local: None Remote: None")
	assert.Contains(t, out, "RemoteNode: 0000.0000.0003")
	assert.Contains(t, out, "RemoteNode: None")
	assert.Contains(t, out, "igp: 10")
	assert.Contains(t, out, "Adj-SID: 24001")
	assert.Contains(t, out, "EndpointBehavior: ENDX")
	assert.Contains(t, out, "SIDs: [2001:db8:1::1]")
	assert.Contains(t, out, "SID Structure: Block: 32, Node: 16, Func: 16, Arg: 0")
	assert.Contains(t, out, "SIDs: [2001:db8:1::]")
	assert.Contains(t, out, "Block: 32, Node: 16, Func: 16, Arg: 0")
	assert.Contains(t, out, "EndpointBehavior: UN, Flags: 1, Algorithm: 0")
	assert.Contains(t, out, "MultiTopoIDs: [1]")
}
