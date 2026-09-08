// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tedInternalTestSRv6SID1 = "2001:db8::1"

func TestPrintLink(t *testing.T) {
	t.Parallel()

	t.Run("missing IPs and RemoteNode fall back to None", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		printLink(&errWriter{w: &buf}, &LsLink{})

		assert.Contains(t, buf.String(), "Local: None Remote: None")
		assert.Contains(t, buf.String(), "RemoteNode: None")
	})

	t.Run("populated IPs and RemoteNode are printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{
			Local:  LinkEndpoint{IPv4: netip.MustParseAddr("192.0.2.1")},
			Remote: LinkEndpoint{IPv4: netip.MustParseAddr("192.0.2.2"), Node: &LsNode{RouterID: "R2"}},
		}

		var buf bytes.Buffer
		printLink(&errWriter{w: &buf}, link)

		assert.Contains(t, buf.String(), "Local: 192.0.2.1 Remote: 192.0.2.2")
		assert.Contains(t, buf.String(), "RemoteNode: R2")
	})

	t.Run("IPv6-only endpoints are printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{
			Local:  LinkEndpoint{IPv6: netip.MustParseAddr("2001:db8::1")},
			Remote: LinkEndpoint{IPv6: netip.MustParseAddr("2001:db8::2")},
		}

		var buf bytes.Buffer
		printLink(&errWriter{w: &buf}, link)

		assert.Contains(t, buf.String(), "Local: 2001:db8::1 Remote: 2001:db8::2")
	})

	t.Run("Adj-SID is printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{AdjSids: []AdjSID{{Sid: 24001}}}

		var buf bytes.Buffer
		printLink(&errWriter{w: &buf}, link)

		assert.Contains(t, buf.String(), "Adj-SID: 24001")
	})

	t.Run("a nil SRv6 End.X SID entry is skipped", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{Srv6EndXSIDs: []*Srv6EndXSID{nil, {Sids: []string{tedInternalTestSRv6SID1}}}}

		var buf bytes.Buffer
		printLink(&errWriter{w: &buf}, link)

		assert.Contains(t, buf.String(), fmt.Sprintf("SIDs: [%s]", tedInternalTestSRv6SID1))
	})

	t.Run("metrics are printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{Metrics: []*Metric{nil, {Type: IGPMetric, Value: 10}}}

		var buf bytes.Buffer
		printLink(&errWriter{w: &buf}, link)

		assert.Contains(t, buf.String(), "igp: 10")
	})

	t.Run("SRv6 End.X SID is printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{
			Srv6EndXSIDs: []*Srv6EndXSID{{
				EndpointBehavior: 5,
				Sids:             []string{tedInternalTestSRv6SID1},
				Srv6SIDStructure: &SIDStructure{LocalBlock: 1, LocalNode: 2, LocalFunc: 3, LocalArg: 4},
			}},
		}

		var buf bytes.Buffer
		printLink(&errWriter{w: &buf}, link)

		assert.Contains(t, buf.String(), "SRv6 End.X SID:")
		assert.Contains(t, buf.String(), "EndpointBehavior: "+BehaviorToString(5))
		assert.Contains(t, buf.String(), fmt.Sprintf("SIDs: [%s]", tedInternalTestSRv6SID1))
		assert.Contains(t, buf.String(), "Block: 1, Node: 2, Func: 3, Arg: 4")
	})
}

func TestPrintNodeLinks(t *testing.T) {
	t.Parallel()

	t.Run("node with links", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{Links: []*LsLink{nil, {Remote: LinkEndpoint{Node: &LsNode{RouterID: "R2"}}}}}

		var buf bytes.Buffer
		printNodeLinks(&errWriter{w: &buf}, node)

		assert.Contains(t, buf.String(), "RemoteNode: R2")
	})

	t.Run("node with no links", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{}

		var buf bytes.Buffer
		printNodeLinks(&errWriter{w: &buf}, node)

		assert.Contains(t, buf.String(), "Links:")
	})
}

func TestPrintNodePrefixes(t *testing.T) {
	t.Parallel()

	t.Run("no prefixes", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		printNodePrefixes(&errWriter{w: &buf}, &LsNode{})
		assert.Contains(t, buf.String(), "Prefixes:")
	})

	t.Run("prefix without SID", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}}}

		var buf bytes.Buffer
		printNodePrefixes(&errWriter{w: &buf}, node)
		assert.Contains(t, buf.String(), "10.0.0.1/32")
	})

	t.Run("prefix with SID", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 10, HasSidIndex: true}}}

		var buf bytes.Buffer
		printNodePrefixes(&errWriter{w: &buf}, node)
		assert.Contains(t, buf.String(), "10.0.0.1/32")
		assert.Contains(t, buf.String(), "index: 10")
	})

	t.Run("nil prefixes are skipped", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{Prefixes: []*LsPrefix{nil, {Prefix: netip.MustParsePrefix("10.0.0.1/32")}}}

		var buf bytes.Buffer
		printNodePrefixes(&errWriter{w: &buf}, node)
		assert.Contains(t, buf.String(), "10.0.0.1/32")
	})
}

func TestPrintNodeSRv6SIDs(t *testing.T) {
	t.Parallel()

	t.Run("no SRv6 SIDs", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		printNodeSRv6SIDs(&errWriter{w: &buf}, &LsNode{})
		assert.Contains(t, buf.String(), "SRv6 SIDs:")
	})

	t.Run("SRv6 SID with structure and endpoint behavior", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{
			SRv6SIDs: []*LsSrv6SID{
				{
					Sids:             []string{tedInternalTestSRv6SID1},
					SIDStructure:     &SIDStructure{LocalBlock: 1, LocalNode: 2, LocalFunc: 3, LocalArg: 4},
					EndpointBehavior: EndpointBehavior{Behavior: 5, Flags: 6, Algorithm: 7},
					MultiTopoIDs:     []uint32{0, 1},
				},
			},
		}

		var buf bytes.Buffer
		printNodeSRv6SIDs(&errWriter{w: &buf}, node)
		assert.Contains(t, buf.String(), fmt.Sprintf("SIDs: [%s]", tedInternalTestSRv6SID1))
		assert.Contains(t, buf.String(), "Block: 1, Node: 2, Func: 3, Arg: 4")
		assert.Contains(t, buf.String(), "EndpointBehavior: "+BehaviorToString(5))
		assert.Contains(t, buf.String(), "Flags: 6, Algorithm: 7")
		assert.Contains(t, buf.String(), "MultiTopoIDs: [0 1]")
	})

	t.Run("nil SRv6 SIDs are skipped", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{
			SRv6SIDs: []*LsSrv6SID{
				nil,
				{Sids: []string{tedInternalTestSRv6SID1}},
			},
		}

		var buf bytes.Buffer
		printNodeSRv6SIDs(&errWriter{w: &buf}, node)
		assert.Contains(t, buf.String(), fmt.Sprintf("SIDs: [%s]", tedInternalTestSRv6SID1))
	})
}

func TestPrintNodes(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID: "R1",
		Hostname: "router1",
		Links: []*LsLink{
			{Remote: LinkEndpoint{Node: &LsNode{RouterID: "R2"}}},
		},
	}
	nodes := map[string]*LsNode{"R1": node}

	var buf bytes.Buffer
	printNodes(&errWriter{w: &buf}, nodes)
	assert.Contains(t, buf.String(), "R1")
	assert.Contains(t, buf.String(), "router1")
}

func TestPrintNodes_WithNilNode(t *testing.T) {
	t.Parallel()

	nodes := map[string]*LsNode{"R1": nil}

	var buf bytes.Buffer
	printNodes(&errWriter{w: &buf}, nodes)
	assert.Empty(t, buf.String())
}

func TestLsLink_Families(t *testing.T) {
	t.Parallel()

	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")

	tests := []struct {
		name string
		link *LsLink
		want AddressFamilySet
	}{
		{
			name: "v4-only",
			link: &LsLink{Local: LinkEndpoint{IPv4: v4}, Remote: LinkEndpoint{IPv4: v4}},
			want: AddressFamilySetIPv4,
		},
		{
			name: "v6-only",
			link: &LsLink{Local: LinkEndpoint{IPv6: v6}, Remote: LinkEndpoint{IPv6: v6}},
			want: AddressFamilySetIPv6,
		},
		{
			name: "dual-stack",
			link: &LsLink{
				Local:  LinkEndpoint{IPv4: v4, IPv6: v6},
				Remote: LinkEndpoint{IPv4: v4, IPv6: v6},
			},
			want: AddressFamilySetIPv4 | AddressFamilySetIPv6,
		},
		{
			name: "one side missing the address excludes that family",
			link: &LsLink{
				Local:  LinkEndpoint{IPv4: v4, IPv6: v6},
				Remote: LinkEndpoint{IPv4: v4},
			},
			want: AddressFamilySetIPv4,
		},
		{
			name: "neither side has an address",
			link: &LsLink{},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.link.Families())
		})
	}
}

func TestLsLink_KeyAndUpdateTED(t *testing.T) {
	t.Parallel()

	t.Run("re-advertising the same (nodes, interface IDs) merges into one link", func(t *testing.T) {
		t.Parallel()

		ted := &LsTED{Nodes: map[string]*LsNode{}}
		ifaceID := uint32(5)

		link1 := &LsLink{
			Local:   LinkEndpoint{Node: NewLsNode(1, "A"), InterfaceID: &ifaceID},
			Remote:  LinkEndpoint{Node: NewLsNode(1, "B")},
			Metrics: []*Metric{NewMetric(IGPMetric, 10)},
		}
		link1.UpdateTED(ted, 1)

		link2 := &LsLink{
			Local:   LinkEndpoint{Node: NewLsNode(1, "A"), InterfaceID: &ifaceID},
			Remote:  LinkEndpoint{Node: NewLsNode(1, "B")},
			Metrics: []*Metric{NewMetric(IGPMetric, 20)},
		}
		link2.UpdateTED(ted, 1)

		require.Len(t, ted.Nodes["A"].Links, 1)
		metric, err := ted.Nodes["A"].Links[0].Metric(IGPMetric)
		require.NoError(t, err)
		assert.Equal(t, uint32(20), metric, "the later advertisement should replace the earlier one")
	})

	t.Run("a different interface ID produces a distinct parallel link", func(t *testing.T) {
		t.Parallel()

		ted := &LsTED{Nodes: map[string]*LsNode{}}
		ifaceID1, ifaceID2 := uint32(5), uint32(6)

		link1 := &LsLink{
			Local:  LinkEndpoint{Node: NewLsNode(1, "A"), InterfaceID: &ifaceID1},
			Remote: LinkEndpoint{Node: NewLsNode(1, "B")},
		}
		link1.UpdateTED(ted, 1)

		link2 := &LsLink{
			Local:  LinkEndpoint{Node: NewLsNode(1, "A"), InterfaceID: &ifaceID2},
			Remote: LinkEndpoint{Node: NewLsNode(1, "B")},
		}
		link2.UpdateTED(ted, 1)

		assert.Len(t, ted.Nodes["A"].Links, 2)
	})
}

func TestLsLink_Validate(t *testing.T) {
	t.Parallel()

	linkLocal := netip.MustParseAddr("fe80::1")
	global := netip.MustParseAddr("2001:db8::1")
	ifaceID := uint32(3)

	tests := []struct {
		name    string
		link    *LsLink
		wantErr bool
	}{
		{
			name:    "local link-local IPv6 without an interface ID is rejected",
			link:    &LsLink{Local: LinkEndpoint{IPv6: linkLocal}},
			wantErr: true,
		},
		{
			name:    "local link-local IPv6 with an interface ID is accepted",
			link:    &LsLink{Local: LinkEndpoint{IPv6: linkLocal, InterfaceID: &ifaceID}},
			wantErr: false,
		},
		{
			name:    "remote link-local IPv6 without an interface ID is rejected",
			link:    &LsLink{Remote: LinkEndpoint{IPv6: linkLocal}},
			wantErr: true,
		},
		{
			name:    "a global IPv6 address needs no interface ID",
			link:    &LsLink{Local: LinkEndpoint{IPv6: global}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.link.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
