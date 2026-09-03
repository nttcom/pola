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
)

const tedInternalTestSRv6SID1 = "2001:db8::1"

func TestPrintLink(t *testing.T) {
	t.Parallel()

	t.Run("missing IPs and RemoteNode fall back to None", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		printLink(&buf, &LsLink{})

		assert.Contains(t, buf.String(), "Local: None Remote: None")
		assert.Contains(t, buf.String(), "RemoteNode: None")
	})

	t.Run("populated IPs and RemoteNode are printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{
			LocalIP:    netip.MustParseAddr("192.0.2.1"),
			RemoteIP:   netip.MustParseAddr("192.0.2.2"),
			RemoteNode: &LsNode{RouterID: "R2"},
		}

		var buf bytes.Buffer
		printLink(&buf, link)

		assert.Contains(t, buf.String(), "Local: 192.0.2.1 Remote: 192.0.2.2")
		assert.Contains(t, buf.String(), "RemoteNode: R2")
	})

	t.Run("metrics are printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{Metrics: []*Metric{nil, {Type: IGPMetric, Value: 10}}}

		var buf bytes.Buffer
		printLink(&buf, link)

		assert.Contains(t, buf.String(), "igp: 10")
	})

	t.Run("SRv6 End.X SID is printed", func(t *testing.T) {
		t.Parallel()

		link := &LsLink{
			Srv6EndXSID: &Srv6EndXSID{
				EndpointBehavior: 5,
				Sids:             []string{tedInternalTestSRv6SID1},
				Srv6SIDStructure: SIDStructure{LocalBlock: 1, LocalNode: 2, LocalFunc: 3, LocalArg: 4},
			},
		}

		var buf bytes.Buffer
		printLink(&buf, link)

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

		node := &LsNode{Links: []*LsLink{nil, {RemoteNode: &LsNode{RouterID: "R2"}}}}

		var buf bytes.Buffer
		printNodeLinks(&buf, node)

		assert.Contains(t, buf.String(), "RemoteNode: R2")
	})

	t.Run("node with no links", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{}

		var buf bytes.Buffer
		printNodeLinks(&buf, node)

		assert.Contains(t, buf.String(), "Links:")
	})
}

func TestPrintNodePrefixes(t *testing.T) {
	t.Parallel()

	t.Run("no prefixes", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		printNodePrefixes(&buf, &LsNode{})
		assert.Contains(t, buf.String(), "Prefixes:")
	})

	t.Run("prefix without SID", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32")}}}

		var buf bytes.Buffer
		printNodePrefixes(&buf, node)
		assert.Contains(t, buf.String(), "10.0.0.1/32")
	})

	t.Run("prefix with SID", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{Prefixes: []*LsPrefix{{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 10, HasSidIndex: true}}}

		var buf bytes.Buffer
		printNodePrefixes(&buf, node)
		assert.Contains(t, buf.String(), "10.0.0.1/32")
		assert.Contains(t, buf.String(), "index: 10")
	})

	t.Run("nil prefixes are skipped", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{Prefixes: []*LsPrefix{nil, {Prefix: netip.MustParsePrefix("10.0.0.1/32")}}}

		var buf bytes.Buffer
		printNodePrefixes(&buf, node)
		assert.Contains(t, buf.String(), "10.0.0.1/32")
	})
}

func TestPrintNodeSRv6SIDs(t *testing.T) {
	t.Parallel()

	t.Run("no SRv6 SIDs", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		printNodeSRv6SIDs(&buf, &LsNode{})
		assert.Contains(t, buf.String(), "SRv6 SIDs:")
	})

	t.Run("SRv6 SID with structure and endpoint behavior", func(t *testing.T) {
		t.Parallel()

		node := &LsNode{
			SRv6SIDs: []*LsSrv6SID{
				{
					Sids:             []string{tedInternalTestSRv6SID1},
					SIDStructure:     SIDStructure{LocalBlock: 1, LocalNode: 2, LocalFunc: 3, LocalArg: 4},
					EndpointBehavior: EndpointBehavior{Behavior: 5, Flags: 6, Algorithm: 7},
					MultiTopoIDs:     []uint32{0, 1},
				},
			},
		}

		var buf bytes.Buffer
		printNodeSRv6SIDs(&buf, node)
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
		printNodeSRv6SIDs(&buf, node)
		assert.Contains(t, buf.String(), fmt.Sprintf("SIDs: [%s]", tedInternalTestSRv6SID1))
	})
}

func TestPrintNodes(t *testing.T) {
	t.Parallel()

	node := &LsNode{
		RouterID: "R1",
		Hostname: "router1",
		Links: []*LsLink{
			{RemoteNode: &LsNode{RouterID: "R2"}},
		},
	}
	nodes := map[string]*LsNode{"R1": node}

	var buf bytes.Buffer
	printNodes(&buf, nodes)
	assert.Contains(t, buf.String(), "R1")
	assert.Contains(t, buf.String(), "router1")
}

func TestPrintNodes_WithNilNode(t *testing.T) {
	t.Parallel()

	nodes := map[string]*LsNode{"R1": nil}

	var buf bytes.Buffer
	printNodes(&buf, nodes)
	assert.Empty(t, buf.String())
}
