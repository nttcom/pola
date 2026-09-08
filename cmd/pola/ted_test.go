// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewTEDCmd_RunE(t *testing.T) {
	t.Parallel()

	c := &cli{}
	cmd := newTEDCmd(c)

	c.client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{
		Enabled: true,
		Nodes:   []*pb.LsNode{{RouterId: testRouterID1}},
	}}

	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.RunE(cmd, []string{}))

	c.client = &fakePCEServiceClient{tedErr: assert.AnError}
	err := cmd.RunE(cmd, []string{})
	require.ErrorIs(t, err, assert.AnError)
}

func TestShowTED(t *testing.T) {
	t.Parallel()

	t.Run("grpc error propagates", func(t *testing.T) {
		t.Parallel()

		client := &fakePCEServiceClient{tedErr: assert.AnError}

		var buf bytes.Buffer

		err := showTED(&buf, outputText, client)
		require.Error(t, err)
	})

	t.Run("disabled TED returns an error", func(t *testing.T) {
		t.Parallel()

		client := &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enabled: false}}

		var buf bytes.Buffer

		err := showTED(&buf, outputText, client)
		require.ErrorContains(t, err, "TED is disabled by polad")
	})

	t.Run("disabled TED returns an error even in JSON mode", func(t *testing.T) {
		t.Parallel()

		client := &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enabled: false}}

		var buf bytes.Buffer

		err := showTED(&buf, outputJSON, client)
		require.ErrorContains(t, err, "TED is disabled by polad")
	})

	t.Run("plain text output", func(t *testing.T) {
		t.Parallel()

		client := &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{
			Enabled: true,
			Nodes:   []*pb.LsNode{{RouterId: testRouterID1}},
		}}

		var buf bytes.Buffer
		require.NoError(t, showTED(&buf, outputText, client))
		assert.Contains(t, buf.String(), testRouterID1)
	})

	t.Run("json output", func(t *testing.T) {
		t.Parallel()

		node := &pb.LsNode{
			Asn:      65000,
			RouterId: testRouterID1,
			Hostname: "routerA",
			Links: []*pb.LsLink{
				{
					Local:   &pb.LsLinkEndpoint{RouterId: testRouterID1, Ipv4: testPeerAddr1},
					Remote:  &pb.LsLinkEndpoint{RouterId: testRouterID1},
					Metrics: []*pb.Metric{{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10}},
					AdjSids: []*pb.AdjSid{{Family: pb.AddressFamily_ADDRESS_FAMILY_IPV4, Sid: 24001}},
				},
				{
					Local:   &pb.LsLinkEndpoint{RouterId: testRouterID1},
					Remote:  &pb.LsLinkEndpoint{RouterId: testRouterID1, Ipv4: testPeerAddr2},
					AdjSids: []*pb.AdjSid{{Family: pb.AddressFamily_ADDRESS_FAMILY_IPV4, Sid: 24002}},
				},
			},
			Prefixes: []*pb.LsPrefix{
				{Prefix: "10.0.0.1/32", SidIndex: proto.Uint32(1)},
				{Prefix: "10.0.0.2/32"},
			},
			Srv6Sids: []*pb.LsSrv6SID{{
				Sids:             []*pb.SID{{Sid: "2001:db8:1::"}},
				EndpointBehavior: &pb.EndpointBehavior{Behavior: 1},
				SidStructure:     &pb.SidStructure{},
			}},
		}
		client := &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enabled: true, Nodes: []*pb.LsNode{node}}}

		var buf bytes.Buffer
		require.NoError(t, showTED(&buf, outputJSON, client))

		var nodes []map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &nodes))
		require.Len(t, nodes, 1)
		nodeMap := nodes[0]
		assert.Equal(t, "routerA", nodeMap["hostname"])
		//nolint:testifylint // exact integer values after JSON float64 decoding.
		assert.Equal(t, float64(65000), nodeMap["asn"])

		links, ok := nodeMap["links"].([]any)
		require.True(t, ok)
		require.Len(t, links, 2)
		linkMap, ok := links[0].(map[string]any)
		require.True(t, ok)

		localMap, ok := linkMap["local"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, testPeerAddr1, localMap["ipv4"])

		remoteMap, ok := linkMap["remote"].(map[string]any)
		require.True(t, ok)

		_, hasRemoteIPv4 := remoteMap["ipv4"]
		assert.False(t, hasRemoteIPv4, "unset remote ipv4 must be omitted, not a \"None\" sentinel")

		linkMap2, ok := links[1].(map[string]any)
		require.True(t, ok)

		localMap2, ok := linkMap2["local"].(map[string]any)
		require.True(t, ok)

		_, hasLocalIPv4 := localMap2["ipv4"]
		assert.False(t, hasLocalIPv4)

		remoteMap2, ok := linkMap2["remote"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, testPeerAddr2, remoteMap2["ipv4"])

		prefixes, ok := nodeMap["prefixes"].([]any)
		require.True(t, ok)
		require.Len(t, prefixes, 2)
		prefixMap, ok := prefixes[0].(map[string]any)
		require.True(t, ok)
		//nolint:testifylint // exact integer values after JSON float64 decoding.
		assert.Equal(t, float64(1), prefixMap["sidIndex"])

		_, hasSidIndex := prefixes[1].(map[string]any)["sidIndex"]
		assert.False(t, hasSidIndex)

		srv6SIDs, ok := nodeMap["srv6Sids"].([]any)
		require.True(t, ok)
		assert.Len(t, srv6SIDs, 1)
	})

	t.Run("dual-stack link shows both IPv4 and IPv6 addresses", func(t *testing.T) {
		t.Parallel()

		ifaceID := uint32(9)
		node := &pb.LsNode{
			Asn:      65000,
			RouterId: testRouterID1,
			Links: []*pb.LsLink{
				{
					Local: &pb.LsLinkEndpoint{
						RouterId:    testRouterID1,
						Ipv4:        testPeerAddr1,
						Ipv6:        "2001:db8::1",
						InterfaceId: new(ifaceID),
					},
					Remote: &pb.LsLinkEndpoint{
						RouterId: testRouterID2,
						Ipv4:     testPeerAddr2,
						Ipv6:     "2001:db8::2",
					},
				},
			},
		}
		client := &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{
			Enabled: true,
			Nodes:   []*pb.LsNode{node, {RouterId: testRouterID2}},
		}}

		t.Run("json", func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			require.NoError(t, showTED(&buf, outputJSON, client))

			var nodes []map[string]any
			require.NoError(t, json.Unmarshal(buf.Bytes(), &nodes))

			var link map[string]any

			for _, n := range nodes {
				if n["routerId"] != testRouterID1 {
					continue
				}

				links, ok := n["links"].([]any)
				require.True(t, ok)
				require.Len(t, links, 1)
				link, ok = links[0].(map[string]any)
				require.True(t, ok)
			}

			require.NotNil(t, link)

			local, ok := link["local"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, testPeerAddr1, local["ipv4"])
			assert.Equal(t, "2001:db8::1", local["ipv6"])
			//nolint:testifylint // exact integer value after JSON float64 decoding.
			assert.Equal(t, float64(ifaceID), local["interfaceId"])

			remote, ok := link["remote"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, testPeerAddr2, remote["ipv4"])
			assert.Equal(t, "2001:db8::2", remote["ipv6"])
		})

		t.Run("text", func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			require.NoError(t, showTED(&buf, outputText, client))

			out := buf.String()
			assert.Contains(t, out, testPeerAddr1)
			assert.Contains(t, out, "2001:db8::1")
			assert.Contains(t, out, testPeerAddr2)
			assert.Contains(t, out, "2001:db8::2")
			assert.Contains(t, out, "interface 9")
		})
	})
}
