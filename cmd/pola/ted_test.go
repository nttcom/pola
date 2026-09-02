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
	jsonFmt = false
	cmd := newTEDCmd()

	client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{
		Enabled: true,
		Nodes:   []*pb.LsNode{{RouterId: testRouterID1}},
	}}
	captureStdout(t, func() {
		require.NoError(t, cmd.RunE(cmd, []string{}))
	})

	client = &fakePCEServiceClient{tedErr: assert.AnError}
	err := cmd.RunE(cmd, []string{})
	require.ErrorIs(t, err, assert.AnError)
}

func TestShowTED(t *testing.T) {
	t.Run("grpc error propagates", func(t *testing.T) {
		client = &fakePCEServiceClient{tedErr: assert.AnError}
		var buf bytes.Buffer
		err := showTED(&buf, outputText)
		require.Error(t, err)
	})

	t.Run("disabled TED returns an error", func(t *testing.T) {
		client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enabled: false}}
		var buf bytes.Buffer
		err := showTED(&buf, outputText)
		require.ErrorContains(t, err, "TED is disabled by polad")
	})

	t.Run("disabled TED returns an error even in JSON mode", func(t *testing.T) {
		client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enabled: false}}
		var buf bytes.Buffer
		err := showTED(&buf, outputJSON)
		require.ErrorContains(t, err, "TED is disabled by polad")
	})

	t.Run("plain text output", func(t *testing.T) {
		client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{
			Enabled: true,
			Nodes:   []*pb.LsNode{{RouterId: testRouterID1}},
		}}
		var buf bytes.Buffer
		require.NoError(t, showTED(&buf, outputText))
		assert.Contains(t, buf.String(), testRouterID1)
	})

	t.Run("json output", func(t *testing.T) {
		node := &pb.LsNode{
			Asn:      65000,
			RouterId: testRouterID1,
			Hostname: "routerA",
			Links: []*pb.LsLink{
				{
					LocalRouterId:  testRouterID1,
					RemoteRouterId: testRouterID1,
					LocalIp:        testPeerAddr1,
					Metrics:        []*pb.Metric{{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10}},
					AdjSid:         24001,
				},
				{
					LocalRouterId:  testRouterID1,
					RemoteRouterId: testRouterID1,
					RemoteIp:       testPeerAddr2,
					AdjSid:         24002,
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
		client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enabled: true, Nodes: []*pb.LsNode{node}}}

		var buf bytes.Buffer
		require.NoError(t, showTED(&buf, outputJSON))

		var nodes []map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &nodes))
		require.Len(t, nodes, 1)
		nodeMap := nodes[0]
		assert.Equal(t, "routerA", nodeMap["hostname"])
		//nolint:testifylint // float-compare: JSON decodes numbers to float64, and these are exact small integers.
		assert.Equal(t, float64(65000), nodeMap["asn"])

		links, ok := nodeMap["links"].([]any)
		require.True(t, ok)
		require.Len(t, links, 2)
		linkMap, ok := links[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, testPeerAddr1, linkMap["localIp"])
		_, hasRemoteIP := linkMap["remoteIp"]
		assert.False(t, hasRemoteIP, "unset remoteIp must be omitted, not a \"None\" sentinel")

		linkMap2, ok := links[1].(map[string]any)
		require.True(t, ok)
		_, hasLocalIP := linkMap2["localIp"]
		assert.False(t, hasLocalIP)
		assert.Equal(t, testPeerAddr2, linkMap2["remoteIp"])

		prefixes, ok := nodeMap["prefixes"].([]any)
		require.True(t, ok)
		require.Len(t, prefixes, 2)
		prefixMap, ok := prefixes[0].(map[string]any)
		require.True(t, ok)
		//nolint:testifylint // float-compare: JSON decodes numbers to float64, and this is an exact small integer.
		assert.Equal(t, float64(1), prefixMap["sidIndex"])
		_, hasSidIndex := prefixes[1].(map[string]any)["sidIndex"]
		assert.False(t, hasSidIndex)

		srv6SIDs, ok := nodeMap["srv6Sids"].([]any)
		require.True(t, ok)
		assert.Len(t, srv6SIDs, 1)
	})
}
