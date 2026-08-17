// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
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
		Enable:  true,
		LsNodes: []*pb.LsNode{{RouterId: "0000.0aff.0001"}},
	}}
	captureStdout(t, func() {
		require.NoError(t, cmd.RunE(cmd, []string{}))
	})

	client = &fakePCEServiceClient{tedErr: assert.AnError}
	err := cmd.RunE(cmd, []string{})
	require.ErrorIs(t, err, assert.AnError)
}

func TestPrintTED(t *testing.T) {
	t.Run("grpc error propagates", func(t *testing.T) {
		client = &fakePCEServiceClient{tedErr: assert.AnError}
		err := printTED(false)
		require.Error(t, err)
	})

	t.Run("disabled TED prints a dedicated message", func(t *testing.T) {
		client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enable: false}}
		out := captureStdout(t, func() {
			require.NoError(t, printTED(false))
		})
		assert.Contains(t, out, "TED is disabled by polad")
	})

	t.Run("plain text output delegates to LsTED.Print", func(t *testing.T) {
		client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{
			Enable:  true,
			LsNodes: []*pb.LsNode{{RouterId: "0000.0aff.0001"}},
		}}
		out := captureStdout(t, func() {
			require.NoError(t, printTED(false))
		})
		assert.Contains(t, out, "0000.0aff.0001")
	})

	t.Run("json output", func(t *testing.T) {
		node := &pb.LsNode{
			Asn:      65000,
			RouterId: "0000.0aff.0001",
			Hostname: "routerA",
			LsLinks: []*pb.LsLink{
				{
					LocalRouterId:  "0000.0aff.0001",
					RemoteRouterId: "0000.0aff.0001",
					LocalIp:        "192.0.2.1",
					Metrics:        []*pb.Metric{{Type: pb.MetricType_METRIC_TYPE_IGP, Value: 10}},
					AdjSid:         24001,
				},
				{
					LocalRouterId:  "0000.0aff.0001",
					RemoteRouterId: "0000.0aff.0001",
					RemoteIp:       "192.0.2.2",
					AdjSid:         24002,
				},
			},
			LsPrefixes: []*pb.LsPrefix{
				{Prefix: "10.0.0.1/32", SidIndex: proto.Uint32(1)},
				{Prefix: "10.0.0.2/32"},
			},
			LsSrv6Sids: []*pb.LsSrv6SID{{
				Sids:             []*pb.SID{{Sid: "2001:db8:1::"}},
				EndpointBehavior: &pb.EndpointBehavior{Behavior: 1},
			}},
		}
		client = &fakePCEServiceClient{tedResp: &pb.GetTEDResponse{Enable: true, LsNodes: []*pb.LsNode{node}}}

		out := captureStdout(t, func() {
			require.NoError(t, printTED(true))
		})

		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &decoded))
		nodes, ok := decoded["ted"].([]any)
		require.True(t, ok)
		require.Len(t, nodes, 1)
		nodeMap := nodes[0].(map[string]any)
		assert.Equal(t, "routerA", nodeMap["hostname"])
		assert.Equal(t, float64(65000), nodeMap["asn"])

		links, ok := nodeMap["links"].([]any)
		require.True(t, ok)
		require.Len(t, links, 2)
		linkMap := links[0].(map[string]any)
		assert.Equal(t, "192.0.2.1", linkMap["localIP"])
		assert.Equal(t, "None", linkMap["remoteIP"])

		linkMap2 := links[1].(map[string]any)
		assert.Equal(t, "None", linkMap2["localIP"])
		assert.Equal(t, "192.0.2.2", linkMap2["remoteIP"])

		prefixes, ok := nodeMap["prefixes"].([]any)
		require.True(t, ok)
		require.Len(t, prefixes, 2)
		assert.Equal(t, float64(1), prefixes[0].(map[string]any)["sidIndex"])
		_, hasSidIndex := prefixes[1].(map[string]any)["sidIndex"]
		assert.False(t, hasSidIndex)

		srv6SIDs, ok := nodeMap["srv6SIDs"].([]any)
		require.True(t, ok)
		assert.Len(t, srv6SIDs, 1)
	})
}
