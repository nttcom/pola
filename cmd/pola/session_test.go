// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"net/netip"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionCmd_RunE(t *testing.T) {
	jsonFmt = false
	cmd := newSessionCmd()

	client = &fakePCEServiceClient{}
	captureStdout(t, func() {
		require.NoError(t, cmd.RunE(cmd, []string{}))
	})

	client = &fakePCEServiceClient{sessionListErr: assert.AnError}
	err := cmd.RunE(cmd, []string{})
	require.ErrorIs(t, err, assert.AnError)
}

func TestShowSession(t *testing.T) {
	newFake := func() *fakePCEServiceClient {
		return &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{
			Sessions: []*pb.Session{
				{
					Addr:     netip.MustParseAddr("192.0.2.1").AsSlice(),
					State:    pb.SessionState_SESSION_STATE_UP,
					IsSynced: true,
					Capabilities: []*pb.Capability{
						{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: 10}}},
					},
				},
			},
		}}
	}

	t.Run("plain text format", func(t *testing.T) {
		client = newFake()
		out := captureStdout(t, func() {
			require.NoError(t, showSession(false))
		})
		assert.Equal(t, "sessionAddr(0): 192.0.2.1\n  State: SESSION_STATE_UP\n  Capabilities: SR, MSD=10\n  IsSynced: true\n", out)
	})

	t.Run("json format", func(t *testing.T) {
		client = newFake()
		out := captureStdout(t, func() {
			require.NoError(t, showSession(true))
		})

		var decoded []map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &decoded))
		require.Len(t, decoded, 1)
		assert.Equal(t, "192.0.2.1", decoded[0]["Addr"])
		assert.Equal(t, "SESSION_STATE_UP", decoded[0]["State"])
		assert.Equal(t, true, decoded[0]["IsSynced"])
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		client = &fakePCEServiceClient{sessionListErr: assert.AnError}
		err := showSession(false)
		require.ErrorIs(t, err, assert.AnError)
	})
}
