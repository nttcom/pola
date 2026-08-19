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
	"google.golang.org/protobuf/proto"
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
					Addr:            netip.MustParseAddr("192.0.2.1").AsSlice(),
					State:           pb.SessionState_SESSION_STATE_UP,
					IsSynced:        true,
					LocalSessionId:  proto.Uint32(1),
					PccSessionId:    proto.Uint32(7),
					LocalTimers:     &pb.SessionTimers{Keepalive: 30, DeadTimer: 120},
					PccTimers:       &pb.SessionTimers{Keepalive: 10, DeadTimer: 40},
					EffectiveTimers: &pb.EffectiveTimers{Keepalive: 30, DeadTimer: 40},
					PccType:         pb.PccType_PCC_TYPE_RFC_COMPLIANT,
					Capabilities: []*pb.Capability{
						{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: 10}}},
					},
					PccCapabilities: []*pb.Capability{
						{Type: pb.CapabilityType_CAPABILITY_TYPE_SR, Detail: &pb.Capability_Sr{Sr: &pb.SrCapability{Msd: 16}}},
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
		assert.Equal(t, "sessionAddr(0): 192.0.2.1\n"+
			"  State: UP\n"+
			"  SessionID (Pola): 1, SessionID (PCC): 7\n"+
			"  Advertised (Pola): Keepalive 30, DeadTimer 120\n"+
			"  Advertised (PCC):  Keepalive 10, DeadTimer 40\n"+
			"  Effective: Keepalive 30, DeadTimer 40\n"+
			"  PccType: RFC_COMPLIANT\n"+
			"  Capabilities (Pola): SR, MSD=10\n"+
			"  Capabilities (PCC): SR, MSD=16\n"+
			"  IsSynced: true\n", out)
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
		assert.Equal(t, "UP", decoded[0]["State"])
		assert.Equal(t, true, decoded[0]["IsSynced"])
	})

	t.Run("advertised values are omitted before the Open exchange", func(t *testing.T) {
		client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{
			Sessions: []*pb.Session{{
				Addr:  netip.MustParseAddr("192.0.2.1").AsSlice(),
				State: pb.SessionState_SESSION_STATE_OPEN_WAIT,
			}},
		}}
		out := captureStdout(t, func() {
			require.NoError(t, showSession(false))
		})
		assert.Contains(t, out, "State: OPEN_WAIT")
		assert.Contains(t, out, "SessionID (Pola): -, SessionID (PCC): -")
		assert.Contains(t, out, "Advertised (Pola): -")
	})

	t.Run("a session ID of zero is distinguished from an unset one", func(t *testing.T) {
		client = &fakePCEServiceClient{sessionListResp: &pb.GetSessionListResponse{
			Sessions: []*pb.Session{{
				Addr:           netip.MustParseAddr("192.0.2.1").AsSlice(),
				State:          pb.SessionState_SESSION_STATE_UP,
				LocalSessionId: proto.Uint32(0),
				PccSessionId:   proto.Uint32(0),
			}},
		}}
		out := captureStdout(t, func() {
			require.NoError(t, showSession(false))
		})
		assert.Contains(t, out, "SessionID (Pola): 0, SessionID (PCC): 0")
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		client = &fakePCEServiceClient{sessionListErr: assert.AnError}
		err := showSession(false)
		require.ErrorIs(t, err, assert.AnError)
	})
}
