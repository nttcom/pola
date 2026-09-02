// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"net/netip"
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionDeleteCmd_DelAlias(t *testing.T) {
	var client pb.PCEServiceClient
	jsonFmt := false
	cmd := newSessionCmd(&client, &jsonFmt)
	found, _, err := cmd.Find([]string{"del"})
	require.NoError(t, err)
	assert.Equal(t, cmdNameDelete, found.Name())
}

func TestNewSessionDeleteCmd_ArgValidation(t *testing.T) {
	t.Run("missing address argument", func(t *testing.T) {
		var client pb.PCEServiceClient
		jsonFmt := false
		cmd := newSessionDeleteCmd(&client, &jsonFmt)
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires session address")
	})

	t.Run("invalid address", func(t *testing.T) {
		var client pb.PCEServiceClient
		jsonFmt := false
		cmd := newSessionDeleteCmd(&client, &jsonFmt)
		err := cmd.RunE(cmd, []string{"not-an-address"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("valid address delegates to deleteSession", func(t *testing.T) {
		var client pb.PCEServiceClient = &fakePCEServiceClient{}
		jsonFmt := false
		cmd := newSessionDeleteCmd(&client, &jsonFmt)
		captureStdout(t, func() {
			require.NoError(t, cmd.RunE(cmd, []string{testPeerAddr1}))
		})
	})

	t.Run("deleteSession error propagates", func(t *testing.T) {
		var client pb.PCEServiceClient = &fakePCEServiceClient{deleteSessionErr: assert.AnError}
		jsonFmt := false
		cmd := newSessionDeleteCmd(&client, &jsonFmt)
		err := cmd.RunE(cmd, []string{testPeerAddr1})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestDeleteSession(t *testing.T) {
	tests := []struct {
		name     string
		jsonFlag bool
		want     string
	}{
		{"plain text success", false, "success!\n"},
		{"json success", true, "{\"status\":\"success\"}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePCEServiceClient{}
			out := captureStdout(t, func() {
				require.NoError(t, deleteSession(netip.MustParseAddr(testPeerAddr1), tt.jsonFlag, fake))
			})
			assert.Equal(t, tt.want, out)
			require.NotNil(t, fake.deleteSessionReq)
			assert.Equal(t, netip.MustParseAddr(testPeerAddr1).AsSlice(), fake.deleteSessionReq.PeerAddr)
		})
	}

	t.Run("grpc error propagates", func(t *testing.T) {
		fake := &fakePCEServiceClient{deleteSessionErr: assert.AnError}
		err := deleteSession(netip.MustParseAddr(testPeerAddr1), false, fake)
		require.ErrorIs(t, err, assert.AnError)
	})
}
