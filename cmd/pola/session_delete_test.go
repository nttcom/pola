// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionDeleteCmd_DelAlias(t *testing.T) {
	t.Parallel()

	cmd := newSessionCmd(&cli{})
	found, _, err := cmd.Find([]string{"del"})
	require.NoError(t, err)
	assert.Equal(t, cmdNameDelete, found.Name())
}

func TestNewSessionDeleteCmd_ArgValidation(t *testing.T) {
	t.Parallel()

	t.Run("missing address argument", func(t *testing.T) {
		t.Parallel()
		cmd := newSessionDeleteCmd(&cli{})
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires session address")
	})

	t.Run("invalid address", func(t *testing.T) {
		t.Parallel()
		cmd := newSessionDeleteCmd(&cli{})
		err := cmd.RunE(cmd, []string{"not-an-address"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("valid address delegates to deleteSession", func(t *testing.T) {
		t.Parallel()
		cmd := newSessionDeleteCmd(&cli{client: &fakePCEServiceClient{}})
		cmd.SetOut(&bytes.Buffer{})
		require.NoError(t, cmd.RunE(cmd, []string{testPeerAddr1}))
	})

	t.Run("deleteSession error propagates", func(t *testing.T) {
		t.Parallel()
		cmd := newSessionDeleteCmd(&cli{client: &fakePCEServiceClient{deleteSessionErr: assert.AnError}})
		err := cmd.RunE(cmd, []string{testPeerAddr1})
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestDeleteSession(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			fake := &fakePCEServiceClient{}
			var out bytes.Buffer
			require.NoError(t, deleteSession(&out, netip.MustParseAddr(testPeerAddr1), tt.jsonFlag, fake))
			assert.Equal(t, tt.want, out.String())
			require.NotNil(t, fake.deleteSessionReq)
			assert.Equal(t, netip.MustParseAddr(testPeerAddr1).AsSlice(), fake.deleteSessionReq.PeerAddr)
		})
	}

	t.Run("grpc error propagates", func(t *testing.T) {
		t.Parallel()
		fake := &fakePCEServiceClient{deleteSessionErr: assert.AnError}
		err := deleteSession(&bytes.Buffer{}, netip.MustParseAddr(testPeerAddr1), false, fake)
		require.ErrorIs(t, err, assert.AnError)
	})
}
