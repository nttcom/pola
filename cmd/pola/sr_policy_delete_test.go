// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nttcom/pola/api/pola/v1"
)

func newTestSRPolicyDeleteCmd(client pb.PCEServiceClient) *cobra.Command {
	return newSRPolicyDeleteCmd(&cli{client: client})
}

func TestNewSRPolicyDeleteCmd_RunE(t *testing.T) {
	t.Parallel()

	t.Run("file flag not registered", func(t *testing.T) {
		t.Parallel()
		cmd := newTestSRPolicyDeleteCmd(nil)
		err := cmd.RunE(&cobra.Command{}, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'file' flag")
	})

	t.Run("missing file flag", func(t *testing.T) {
		t.Parallel()
		cmd := newTestSRPolicyDeleteCmd(nil)
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mandatory")
	})

	t.Run("file does not exist", func(t *testing.T) {
		t.Parallel()
		cmd := newTestSRPolicyDeleteCmd(nil)
		require.NoError(t, cmd.Flags().Set("file", filepath.Join(t.TempDir(), "missing.yaml")))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("not: [valid"), 0o600))
		cmd := newTestSRPolicyDeleteCmd(nil)
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "YAML syntax error")
	})

	t.Run("success delegates to deleteSRPolicy", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "policy.yaml")
		yamlContent := "srPolicy:\n" +
			"  pcepSessionAddr: 192.0.2.1\n" +
			"  dstAddr: 192.0.2.2\n" +
			"  color: 100\n" +
			"  name: pol1\n"
		require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o600))

		cmd := newTestSRPolicyDeleteCmd(&fakePCEServiceClient{})
		require.NoError(t, cmd.Flags().Set("file", path))
		cmd.SetOut(&bytes.Buffer{})
		require.NoError(t, cmd.RunE(cmd, []string{}))
	})

	t.Run("deleteSRPolicy error is wrapped", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("srPolicy:\n  name: incomplete\n"), 0o600))
		cmd := newTestSRPolicyDeleteCmd(nil)
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete SR policy")
	})
}

func TestDeleteSRPolicy(t *testing.T) {
	t.Parallel()

	validPolicy := func() srPolicy {
		return srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			DstAddr:         netip.MustParseAddr(testPeerAddr2),
			Color:           100,
			Name:            testPolicyName,
		}
	}

	t.Run("missing mandatory fields", func(t *testing.T) {
		t.Parallel()
		err := deleteSRPolicy(&bytes.Buffer{}, inputFormat{}, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("success builds the request", func(t *testing.T) {
		t.Parallel()
		fake := &fakePCEServiceClient{}
		var out bytes.Buffer
		require.NoError(t, deleteSRPolicy(&out, inputFormat{ASN: 65000, SRPolicy: validPolicy()}, false, fake))
		assert.Equal(t, "success!\n", out.String())

		require.NotNil(t, fake.deleteSRPolicyReq)
		assert.Equal(t, netip.MustParseAddr(testPeerAddr1).AsSlice(), fake.deleteSRPolicyReq.SrPolicy.PeerAddr)
		assert.Equal(t, netip.MustParseAddr(testPeerAddr2).AsSlice(), fake.deleteSRPolicyReq.SrPolicy.DstAddr)
		assert.Equal(t, uint32(100), fake.deleteSRPolicyReq.SrPolicy.Color)
		assert.Equal(t, testPolicyName, fake.deleteSRPolicyReq.SrPolicy.PolicyName)
		assert.Equal(t, uint32(65000), fake.deleteSRPolicyReq.Asn)
	})

	t.Run("json output on success", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		require.NoError(t, deleteSRPolicy(&out, inputFormat{ASN: 65000, SRPolicy: validPolicy()}, true, &fakePCEServiceClient{}))
		assert.JSONEq(t, "{\"status\": \"success\"}\n", out.String())
	})

	t.Run("grpc status error is unwrapped to its message", func(t *testing.T) {
		t.Parallel()
		fake := &fakePCEServiceClient{deleteSRPolicyErr: status.Error(codes.NotFound, "SR policy not found")}
		err := deleteSRPolicy(&bytes.Buffer{}, inputFormat{ASN: 65000, SRPolicy: validPolicy()}, false, fake)
		require.Error(t, err)
		assert.Equal(t, "gRPC Server Error: SR policy not found", err.Error())
	})

	t.Run("plain grpc error falls back to Error()", func(t *testing.T) {
		t.Parallel()
		fake := &fakePCEServiceClient{deleteSRPolicyErr: assert.AnError}
		err := deleteSRPolicy(&bytes.Buffer{}, inputFormat{ASN: 65000, SRPolicy: validPolicy()}, false, fake)
		require.Error(t, err)
		assert.Equal(t, "gRPC Server Error: "+assert.AnError.Error(), err.Error())
	})
}
