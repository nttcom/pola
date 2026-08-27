// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewSRPolicyDeleteCmd_RunE(t *testing.T) {
	t.Run("file flag not registered", func(t *testing.T) {
		cmd := newSRPolicyDeleteCmd()
		err := cmd.RunE(&cobra.Command{}, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'file' flag")
	})

	t.Run("missing file flag", func(t *testing.T) {
		cmd := newSRPolicyDeleteCmd()
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mandatory")
	})

	t.Run("file does not exist", func(t *testing.T) {
		cmd := newSRPolicyDeleteCmd()
		require.NoError(t, cmd.Flags().Set("file", filepath.Join(t.TempDir(), "missing.yaml")))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("not: [valid"), 0o600))
		cmd := newSRPolicyDeleteCmd()
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "YAML syntax error")
	})

	t.Run("success delegates to deleteSRPolicy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		yamlContent := "srPolicy:\n" +
			"  pcepSessionAddr: 192.0.2.1\n" +
			"  dstAddr: 192.0.2.2\n" +
			"  color: 100\n" +
			"  name: pol1\n"
		require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o600))

		client = &fakePCEServiceClient{}
		cmd := newSRPolicyDeleteCmd()
		require.NoError(t, cmd.Flags().Set("file", path))
		captureStdout(t, func() {
			require.NoError(t, cmd.RunE(cmd, []string{}))
		})
	})

	t.Run("deleteSRPolicy error is wrapped", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("srPolicy:\n  name: incomplete\n"), 0o600))
		cmd := newSRPolicyDeleteCmd()
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete SR policy")
	})
}

func TestDeleteSRPolicy(t *testing.T) {
	validPolicy := func() srPolicy {
		return srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			DstAddr:         netip.MustParseAddr(testPeerAddr2),
			Color:           100,
			Name:            testPolicyName,
		}
	}

	t.Run("missing mandatory fields", func(t *testing.T) {
		err := deleteSRPolicy(inputFormat{}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("success builds the request", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		client = fake
		out := captureStdout(t, func() {
			require.NoError(t, deleteSRPolicy(inputFormat{ASN: 65000, SRPolicy: validPolicy()}, false))
		})
		assert.Equal(t, "success!\n", out)

		require.NotNil(t, fake.deleteSRPolicyReq)
		assert.Equal(t, netip.MustParseAddr(testPeerAddr1).AsSlice(), fake.deleteSRPolicyReq.SrPolicy.PeerAddr)
		assert.Equal(t, netip.MustParseAddr(testPeerAddr2).AsSlice(), fake.deleteSRPolicyReq.SrPolicy.DstAddr)
		assert.Equal(t, uint32(100), fake.deleteSRPolicyReq.SrPolicy.Color)
		assert.Equal(t, testPolicyName, fake.deleteSRPolicyReq.SrPolicy.PolicyName)
		assert.Equal(t, uint32(65000), fake.deleteSRPolicyReq.Asn)
	})

	t.Run("json output on success", func(t *testing.T) {
		client = &fakePCEServiceClient{}
		out := captureStdout(t, func() {
			require.NoError(t, deleteSRPolicy(inputFormat{ASN: 65000, SRPolicy: validPolicy()}, true))
		})
		assert.JSONEq(t, "{\"status\": \"success\"}\n", out)
	})

	t.Run("grpc status error is unwrapped to its message", func(t *testing.T) {
		client = &fakePCEServiceClient{deleteSRPolicyErr: status.Error(codes.NotFound, "SR policy not found")}
		err := deleteSRPolicy(inputFormat{ASN: 65000, SRPolicy: validPolicy()}, false)
		require.Error(t, err)
		assert.Equal(t, "gRPC Server Error: SR policy not found", err.Error())
	})

	t.Run("plain grpc error falls back to Error()", func(t *testing.T) {
		client = &fakePCEServiceClient{deleteSRPolicyErr: assert.AnError}
		err := deleteSRPolicy(inputFormat{ASN: 65000, SRPolicy: validPolicy()}, false)
		require.Error(t, err)
		assert.Equal(t, "gRPC Server Error: "+assert.AnError.Error(), err.Error())
	})
}
