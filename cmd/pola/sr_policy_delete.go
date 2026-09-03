// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	yaml "gopkg.in/yaml.v2"

	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyDeleteCmd(c *cli) *cobra.Command {
	srPolicyDeleteCmd := &cobra.Command{
		Use: cmdNameDelete,
		RunE: func(cmd *cobra.Command, _ []string) error {
			filepath, err := cmd.Flags().GetString("file")
			if err != nil {
				return fmt.Errorf("failed to retrieve 'file' flag: %w", err)
			}

			if filepath == "" {
				return errors.New("file path option \"-f filepath\" is mandatory")
			}

			//nolint:gosec // G304: the file path comes from the operator's -f flag.
			f, err := os.Open(filepath)
			if err != nil {
				return fmt.Errorf("failed to open file \"%s\": %w", filepath, err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to close file \"%s\": %v\n", filepath, err)
				}
			}()

			var inputData inputFormat
			if err := yaml.NewDecoder(f).Decode(&inputData); err != nil {
				return fmt.Errorf("YAML syntax error in file \"%s\": %w", filepath, err)
			}

			if err := deleteSRPolicy(cmd.OutOrStdout(), inputData, c.jsonFmt, c.client); err != nil {
				return fmt.Errorf("failed to delete SR policy: %w", err)
			}

			return nil
		},
	}

	srPolicyDeleteCmd.Flags().StringP("file", "f", "", "[mandatory] path to YAML formatted LSP information file")

	return srPolicyDeleteCmd
}

func deleteSRPolicy(out io.Writer, input inputFormat, jsonFlag bool, client pb.PCEServiceClient) error {
	if !input.SRPolicy.PCEPSessionAddr.IsValid() || input.SRPolicy.Color == 0 || !input.SRPolicy.DstAddr.IsValid() || input.SRPolicy.Name == "" {
		sampleInput := "srPolicy:\n" +
			"  pcepSessionAddr: 192.0.2.1\n" +
			"  dstAddr: 192.0.2.2\n" +
			"  color: 100\n" +
			"  name: name\n"
		errMsg := "invalid input\n" +
			"Input example is below:\n\n" +
			sampleInput

		return errors.New(errMsg)
	}

	srPolicy := &pb.SRPolicy{
		PeerAddr:   input.SRPolicy.PCEPSessionAddr.AsSlice(),
		DstAddr:    input.SRPolicy.DstAddr.AsSlice(),
		Color:      input.SRPolicy.Color,
		PolicyName: input.SRPolicy.Name,
	}

	inputData := &pb.DeleteSRPolicyRequest{
		SrPolicy: srPolicy,
		Asn:      input.ASN,
	}
	if err := grpc.DeleteSRPolicy(client, inputData); err != nil {
		if st, ok := status.FromError(err); ok {
			return fmt.Errorf("gRPC Server Error: %s", st.Message())
		}

		return fmt.Errorf("gRPC Server Error: %s", err.Error())
	}

	if jsonFlag {
		return writeJSON(out, statusResult{Status: statusSuccess})
	}

	fmt.Fprintln(out, "success!")

	return nil
}
