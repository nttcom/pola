// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"os"

	pb "github.com/nttcom/pola/api/grpc"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"

	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyDeleteCmd() *cobra.Command {
	srPolicyDeleteCmd := &cobra.Command{
		Use: "delete",
		RunE: func(cmd *cobra.Command, args []string) error {
			filepath, err := cmd.Flags().GetString("file")
			if err != nil {
				return fmt.Errorf("failed to retrieve 'file' flag: %v", err)
			}
			if filepath == "" {
				return fmt.Errorf("file path option \"-f filepath\" is mandatory")
			}

			f, err := os.Open(filepath)
			if err != nil {
				return fmt.Errorf("failed to open file \"%s\": %v", filepath, err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to close file \"%s\": %v\n", filepath, err)
				}
			}()

			var inputData InputFormat
			if err := yaml.NewDecoder(f).Decode(&inputData); err != nil {
				return fmt.Errorf("failed to decode file \"%s\": %v", filepath, err)
			}

			if err := deleteSRPolicy(inputData, jsonFmt); err != nil {
				return fmt.Errorf("failed to delete SR policy: %v", err)
			}
			return nil
		},
	}

	srPolicyDeleteCmd.Flags().StringP("file", "f", "", "[mandatory] path to YAML formatted LSP information file")

	return srPolicyDeleteCmd
}

func deleteSRPolicy(input InputFormat, jsonFlag bool) error {
	if !input.SRPolicy.PcepSessionAddr.IsValid() || input.SRPolicy.Color == 0 || !input.SRPolicy.DstAddr.IsValid() || input.SRPolicy.Name == "" {
		sampleInput := "srPolicy:\n" +
			"  pcepSessionAddr: 192.0.2.1\n" +
			"  dstAddr: 192.0.2.2\n" +
			"  color: 100\n" +
			"  name: name\n"
		errMsg := "invalid input\n" +
			"input example is below\n\n" +
			sampleInput

		return errors.New(errMsg)
	}

	srPolicy := &pb.SRPolicy{
		PcepSessionAddr: input.SRPolicy.PcepSessionAddr.AsSlice(),
		DstAddr:         input.SRPolicy.DstAddr.AsSlice(),
		Color:           input.SRPolicy.Color,
		PolicyName:      input.SRPolicy.Name,
	}
	inputData := &pb.DeleteSRPolicyInput{
		SRPolicy: srPolicy,
		Asn:      input.Asn,
	}
	if err := grpc.DeleteSRPolicy(client, inputData); err != nil {
		return fmt.Errorf("gRPC Server Error: %s", err.Error())
	}

	if jsonFlag {
		fmt.Printf("{\"status\": \"success\"}\n")
	} else {
		fmt.Printf("success!\n")
	}

	return nil
}
