// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/spf13/cobra"
)

func newSRPolicyCmd(client *pb.PCEServiceClient, jsonFmt *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use: "sr-policy",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newSRPolicyListCmd(client, jsonFmt), newSRPolicyAddCmd(client, jsonFmt), newSRPolicyDeleteCmd(client, jsonFmt))
	return cmd
}
