// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"github.com/spf13/cobra"
)

func newSRPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "sr-policy",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newSRPolicyListCmd(), newSRPolicyAddCmd())
	return cmd
}
