// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"github.com/spf13/cobra"
)

func newLspCmd() *cobra.Command {

	lspCmd := &cobra.Command{
		Use: "lsp",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	lspCmd.AddCommand(newLspListCmd(), newLspAddCmd())
	return lspCmd
}
