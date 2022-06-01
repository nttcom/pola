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
