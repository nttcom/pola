package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

func newLspListCmd() *cobra.Command {

	lspListCmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonFmt, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			if err := showLspList(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	lspListCmd.Flags().BoolP("json", "j", false, "output json format")
	return lspListCmd
}

func showLspList(jsonFlag bool) error {

	lspList, err := getlspList(client)
	if err != nil {
		return err
	}
	if jsonFlag {
		// output json format
		lsps := []map[string]interface{}{}
		for _, lsp := range lspList {
			tmp := map[string]interface{}{ // TODO: Fix format according to readme
				"peerAddr":   lsp.peerAddr.String(),
				"policyName": lsp.name,
				"srcAddr":    net.IP(lsp.srcAddr).String(),
				"dstAddr":    net.IP(lsp.dstAddr).String(),
				"path":       lsp.path,
			}
			lsps = append(lsps, tmp)
		}
		output_map := map[string]interface{}{
			"lsps": lsps,
		}
		output_json, err := json.Marshal(output_map)
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", string(output_json))
	} else {
		//output user-friendly format
		for i, lsp := range lspList {
			fmt.Printf("lsp(%d): \n", i)
			fmt.Printf("  peerAddr: %s\n", lsp.peerAddr)
			fmt.Printf("  policyName: %s\n", lsp.name)
			fmt.Printf("  SrcAddr: %s\n", net.IP(lsp.srcAddr))
			fmt.Printf("  DstAddr: %s\n", net.IP(lsp.dstAddr))
			fmt.Printf("  path: ")

			if len(lsp.path) == 0 {
				fmt.Printf("None \n")
			} else {
				for j, sid := range lsp.path {
					fmt.Printf("%d ", sid)
					if j == len(lsp.path)-1 {
						fmt.Printf("\n")
					} else {
						fmt.Printf("-> ")
					}
				}
			}
			fmt.Printf("\n")
		}
	}

	return nil
}
