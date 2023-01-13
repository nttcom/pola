// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newSrPolicyListCmd() *cobra.Command {

	srPolicyListCmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := showSrPolicyList(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	return srPolicyListCmd
}

func showSrPolicyList(jsonFlag bool) error {

	lspList, err := getSrPolicyList(client)
	if err != nil {
		return err
	}
	if jsonFlag {
		// output json format
		lsps := []map[string]interface{}{}
		for _, lsp := range lspList {
			tmp := map[string]interface{}{ // TODO: Fix format according to readme
				"peerAddr":    lsp.peerAddr.String(),
				"policyName":  lsp.name,
				"srcAddr":     lsp.srcAddr.String(),
				"dstAddr":     lsp.dstAddr.String(),
				"color":       lsp.color,
				"preference":  lsp.preference,
				"segmentList": lsp.path,
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
		if len(lspList) == 0 {
			fmt.Printf("no SR Policies\n")
			return nil
		}
		for i, lsp := range lspList {
			fmt.Printf("LSP(%d): \n", i)
			fmt.Printf("  PcepSessionAddr: %s\n", lsp.peerAddr)
			fmt.Printf("  PolicyName: %s\n", lsp.name)
			fmt.Printf("  SrcAddr: %s\n", lsp.srcAddr.String())
			fmt.Printf("  DstAddr: %s\n", lsp.dstAddr.String())
			fmt.Printf("  Color: %d\n", lsp.color)
			fmt.Printf("  Preference: %d\n", lsp.preference)
			fmt.Printf("  DstAddr: %s\n", lsp.dstAddr.String())
			fmt.Printf("  SegmentList: ")

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
