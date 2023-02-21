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

func newSRPolicyListCmd() *cobra.Command {

	srPolicyListCmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := showSRPolicyList(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	return srPolicyListCmd
}

func showSRPolicyList(jsonFlag bool) error {

	srPolicies, err := getSRPolicyList(client)
	if err != nil {
		return err
	}
	if jsonFlag {
		output_json, err := json.Marshal(srPolicies)
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", string(output_json))
	} else {
		//output user-friendly format
		if len(srPolicies) == 0 {
			fmt.Printf("no SR Policies\n")
			return nil
		}
		for ssId, pols := range srPolicies {
			fmt.Printf("Session: %s\n", ssId)
			for _, pol := range pols {
				fmt.Printf("  PolicyName: %s\n", pol.Name)
				fmt.Printf("    SrcAddr: %s\n", pol.SrcAddr)
				fmt.Printf("    DstAddr: %s\n", pol.DstAddr)
				fmt.Printf("    Color: %d\n", pol.Color)
				fmt.Printf("    Preference: %d\n", pol.Preference)
				fmt.Printf("    SegmentList: ")

				if len(pol.SegmentList) == 0 {
					fmt.Printf("None \n")
				} else {
					for j, seg := range pol.SegmentList {
						fmt.Printf("%s", seg.SidString())
						if j == len(pol.SegmentList)-1 {
							fmt.Printf("\n")
						} else {
							fmt.Printf(" -> ")
						}
					}
				}
			}
			fmt.Printf("\n")
		}
	}

	return nil
}
