// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "list",
		RunE: showSRPolicyList,
	}
}

func showSRPolicyList(cmd *cobra.Command, args []string) error {
	jsonFlag, err := cmd.Flags().GetBool("json")
	if err != nil {
		return err
	}

	srPolicies, err := grpc.GetSRPolicyList(client)
	if err != nil {
		return err
	}

	if jsonFlag {
		// Output JSON format
		outputJSON, err := json.Marshal(srPolicies)
		if err != nil {
			return err
		}
		fmt.Println(string(outputJSON))
	} else {
		// Output user-friendly format
		if len(srPolicies) == 0 {
			fmt.Println("no SR Policies")
		} else {
			for ssID, pols := range srPolicies {
				fmt.Printf("Session: %s\n", ssID)
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
	}
	return nil
}
