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
		return fmt.Errorf("failed to retrieve 'json' flag: %v", err)
	}

	srPolicies, err := grpc.GetSRPolicyList(client)
	if err != nil {
		return fmt.Errorf("failed to retrieve SR policy list: %v", err)
	}

	if jsonFlag {
		// Output in JSON format
		outputJSON, err := json.Marshal(srPolicies)
		if err != nil {
			return fmt.Errorf("failed to marshal SR policy list to JSON: %v", err)
		}
		fmt.Println(string(outputJSON))
	} else {
		// Output in user-friendly format
		if len(srPolicies) == 0 {
			fmt.Println("No SR Policies found.")
		} else {
			for sessionID, policies := range srPolicies {
				fmt.Printf("Session: %s\n", sessionID)
				for _, policy := range policies {
					fmt.Printf("  PolicyName: %s\n", policy.Name)
					fmt.Printf("    SrcAddr: %s\n", policy.SrcAddr)
					fmt.Printf("    DstAddr: %s\n", policy.DstAddr)
					fmt.Printf("    Color: %d\n", policy.Color)
					fmt.Printf("    Preference: %d\n", policy.Preference)
					fmt.Printf("    SegmentList: ")

					if len(policy.SegmentList) == 0 {
						fmt.Println("None")
					} else {
						for j, segment := range policy.SegmentList {
							fmt.Print(segment.SidString())
							if j == len(policy.SegmentList)-1 {
								fmt.Println()
							} else {
								fmt.Print(" -> ")
							}
						}
					}
				}
				fmt.Println()
			}
		}
	}
	return nil
}
