// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/pkg/table"
)

func newSRPolicyListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "list",
		RunE: showSRPolicyList,
	}
	cmd.Flags().String("session", "", "filter by PCEP session peer address")
	return cmd
}

func showSRPolicyList(cmd *cobra.Command, args []string) error {
	jsonFlag, err := cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("failed to retrieve 'json' flag: %v", err)
	}

	sessionAddr, err := sessionAddrFlag(cmd)
	if err != nil {
		return err
	}

	sessions, err := grpc.GetSRPolicyList(client, sessionAddr)
	if err != nil {
		return fmt.Errorf("failed to retrieve SR policy list: %v", err)
	}

	if jsonFlag {
		// Output in JSON format
		outputJSON, err := json.Marshal(sessions)
		if err != nil {
			return fmt.Errorf("failed to marshal SR policy list to JSON: %v", err)
		}
		fmt.Println(string(outputJSON))
	} else {
		// Output in user-friendly format
		if len(sessions) == 0 {
			fmt.Println("No SR Policies found.")
		} else {
			for _, session := range sessions {
				fmt.Printf("Session: %s\n", session.Addr.String())
				for _, policy := range session.SRPolicies {
					fmt.Printf("  PolicyName: %s\n", policy.Name)
					fmt.Printf("    PlspID: %d\n", policy.PlspID)
					fmt.Printf("    LSPID: %d\n", policy.LSPID)
					fmt.Printf("    State: %s\n", policy.State)
					if policy.Type != "" {
						fmt.Printf("    Type: %s\n", policy.Type)
					}
					if policy.Metric != table.UnspecifiedMetric {
						fmt.Printf("    Metric: %s\n", policy.Metric.DisplayString())
					}
					fmt.Printf("    SrcAddr: %s\n", srcDstDisplay(policy.SrcAddr.String(), policy.SrcRouterID))
					fmt.Printf("    DstAddr: %s\n", srcDstDisplay(policy.DstAddr.String(), policy.DstRouterID))
					fmt.Printf("    Color: %d\n", policy.Color)
					fmt.Printf("    Preference: %d\n", policy.Preference)
					fmt.Printf("    SegmentList: ")

					if len(policy.SegmentList) == 0 {
						fmt.Println("None")
					} else {
						for j, segment := range policy.SegmentList {
							fmt.Print(segmentDisplayString(segment))
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

func sessionAddrFlag(cmd *cobra.Command) (netip.Addr, error) {
	flag, err := cmd.Flags().GetString("session")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to retrieve 'session' flag: %v", err)
	}
	if flag == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(flag)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid --session address %q: %v", flag, err)
	}
	return addr, nil
}

func srcDstDisplay(addr, routerID string) string {
	if routerID == "" {
		return addr
	}
	return fmt.Sprintf("%s (%s)", addr, routerID)
}

func segmentDisplayString(seg table.Segment) string {
	var localAddr, remoteAddr string
	switch v := seg.(type) {
	case table.SegmentSRv6:
		if v.LocalAddr.IsValid() {
			localAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			remoteAddr = v.RemoteAddr.String()
		}
	case table.SegmentSRMPLS:
		if v.LocalAddr.IsValid() {
			localAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			remoteAddr = v.RemoteAddr.String()
		}
	}

	switch {
	case localAddr == "" && remoteAddr == "":
		return seg.SidString()
	case remoteAddr == "":
		return fmt.Sprintf("%s (local=%s)", seg.SidString(), localAddr)
	case localAddr == "":
		return fmt.Sprintf("%s (remote=%s)", seg.SidString(), remoteAddr)
	default:
		return fmt.Sprintf("%s (local=%s, remote=%s)", seg.SidString(), localAddr, remoteAddr)
	}
}
