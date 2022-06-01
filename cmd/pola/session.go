package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {

	sessionCmd := &cobra.Command{
		Use: "session",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonFmt, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			if err := showSession(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	sessionCmd.Flags().BoolP("json", "j", false, "output json format")
	return sessionCmd
}

func showSession(jsonFlag bool) error {
	peerAddrList, err := getPeerAddrList(client)
	if err != nil {
		return err
	}
	if jsonFlag {
		// output json format
		peerAddrs := []map[string]string{}
		for _, peerAddr := range peerAddrList {
			peerAddrInfo := map[string]string{
				"address": net.IP(peerAddr).String(),
				"status":  "active",
			}
			peerAddrs = append(peerAddrs, peerAddrInfo)
		}
		output_map := map[string]interface{}{
			"peers": peerAddrs,
		}
		output_json, err := json.Marshal(output_map)
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", string(output_json))
	} else {
		//output user-friendly format
		for i, peerAddr := range peerAddrList {
			fmt.Printf("peerAddr(%d): %v\n", i, net.IP(peerAddr))
		}
	}
	return nil
}
