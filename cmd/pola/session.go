// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

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
			if err := showSession(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}
	return sessionCmd
}

func showSession(jsonFlag bool) error {
	sessionAddrList, err := getSessionAddrList(client)
	if err != nil {
		return err
	}
	if jsonFlag {
		// output json format
		peerAddrs := []map[string]string{}
		for _, peerAddr := range sessionAddrList {
			peerAddrInfo := map[string]string{
				"address": net.IP(peerAddr).String(),
				"status":  "active",
			}
			peerAddrs = append(peerAddrs, peerAddrInfo)
		}
		output_map := map[string]interface{}{
			"sessions": peerAddrs,
		}
		output_json, err := json.Marshal(output_map)
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", string(output_json))
	} else {
		//output user-friendly format
		for i, peerAddr := range sessionAddrList {
			fmt.Printf("sessionAddr(%d): %v\n", i, net.IP(peerAddr))
		}
	}
	return nil
}
