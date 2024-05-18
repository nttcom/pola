// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "session",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := showSession(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.AddCommand(newSessionDelCmd())
	return cmd
}

func showSession(jsonFlag bool) error {
	sessionAddrList, err := grpc.GetSessionAddrList(client)
	if err != nil {
		return err
	}

	if jsonFlag {
		// Output JSON format
		peerAddrs := make([]map[string]string, 0, len(sessionAddrList))
		for _, peerAddr := range sessionAddrList {
			peerAddrs = append(peerAddrs, map[string]string{
				"address": peerAddr.String(),
				"status":  "active",
			})
		}
		outputMap := map[string]interface{}{
			"sessions": peerAddrs,
		}
		outputJSON, err := json.Marshal(outputMap)
		if err != nil {
			return err
		}
		fmt.Println(string(outputJSON))
	} else {
		// Output user-friendly format
		for i, peerAddr := range sessionAddrList {
			fmt.Printf("sessionAddr(%d): %s\n", i, peerAddr.String())
		}
	}
	return nil
}
