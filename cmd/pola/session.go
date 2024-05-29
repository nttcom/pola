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
	sessions, err := grpc.GetSessions(client)

	if err != nil {
		return err
	}

	if jsonFlag {
		// Output JSON format
		outputJSON, err := json.Marshal(sessions)
		if err != nil {
			return err
		}
		fmt.Println(string(outputJSON))
	} else {
		// Output user-friendly format
		for i, ss := range sessions {
			fmt.Printf("sessionAddr(%d): %s\n", i, ss.Addr.String())
			fmt.Printf("  State: %s\n", ss.State)
			fmt.Printf("  Capabilities: %s\n", ss.Caps)
			fmt.Printf("  IsSynced: %t\n", ss.IsSynced)
		}
	}
	return nil
}
