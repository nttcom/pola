// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "session",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := showSession(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.AddCommand(newSessionDeleteCmd())
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
			fmt.Printf("  Capabilities: %s\n", strings.Join(ss.CapStrings(), ", "))
			fmt.Printf("  IsSynced: %t\n", ss.IsSynced)
		}
	}
	return nil
}
