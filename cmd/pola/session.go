// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"
	"strconv"
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

func displaySessionID(sessionID *uint32) string {
	if sessionID == nil {
		return "-"
	}
	return strconv.FormatUint(uint64(*sessionID), 10)
}

func timersDisplay(timers *grpc.SessionTimers) string {
	if timers == nil {
		return "-"
	}
	return fmt.Sprintf("Keepalive %d, DeadTimer %d", timers.Keepalive, timers.DeadTimer)
}

func showSession(jsonFlag bool) error {
	sessions, err := grpc.GetSessions(client)

	if err != nil {
		return err
	}

	if jsonFlag {
		outputJSON, err := json.Marshal(sessions)
		if err != nil {
			return err
		}
		fmt.Println(string(outputJSON))
	} else {
		for i, ss := range sessions {
			fmt.Printf("sessionAddr(%d): %s\n", i, ss.Addr.String())
			fmt.Printf("  State: %s\n", ss.State)
			fmt.Printf("  SessionID (Pola): %s, SessionID (PCC): %s\n",
				displaySessionID(ss.LocalSessionID), displaySessionID(ss.PccSessionID))
			fmt.Printf("  Advertised (Pola): %s\n", timersDisplay(ss.LocalTimers))
			fmt.Printf("  Advertised (PCC):  %s\n", timersDisplay(ss.PccTimers))
			fmt.Printf("  Effective: Keepalive %d, DeadTimer %d\n",
				ss.EffectiveTimers.Keepalive, ss.EffectiveTimers.DeadTimer)
			fmt.Printf("  PccType: %s\n", ss.PccType)
			fmt.Printf("  Capabilities (Pola): %s\n", strings.Join(ss.CapStrings(), ", "))
			fmt.Printf("  Capabilities (PCC): %s\n", strings.Join(ss.PccCapStrings(), ", "))
			fmt.Printf("  IsSynced: %t\n", ss.IsSynced)
		}
	}
	return nil
}
