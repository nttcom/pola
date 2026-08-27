// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session [peer-address] [detail]",
		Short: "Show PCEP sessions",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			addr, detail, err := parseSessionArgs(args)
			if err != nil {
				return err
			}
			return showSession(os.Stdout, addr, detail, resolveOutputFormat(jsonFmt))
		},
	}

	cmd.AddCommand(newSessionDeleteCmd())
	return cmd
}

// parseSessionArgs parses an optional peer address and "detail" argument.
func parseSessionArgs(args []string) (netip.Addr, bool, error) {
	var addr netip.Addr
	detail := false
	for _, arg := range args {
		if arg == "detail" {
			if detail {
				return netip.Addr{}, false, errors.New(`"detail" specified more than once`)
			}
			detail = true
			continue
		}
		if addr.IsValid() {
			return netip.Addr{}, false, fmt.Errorf("unexpected argument %q\nUsage: pola session [peer-address] [detail]", arg)
		}
		parsed, err := netip.ParseAddr(arg)
		if err != nil {
			return netip.Addr{}, false, fmt.Errorf("invalid peer address %q: %w", arg, err)
		}
		addr = parsed
	}
	return addr, detail, nil
}

func showSession(w io.Writer, addr netip.Addr, detail bool, format outputFormat) error {
	sessions, err := grpc.GetSessions(client, addr, detail)
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		return writeNoSessions(w, addr, format)
	}

	views := make([]sessionView, 0, len(sessions))
	for _, ss := range sessions {
		views = append(views, newSessionView(ss, detail))
	}

	if format == outputJSON {
		return writeJSON(w, views)
	}
	return writeSessionText(w, views)
}

func writeNoSessions(w io.Writer, addr netip.Addr, format outputFormat) error {
	if format == outputJSON {
		_, err := fmt.Fprintln(w, "[]")
		return err
	}
	if addr.IsValid() {
		_, err := fmt.Fprintf(w, "No PCEP session for %s.\n", addr)
		return err
	}
	_, err := fmt.Fprintln(w, "No PCEP sessions connected.")
	return err
}
