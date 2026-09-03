// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyListCmd(c *cli) *cobra.Command {
	cmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showSRPolicyList(cmd, args, c.client, c.jsonFmt)
		},
	}
	cmd.Flags().String("peer", "", "filter by PCEP peer address")
	return cmd
}

func showSRPolicyList(cmd *cobra.Command, _ []string, client pb.PCEServiceClient, jsonFmt bool) error {
	peerAddr, err := peerAddrFlag(cmd)
	if err != nil {
		return err
	}
	return writeSRPolicyList(os.Stdout, peerAddr, resolveOutputFormat(jsonFmt), client)
}

func writeSRPolicyList(w io.Writer, peerAddr netip.Addr, format outputFormat, client pb.PCEServiceClient) error {
	sessions, err := grpc.GetSRPolicyList(client, peerAddr)
	if err != nil {
		return fmt.Errorf("failed to retrieve SR policy list: %w", err)
	}

	if len(sessions) == 0 {
		return writeNoSessions(w, peerAddr, format)
	}

	views := make([]srPolicySessionView, 0, len(sessions))
	for _, ss := range sessions {
		views = append(views, newSRPolicySessionView(ss))
	}

	if format == outputJSON {
		return writeJSON(w, views)
	}
	return writeSRPolicyText(w, views)
}

func peerAddrFlag(cmd *cobra.Command) (netip.Addr, error) {
	flag, err := cmd.Flags().GetString("peer")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to retrieve 'peer' flag: %w", err)
	}
	if flag == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(flag)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid --peer address %q: %w", flag, err)
	}
	return addr, nil
}
