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

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newSessionDeleteCmd(c *cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:          cmdNameDelete,
		Aliases:      []string{"del"},
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("requires session address\nUsage: pola session delete [session address]")
			}
			ssAddr, err := netip.ParseAddr(args[0])
			if err != nil {
				return errors.New("invalid input\nUsage: pola session delete [session address]")
			}
			return deleteSession(cmd.OutOrStdout(), ssAddr, c.jsonFmt, c.client)
		},
	}
	return cmd
}

func deleteSession(out io.Writer, session netip.Addr, jsonFlag bool, client pb.PCEServiceClient) error {
	request := &pb.DeleteSessionRequest{
		PeerAddr: session.AsSlice(),
	}
	err := grpc.DeleteSession(client, request)
	if err != nil {
		return err
	}
	if jsonFlag {
		return writeJSON(out, statusResult{Status: statusSuccess})
	}
	fmt.Fprintln(out, "success!")
	return nil
}
