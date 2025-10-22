// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"net/netip"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newSessionDelCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "del",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("requires session address\nUsage: pola session del [session address]")
			}
			ssAddr, err := netip.ParseAddr(args[0])
			if err != nil {
				return fmt.Errorf("invalid input\nUsage: pola session del [session address]")
			}
			if err := delSession(ssAddr, jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}
}

func delSession(session netip.Addr, jsonFlag bool) error {
	request := &pb.DeleteSessionRequest{
		Addr: session.AsSlice(),
	}
	err := grpc.DeleteSession(client, request)
	if err != nil {
		return err
	}
	if jsonFlag {
		fmt.Printf("{\"status\": \"success\"}\n")
	} else {
		fmt.Printf("success!\n")
	}
	return nil
}
