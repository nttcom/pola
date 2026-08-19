// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"net/netip"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newSessionDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "delete",
		Aliases:      []string{"del"},
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("requires session address\nUsage: pola session delete [session address]")
			}
			ssAddr, err := netip.ParseAddr(args[0])
			if err != nil {
				return errors.New("invalid input\nUsage: pola session delete [session address]")
			}
			if err := deleteSession(ssAddr, jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}
	return cmd
}

func deleteSession(session netip.Addr, jsonFlag bool) error {
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
