// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"net"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	client  pb.PCEServiceClient
	jsonFmt bool
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "pola",
	}
	rootCmd.PersistentFlags().BoolVarP(&jsonFmt, "json", "j", false, "output json format")
	rootCmd.PersistentFlags().String("host", "127.0.0.1", "polad connection address")
	rootCmd.PersistentFlags().StringP("port", "p", "50051", "polad connection port")

	rootCmd.AddCommand(newSessionCmd(), newSRPolicyCmd(), newTEDCmd())
	rootCmd.PersistentPreRunE = persistentPreRunE
	rootCmd.Run = runRootCmd

	return rootCmd
}

func persistentPreRunE(cmd *cobra.Command, args []string) error {
	conn, err := grpc.NewClient(
		net.JoinHostPort(cmd.Flag("host").Value.String(), cmd.Flag("port").Value.String()),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to dial polad connection: %v", err)
	}

	client = pb.NewPCEServiceClient(conn)
	return nil
}

func runRootCmd(cmd *cobra.Command, args []string) {
	cmd.HelpFunc()(cmd, args)
}
