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

type cli struct {
	client  pb.PCEServiceClient
	jsonFmt bool
}

func newRootCmd() *cobra.Command {
	c := &cli{}

	rootCmd := &cobra.Command{
		Use: "pola",
	}
	rootCmd.PersistentFlags().BoolVarP(&c.jsonFmt, "json", "j", false, "output json format")
	rootCmd.PersistentFlags().String("host", "127.0.0.1", "polad connection address")
	rootCmd.PersistentFlags().StringP("port", "p", "50051", "polad connection port")

	rootCmd.AddCommand(newSessionCmd(c), newSRPolicyCmd(c), newTEDCmd(c))
	rootCmd.PersistentPreRunE = persistentPreRunE(c)
	rootCmd.Run = runRootCmd

	return rootCmd
}

func persistentPreRunE(c *cli) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		conn, err := grpc.NewClient(
			net.JoinHostPort(cmd.Flag("host").Value.String(), cmd.Flag("port").Value.String()),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return fmt.Errorf("failed to dial polad connection: %w", err)
		}

		c.client = pb.NewPCEServiceClient(conn)

		return nil
	}
}

func runRootCmd(cmd *cobra.Command, args []string) {
	cmd.HelpFunc()(cmd, args)
}
