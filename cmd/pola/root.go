// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	pb "github.com/nttcom/pola/api/grpc"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var client pb.PceServiceClient
var jsonFmt bool

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "pola",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			jFlag, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonFmt = jFlag
			host, err := cmd.Flags().GetString("host")
			if err != nil {
				return err
			}
			port, err := cmd.Flags().GetString("port")
			if err != nil {
				return err
			}
			conn, err := grpc.Dial(host+":"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				conn.Close()
				return err
			}

			client = pb.NewPceServiceClient(conn)
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.PersistentFlags().BoolP("json", "j", false, "output json format")
	rootCmd.PersistentFlags().String("host", "127.0.0.1", "polad connection address")
	rootCmd.PersistentFlags().StringP("port", "p", "50051", "polad connection port")

	rootCmd.AddCommand(newSessionCmd(), newSRPolicyCmd(), newTedCmd())
	return rootCmd
}
