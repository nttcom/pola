package main

import (
	pb "github.com/nttcom/pola/api/grpc"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var client pb.PceServiceClient

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "pola",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	rootCmd.AddCommand(newSessionCmd(), newLspCmd())
	return rootCmd
}
