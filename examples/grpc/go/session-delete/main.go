// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command session-delete deletes a PCEP session via the DeleteSession RPC.
package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/nttcom/pola/api/pola/v1"
)

const requestTimeout = 10 * time.Second

func main() {
	serverAddr := flag.String("server", "localhost:50051", "address of the polad gRPC server")
	flag.Parse()

	conn, err := grpc.NewClient(
		*serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("unable to connect to %s: %v", *serverAddr, err)
	}
	defer func() { _ = conn.Close() }()

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	r, err := c.DeleteSession(ctx, &pb.DeleteSessionRequest{
		Addr: netip.MustParseAddr("192.0.2.1").AsSlice(),
	})
	if err != nil {
		log.Fatalf("c.DeleteSession error: %v", err)
	}

	log.Printf("success: isSuccess=%t", r.GetIsSuccess())
}
