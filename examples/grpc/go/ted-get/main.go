// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command ted-get dumps the traffic engineering database via the GetTED RPC.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/nttcom/pola/api/pola/v1"
)

// The TED can hold thousands of nodes, so allow more time.
const requestTimeout = 30 * time.Second

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
	defer func() { _ = conn.Close() }() //nolint:errcheck // best-effort cleanup

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	ret, err := c.GetTED(ctx, &pb.GetTEDRequest{})
	if err != nil {
		log.Fatalf("unable to get TED info: %v", err) //nolint:gocritic // main exits immediately.
	}

	// A disabled TED returns an empty node list instead of an error.
	if !ret.GetEnabled() {
		fmt.Println("TED is disabled on this polad instance")
		return
	}

	marshaler := protojson.MarshalOptions{Multiline: true, Indent: "  "}
	for _, node := range ret.GetNodes() {
		fmt.Println(marshaler.Format(node))
	}
}
