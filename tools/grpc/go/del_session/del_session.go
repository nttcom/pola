// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/nttcom/pola/api/grpc"
)

func main() {
	flag.Parse()
	conn, err := grpc.NewClient(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPceServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ss := &pb.Session{
		Addr: netip.MustParseAddr("192.0.2.1").AsSlice(),
	}
	ret, err := c.DeleteSession(ctx, ss)
	if err != nil {
		log.Fatalf("CreateLsp error: %v", err)
	}
	log.Printf("Success: %#v", ret)
}
