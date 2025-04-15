// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	empty "github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
)

func main() {
	flag.Parse()

	conn, err := grpc.NewClient(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("unable to connect to the server: %v", err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("warning: failed to close connection: %v", err)
		}
	}()

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty

	ret, err := c.GetSessionList(ctx, &empty)
	if err != nil {
		log.Fatalf("unable to get session list from server: %v", err)
	}

	for i, ss := range ret.GetSessions() {
		addr, ok := netip.AddrFromSlice(ss.Addr)
		if !ok {
			log.Printf("invalid address for session %d: %v", i, ss.Addr)
			continue
		}
		fmt.Printf("peerAddr(%d): %v\n", i, addr)
	}
}
