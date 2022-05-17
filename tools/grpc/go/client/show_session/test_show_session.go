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
	"net"
	"time"

	"google.golang.org/grpc"

	empty "github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPceServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := c.GetPeerAddrList(ctx, &empty)
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	for i, peerAddr := range ret.GetPeerAddrs() {
		fmt.Printf("peerAddr(%d): %v\n", i, net.IP(peerAddr))
	}
}
