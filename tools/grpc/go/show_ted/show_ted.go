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
		log.Fatalf("did not connect: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("warning: failed to close connection: %v", err)
		}
	}()

	c := pb.NewPceServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty

	ret, err := c.GetTed(ctx, &empty)
	if err != nil {
		log.Fatalf("did not get TED info: %v", err)
	}

	for _, node := range ret.GetLsNodes() {
		fmt.Printf("node info:\n")
		fmt.Printf("%#v\n", node)
		for _, prefix := range node.GetLsPrefixes() {
			fmt.Printf("prefix info:\n")
			fmt.Printf("%#v\n", prefix)
		}
		for _, link := range node.GetLsLinks() {
			fmt.Printf("link info:\n")
			fmt.Printf("%#v\n", link)
		}
		fmt.Printf("\n\n")
	}
}
