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

	pb "github.com/nttcom/pola/api/pola/v1"
)

func main() {
	flag.Parse()

	conn, err := grpc.NewClient(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("unable to connect: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("warning: failed to close connection: %v", err)
		}
	}()

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ret, err := c.GetTED(ctx, &pb.GetTEDRequest{})
	if err != nil {
		log.Fatalf("unable to get TED info: %v", err)
	}

	for _, node := range ret.GetLsNodes() {
		fmt.Printf("node info: %#v\n", node)
		for _, prefix := range node.GetLsPrefixes() {
			fmt.Printf("prefix info: %#v\n", prefix)
		}
		for _, link := range node.GetLsLinks() {
			fmt.Printf("link info: %#v\n", link)
		}
		fmt.Println()
	}
}
