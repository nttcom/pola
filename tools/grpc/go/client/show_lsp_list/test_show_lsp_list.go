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
	"google.golang.org/grpc/credentials/insecure"

	empty "github.com/golang/protobuf/ptypes/empty"
	pb "github.com/nttcom/pola/api/grpc"
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPceServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var empty empty.Empty
	ret, err := c.GetLspList(ctx, &empty)
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	for i, lsp := range ret.GetLsps() {
		fmt.Printf("lsp(%d): \n", i)
		sessionAddr := net.IP(lsp.GetPcepSessionAddr())
		fmt.Printf("  sessionAddr: %s\n", sessionAddr.String())
		fmt.Printf("  policyName: %s\n", lsp.GetPolicyName())
		fmt.Printf("  SrcAddr: %s\n", net.IP(lsp.GetSrcAddr()))
		fmt.Printf("  DstAddr: %s\n", net.IP(lsp.GetDstAddr()))
		fmt.Printf("  path: ")

		if len(lsp.GetLabels()) == 0 {
			fmt.Printf("None \n")
			continue
		}
		for j, label := range lsp.GetLabels() {
			fmt.Printf("%d ", label.GetSid())
			if j == len(lsp.GetLabels())-1 {
				fmt.Printf("\n")
			} else {
				fmt.Printf("-> ")
			}
		}
	}
}
