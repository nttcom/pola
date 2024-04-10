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
	var empty empty.Empty
	ret, err := c.GetSRPolicyList(ctx, &empty)
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	for i, srPolicy := range ret.GetSRPolicies() {
		fmt.Printf("srPolicy(%d): \n", i)
		sessionAddr := net.IP(srPolicy.GetPcepSessionAddr())
		fmt.Printf("  sessionAddr: %s\n", sessionAddr.String())
		fmt.Printf("  policyName: %s\n", srPolicy.GetPolicyName())
		fmt.Printf("  SrcAddr: %s\n", net.IP(srPolicy.GetSrcAddr()))
		fmt.Printf("  DstAddr: %s\n", net.IP(srPolicy.GetDstAddr()))
		fmt.Printf("  path: ")

		if len(srPolicy.GetSegmentList()) == 0 {
			fmt.Printf("None \n")
			continue
		}
		for j, segment := range srPolicy.GetSegmentList() {
			fmt.Printf("%s", segment.GetSid())
			if j == len(srPolicy.GetSegmentList())-1 {
				fmt.Printf("\n")
			} else {
				fmt.Printf(" -> ")
			}
		}
	}
}
