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

	pb "github.com/nttcom/pola/api/pola/v1"
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

	ret, err := c.GetSRPolicyList(ctx, &pb.GetSRPolicyListRequest{})
	if err != nil {
		log.Fatalf("unable to get SR policy list from server: %v", err)
	}

	for i, srPolicy := range ret.GetSrPolicies() {
		fmt.Printf("srPolicy(%d): \n", i)
		sessionAddr := net.IP(srPolicy.GetPcepSessionAddr())
		fmt.Printf("  sessionAddr: %s\n", sessionAddr.String())
		fmt.Printf("  policyName: %s\n", srPolicy.GetPolicyName())
		fmt.Printf("  SrcAddr: %s\n", net.IP(srPolicy.GetSrcAddr()))
		fmt.Printf("  DstAddr: %s\n", net.IP(srPolicy.GetDstAddr()))
		fmt.Printf("  path: ")

		if len(srPolicy.GetSegmentList()) == 0 {
			fmt.Printf("None\n")
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
