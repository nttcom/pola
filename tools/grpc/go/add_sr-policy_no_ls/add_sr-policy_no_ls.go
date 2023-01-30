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
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Can't connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPceServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ssAddr, _ := netip.ParseAddr("192.0.2.1")
	srcAddr, _ := netip.ParseAddr("192.0.2.1")
	dstAddr, _ := netip.ParseAddr("192.0.2.2")
	r, err := c.CreateSRPolicyWithoutLinkState(ctx, &pb.CreateSRPolicyInput{
		SRPolicy: &pb.SRPolicy{
			PcepSessionAddr: ssAddr.AsSlice(),
			SrcAddr:         srcAddr.AsSlice(),
			DstAddr:         dstAddr.AsSlice(),
			Color:           uint32(100),
			PolicyName:      "sample-name",
			SegmentList: []*pb.Segment{{Sid: "16002"},
				{Sid: "16003"},
				{Sid: "16004"},
			},
		},
	})
	if err != nil {
		log.Fatalf("CreateLsp error: %v", err)
	}
	log.Printf("Success: %#v", r)
}
