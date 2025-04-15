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
		log.Fatalf("can't connect: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("warning: failed to close connection: %v", err)
		}
	}()

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ssAddr := netip.MustParseAddr("192.0.2.1")
	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	r, err := c.CreateSRPolicyWithoutLinkState(ctx, &pb.CreateSRPolicyInput{
		SRPolicy: &pb.SRPolicy{
			PCEPSessionAddr: ssAddr.AsSlice(),
			SrcAddr:         srcAddr.AsSlice(),
			DstAddr:         dstAddr.AsSlice(),
			Color:           uint32(100),
			PolicyName:      "sample-name",
			SegmentList: []*pb.Segment{
				{Sid: "16002"},
				{Sid: "16003"},
				{Sid: "16004"},
			},
		},
	})
	if err != nil {
		log.Fatalf("c.CreateSRPolicyWithoutLinkState error: %v", err)
	}

	log.Printf("Success: %#v", r)
}
