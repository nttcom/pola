// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"flag"
	"log"
	"net"
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

	r, err := c.CreateSrPolicyWithoutLinkState(ctx, &pb.CreateSrPolicyInput{
		SrPolicy: &pb.SrPolicy{
			PcepSessionAddr: []byte(net.ParseIP("192.0.2.1").To4()),
			SrcAddr:         []byte(net.ParseIP("192.0.2.1").To4()),
			DstAddr:         []byte(net.ParseIP("192.0.2.2").To4()),
			Color:           uint32(100),
			PolicyName:      "sample-name",
			SegmentList: []*pb.Segment{{Sid: 16002, LoAddr: []byte(net.ParseIP("10.255.0.2").To4())},
				{Sid: 16003, LoAddr: []byte(net.ParseIP("10.255.0.3").To4())},
				{Sid: 16004, LoAddr: []byte(net.ParseIP("10.255.0.4").To4())},
			},
		},
	})
	if err != nil {
		log.Fatalf("CreateLsp error: %v", err)
	}
	log.Printf("Success: %#v", r)
}
