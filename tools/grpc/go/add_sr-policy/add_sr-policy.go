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
		log.Fatalf("Can't connect: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("warning: failed to close connection: %v", err)
		}
	}()

	c := pb.NewPceServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ssAddr, _ := netip.ParseAddr("192.0.2.1")
	r, err := c.CreateSRPolicy(ctx, &pb.CreateSRPolicyInput{
		Asn: 65000,
		SRPolicy: &pb.SRPolicy{
			PcepSessionAddr: ssAddr.AsSlice(),
			SrcRouterID:     "0000.0aff.0001",
			DstRouterID:     "0000.0aff.0004",
			Color:           uint32(100),
			PolicyName:      "sample-name",
			Type:            pb.SRPolicyType_DYNAMIC,
			Metric:          pb.MetricType_TE,
		},
	})
	if err != nil {
		log.Fatalf("CreateLsp error: %v", err)
	}
	log.Printf("Success: %#v", r)
}
