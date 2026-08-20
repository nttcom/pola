// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command sr-policy-create-explicit creates an explicit SR Policy.
package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/nttcom/pola/api/pola/v1"
)

const requestTimeout = 10 * time.Second

func main() {
	serverAddr := flag.String("server", "localhost:50051", "address of the polad gRPC server")
	flag.Parse()

	conn, err := grpc.NewClient(
		*serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("unable to connect to %s: %v", *serverAddr, err)
	}
	defer func() { _ = conn.Close() }()

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	ssAddr := netip.MustParseAddr("192.0.2.1")

	_, err = c.CreateSRPolicy(ctx, &pb.CreateSRPolicyRequest{
		Asn: 65000,
		SrPolicy: &pb.SRPolicy{
			PeerAddr:    ssAddr.AsSlice(),
			SrcRouterId: "0000.0aff.0001",
			DstRouterId: "0000.0aff.0004",
			Color:       100,
			PolicyName:  "sample-name",
			Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
			SegmentList: []*pb.Segment{
				{Sid: "16002"},
				{Sid: "16003"},
				{Sid: "16004"},
			},
		},
		DisablePathCompute: false,
	})
	if err != nil {
		log.Fatalf("c.CreateSRPolicy error: %v", err)
	}

	log.Print("success")
}
