// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command sr-policy-create-no-sid-validate creates an explicit SR Policy
// without TED-based path computation or SID validation.
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
	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")

	r, err := c.CreateSRPolicy(ctx, &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			PcepSessionAddr: ssAddr.AsSlice(),
			SrcAddr:         srcAddr.AsSlice(),
			DstAddr:         dstAddr.AsSlice(),
			Color:           100,
			PolicyName:      "sample-name",
			Type:            pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
			SegmentList: []*pb.Segment{
				{Sid: "16002"},
				{Sid: "16003"},
				{Sid: "16004"},
			},
		},
		DisablePathCompute: true,
		NoSidValidate:      true,
	})
	if err != nil {
		log.Fatalf("c.CreateSRPolicy error: %v", err)
	}

	log.Printf("success: isSuccess=%t", r.GetIsSuccess())
}
