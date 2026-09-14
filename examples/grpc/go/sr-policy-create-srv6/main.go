// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command sr-policy-create-srv6 creates an explicit SRv6 SR Policy.
// TED-based path computation and SID validation are disabled.
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
	defer func() { _ = conn.Close() }() //nolint:errcheck // best-effort cleanup

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	ssAddr := netip.MustParseAddr("2001:db8::1")
	headend := netip.MustParseAddr("2001:db8::1")
	endpoint := netip.MustParseAddr("2001:db8::2")

	_, err = c.CreateSRPolicy(ctx, &pb.CreateSRPolicyRequest{
		SrPolicy: &pb.SRPolicy{
			PeerAddr:   ssAddr.AsSlice(),
			Headend:    headend.AsSlice(),
			Endpoint:   endpoint.AsSlice(),
			Color:      100,
			PolicyName: "sample-srv6",
			CandidatePath: &pb.CandidatePath{
				Path: &pb.CandidatePath_Explicit{
					Explicit: &pb.ExplicitPath{
						SegmentList: []*pb.Segment{
							{
								Sid:          "2001:db8:1005::",
								LocalAddr:    "2001:db8::5",
								SidStructure: "32,16,0,80",
							},
							{
								Sid:          "2001:db8:1006::",
								LocalAddr:    "2001:db8::6",
								SidStructure: "32,16,0,80",
							},
						},
					},
				},
			},
		},
		NoSidValidate: true,
	})
	if err != nil {
		log.Fatalf("c.CreateSRPolicy error: %v", err) //nolint:gocritic // main exits immediately.
	}

	log.Print("success")
}
