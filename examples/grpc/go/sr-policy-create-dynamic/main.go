// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command sr-policy-create-dynamic creates a dynamic SR Policy.
// Requires a populated TED.
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

	ssAddr := netip.MustParseAddr("192.0.2.1")

	_, err = c.CreateSRPolicy(ctx, &pb.CreateSRPolicyRequest{
		Asn: 65000,
		SrPolicy: &pb.SRPolicy{
			PeerAddr:         ssAddr.AsSlice(),
			HeadendRouterId:  "0000.0aff.0001",
			EndpointRouterId: "0000.0aff.0004",
			Color:            100,
			PolicyName:       "sample-name",
			CandidatePath: &pb.CandidatePath{
				Path: &pb.CandidatePath_Dynamic{
					Dynamic: &pb.DynamicPath{
						Metric: pb.MetricType_METRIC_TYPE_TE,
						// Optional: constrain the computed path through these routers.
						Waypoints: []*pb.Waypoint{
							{RouterId: "0000.0aff.0002"},
						},
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("c.CreateSRPolicy error: %v", err) //nolint:gocritic // main exits immediately.
	}

	log.Print("success")
}
