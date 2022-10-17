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

	r, err := c.CreateSrPolicy(ctx, &pb.CreateSrPolicyInput{
		Asn: 65000,
		SrPolicy: &pb.SrPolicy{
			PcepSessionAddr: []byte(net.ParseIP("192.0.2.1").To4()),
			SrcRouterId:     "0000.0aff.0001",
			DstRouterId:     "0000.0aff.0004",
			Color:           uint32(100),
			PolicyName:      "sample-name",
			Type:            pb.SrPolicyType_DYNAMIC,
			Metric:          pb.MetricType_TE,
		},
	})
	if err != nil {
		log.Fatalf("CreateLsp error: %v", err)
	}
	log.Printf("Success: %#v", r)
}
