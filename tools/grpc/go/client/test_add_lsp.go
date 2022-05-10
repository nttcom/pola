// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nttcom/pola/api/grpc"
)

var (
	addr = flag.String("addr", "localhost:50051", "the address to connect to")
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPceServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	labels := []*pb.Label{}
	label1 := pb.Label{
		Sid:    16003,
		LoAddr: []byte{0x0a, 0xff, 0x00, 0x03},
	}
	labels = append(labels, &label1)

	label2 := pb.Label{
		Sid:    16001,
		LoAddr: []byte{0x0a, 0xff, 0x00, 0x01},
	}
	labels = append(labels, &label2)

	label3 := pb.Label{
		Sid:    16003,
		LoAddr: []byte{0x0a, 0xff, 0x00, 0x03},
	}
	labels = append(labels, &label3)

	label4 := pb.Label{
		Sid:    16001,
		LoAddr: []byte{0x0a, 0xff, 0x00, 0x01},
	}
	labels = append(labels, &label4)

	r, err := c.CreateLsp(ctx, &pb.LspData{
		PcepSessionAddr: []byte{10, 100, 0, 2},
		SrcAddr:         []byte{10, 255, 0, 2},
		DstAddr:         []byte{10, 255, 0, 1},
		Labels:          labels,
		Color:           uint32(1),
		PolicyName:      "test-color1-policy",
	})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Success: %#v", r)
}
