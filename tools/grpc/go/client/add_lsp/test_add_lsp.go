// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
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

	var numOfLabels string
	var sidStr string
	var localAddrStr string
	var sessionAddrStr string
	var srcAddrStr string
	var dstAddrStr string
	var policyName string
	var colorStr string

	fmt.Printf("sessionAddr: ")
	fmt.Scan(&sessionAddrStr)
	fmt.Printf("%#v  \n", net.ParseIP(sessionAddrStr))
	sessionAddr := net.ParseIP(sessionAddrStr)
	if sessionAddr == nil {
		log.Fatalf("Invalid LocalAddr\n")
	}
	fmt.Printf("srcAddr: ")
	fmt.Scan(&srcAddrStr)
	srcAddr := net.ParseIP(srcAddrStr)
	if srcAddr == nil {
		log.Fatalf("Invalid LocalAddr\n")
	}
	fmt.Printf("dstAddrStr: ")
	fmt.Scan(&dstAddrStr)
	dstAddr := net.ParseIP(dstAddrStr)
	if dstAddr == nil {
		log.Fatalf("Invalid LocalAddr\n")
	}
	fmt.Printf("policyName: ")
	fmt.Scan(&policyName)

	fmt.Printf("Color: ")
	fmt.Scan(&colorStr)
	color, err := strconv.ParseInt(colorStr, 10, 32)
	if err != nil {
		log.Fatalf("Invalid color\n")
	}

	fmt.Printf("Number of labels?: ")
	fmt.Scan(&numOfLabels)
	numberOfLabels, err := strconv.Atoi(numOfLabels)
	if err != nil {
		log.Fatalf("Invalid input\n")
	}

	// Create Segment List
	labels := []*pb.Label{}
	fmt.Printf("Create Sid List\n")
	for i := 0; i < numberOfLabels; i++ {

		fmt.Printf("Sid: ")
		fmt.Scan(&sidStr)
		fmt.Printf("LocalAddr: ")
		fmt.Scan(&localAddrStr)

		sid, err := strconv.ParseInt(sidStr, 10, 32)
		if err != nil {
			log.Fatalf("Invalid Sid\n")
		}
		localAddr := net.ParseIP(localAddrStr)
		if localAddr == nil {
			log.Fatalf("Invalid LocalAddr\n")
		}
		label := pb.Label{
			Sid:    uint32(sid),
			LoAddr: []byte(localAddr.To4()),
		}

		labels = append(labels, &label)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.CreateLsp(ctx, &pb.LspData{
		PcepSessionAddr: []byte(sessionAddr.To4()),
		SrcAddr:         []byte(srcAddr.To4()),
		DstAddr:         []byte(dstAddr.To4()),
		Labels:          labels,
		Color:           uint32(color),
		PolicyName:      policyName,
	})
	if err != nil {
		log.Fatalf("CreateLsp error: %v", err)
	}
	log.Printf("Success: %#v", r)
}
