// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command sr-policy-list lists SR Policies via the GetSRPolicyList RPC.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"strings"
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

	ret, err := c.GetSRPolicyList(ctx, &pb.GetSRPolicyListRequest{})
	if err != nil {
		log.Fatalf("unable to get SR policy list from server: %v", err) //nolint:gocritic // main exits immediately.
	}

	i := 0

	for _, session := range ret.GetSessions() {
		peerAddr := formatAddr(session.GetPeerAddr())
		fmt.Printf("session: %s (state: %s, syncState: %s)\n", peerAddr, session.GetState(), session.GetSyncState())

		for _, srPolicy := range session.GetSrPolicies() {
			fmt.Printf("srPolicy(%d):\n", i)
			i++

			fmt.Printf("  peerAddr: %s\n", peerAddr)
			fmt.Printf("  policyName: %s\n", srPolicy.GetPolicyName())
			fmt.Printf("  srcAddr: %s\n", formatAddr(srPolicy.GetSrcAddr()))
			fmt.Printf("  dstAddr: %s\n", formatAddr(srPolicy.GetDstAddr()))
			fmt.Printf("  color: %d\n", srPolicy.GetColor())
			fmt.Printf("  preference: %d\n", srPolicy.GetPreference())
			fmt.Printf("  path: %s\n", formatSegmentList(srPolicy.GetSegmentList()))
		}
	}
}

// formatAddr formats a 4- or 16-byte address.
func formatAddr(b []byte) string {
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return fmt.Sprintf("invalid (%v)", b)
	}

	return addr.String()
}

func formatSegmentList(segmentList []*pb.Segment) string {
	if len(segmentList) == 0 {
		return "None"
	}

	sids := make([]string, 0, len(segmentList))
	for _, segment := range segmentList {
		sids = append(sids, formatSegment(segment))
	}

	return strings.Join(sids, " -> ")
}

func formatSegment(segment *pb.Segment) string {
	local, remote := segment.GetLocalAddr(), segment.GetRemoteAddr()
	switch {
	case local == "" && remote == "":
		return segment.GetSid()
	case remote == "":
		return fmt.Sprintf("%s (local=%s)", segment.GetSid(), local)
	case local == "":
		return fmt.Sprintf("%s (remote=%s)", segment.GetSid(), remote)
	default:
		return fmt.Sprintf("%s (local=%s, remote=%s)", segment.GetSid(), local, remote)
	}
}
