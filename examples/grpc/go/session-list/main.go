// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command session-list lists PCEP sessions via the GetSessionList RPC.
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
	defer func() { _ = conn.Close() }()

	c := pb.NewPCEServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	ret, err := c.GetSessionList(ctx, &pb.GetSessionListRequest{})
	if err != nil {
		log.Fatalf("unable to get session list from server: %v", err)
	}

	for i, ss := range ret.GetSessions() {
		addr, ok := netip.AddrFromSlice(ss.GetAddr())
		if !ok {
			log.Printf("invalid address for session %d: %v", i, ss.GetAddr())
			continue
		}
		fmt.Printf("sessionAddr(%d): %v\n", i, addr)
		fmt.Printf("  state: %s\n", ss.GetState())
		fmt.Printf("  capabilities: %s\n", strings.Join(capStrings(ss.GetCapabilities()), ", "))
		fmt.Printf("  isSynced: %t\n", ss.GetIsSynced())
	}
}

func capStrings(capabilities []*pb.Capability) []string {
	var caps []string
	for _, c := range capabilities {
		caps = append(caps, capString(c))
	}
	return caps
}

func capString(c *pb.Capability) string {
	typ := strings.TrimPrefix(c.GetType().String(), "CAPABILITY_TYPE_")
	switch detail := c.GetDetail().(type) {
	case *pb.Capability_Sr:
		return fmt.Sprintf("%s(msd=%d, unlimitedMsd=%t, naiSupported=%t)", typ, detail.Sr.GetMsd(), detail.Sr.GetUnlimitedMsd(), detail.Sr.GetNaiSupported())
	case *pb.Capability_LspDbVersion:
		return fmt.Sprintf("%s(versionNumber=%d)", typ, detail.LspDbVersion.GetVersionNumber())
	default:
		return typ
	}
}
