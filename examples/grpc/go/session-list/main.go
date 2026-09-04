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
	"strconv"
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

	ret, err := c.GetSessionList(ctx, &pb.GetSessionListRequest{IncludeStats: true})
	if err != nil {
		log.Fatalf("unable to get session list from server: %v", err) //nolint:gocritic // main exits immediately.
	}

	for i, ss := range ret.GetSessions() {
		addr, ok := netip.AddrFromSlice(ss.GetPeerAddr())
		if !ok {
			log.Printf("invalid address for session %d: %v", i, ss.GetPeerAddr())
			continue
		}

		fmt.Printf("peerAddr(%d): %v\n", i, addr)
		fmt.Printf("  sessionID (Pola): %s, sessionID (peer): %s\n",
			optionalUint32(ss.LocalSessionId), optionalUint32(ss.PeerSessionId))
		fmt.Printf("  state: %s\n", ss.GetState())
		fmt.Printf("  advertised (Pola): %s\n", timersString(ss.GetLocalTimers()))
		fmt.Printf("  advertised (peer): %s\n", timersString(ss.GetPeerTimers()))
		fmt.Printf("  effective: keepalive: %s, deadTimer: %s\n",
			effectiveTimerString(pb.EffectiveKeepalive(ss.GetState(), ss.GetEffectiveTimers())),
			effectiveTimerString(pb.EffectiveDeadTimer(ss.GetState(), ss.GetEffectiveTimers())))
		fmt.Printf("  pccType: %s\n", strings.TrimPrefix(ss.GetPccType().String(), "PCC_TYPE_"))
		fmt.Printf("  capabilities (Pola): %s\n", strings.Join(capStrings(ss.GetLocalCapabilities()), ", "))
		fmt.Printf("  capabilities (peer): %s\n", strings.Join(capStrings(ss.GetPeerCapabilities()), ", "))
		fmt.Printf("  initiator: %s\n", strings.TrimPrefix(ss.GetInitiator().String(), "SESSION_INITIATOR_"))
		fmt.Printf("  syncState: %s\n", strings.TrimPrefix(ss.GetSyncState().String(), "LSP_DB_SYNC_STATE_"))
		fmt.Printf("  createdAt: %s\n", unixNanoString(ss.GetCreatedAtUnixNano()))
		fmt.Printf("  establishedAt: %s\n", unixNanoString(ss.GetEstablishedAtUnixNano()))
		fmt.Printf("  stats: %s\n", ss.GetStats())
	}
}

func unixNanoString(n int64) string {
	if n == 0 {
		return "-"
	}

	return time.Unix(0, n).UTC().Format(time.RFC3339)
}

func optionalUint32(v *uint32) string {
	if v == nil {
		return "-"
	}

	return strconv.FormatUint(uint64(*v), 10)
}

func effectiveTimerString(v uint32, ok bool) string {
	if !ok {
		return "-"
	}

	return strconv.FormatUint(uint64(v), 10)
}

func timersString(timers *pb.SessionTimers) string {
	if timers == nil {
		return "-"
	}

	return fmt.Sprintf("keepalive: %d, deadTimer: %d", timers.GetKeepalive(), timers.GetDeadTimer())
}

func capStrings(capabilities []*pb.Capability) []string {
	caps := make([]string, 0, len(capabilities))
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
