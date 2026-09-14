// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"io"
	"strings"
)

// writeTEDText expects nodes to be sorted by router ID for deterministic output.
func writeTEDText(w io.Writer, nodes []tedNodeView) error {
	ew := &errWriter{w: w}
	if len(nodes) == 0 {
		ew.println("TED is empty")
		return ew.err
	}

	for i, node := range nodes {
		if i > 0 {
			ew.println()
		}

		ew.printf("Node #%d: %s\n", i, node.RouterID)
		writeTEDNodeBasicText(ew, node)
		writeTEDNodePrefixesText(ew, node)
		writeTEDNodeLinksText(ew, node)
		writeTEDNodeSrv6SIDsText(ew, node)
	}

	return ew.err
}

func writeTEDNodeBasicText(ew *errWriter, node tedNodeView) {
	ew.printf("  Hostname: %s\n", node.Hostname)
	ew.printf("  ISIS Area ID: %s\n", node.IsisAreaID)
	ew.printf("  SRGB: %d - %d\n", node.Srgb.Begin, node.Srgb.End)
}

func writeTEDNodePrefixesText(ew *errWriter, node tedNodeView) {
	ew.println("  Prefixes:")

	for _, p := range node.Prefixes {
		ew.printf("    %s\n", p.Prefix)

		if p.SidIndex != nil {
			ew.printf("      index: %d\n", *p.SidIndex)
		}
	}
}

func writeTEDNodeLinksText(ew *errWriter, node tedNodeView) {
	ew.println("  Links:")

	for _, link := range node.Links {
		writeTEDLinkText(ew, link)
	}
}

const displayNone = "None"

func orNone(s string) string {
	if s == "" {
		return displayNone
	}

	return s
}

func writeTEDLinkText(ew *errWriter, link tedLinkView) {
	ew.printf("    Local: %s Remote: %s\n", linkEndpointDisplay(link.Local), linkEndpointDisplay(link.Remote))
	ew.printf("      RemoteRouterID: %s\n", orNone(link.Remote.RouterID))

	ew.println("      Metrics:")

	for _, m := range link.Metrics {
		ew.printf("        %s: %d\n", m.Type, m.Value)
	}

	ew.println("      Adj-SIDs:")

	for _, a := range link.AdjSids {
		ew.printf("        %s: %d\n", a.Family, a.Sid)
	}

	for _, sid := range link.Srv6EndXSIDs {
		writeTEDSrv6EndXSIDText(ew, sid)
	}
}

func linkEndpointDisplay(e tedLinkEndpointView) string {
	var addrs []string

	if e.IPv4 != "" {
		addrs = append(addrs, e.IPv4)
	}

	if e.IPv6 != "" {
		addrs = append(addrs, e.IPv6)
	}

	if len(addrs) == 0 {
		return displayNone
	}

	s := strings.Join(addrs, ", ")
	if e.InterfaceID != nil {
		s += fmt.Sprintf(" (interface %d)", *e.InterfaceID)
	}

	return s
}

func writeTEDSrv6EndXSIDText(ew *errWriter, sid tedSrv6EndXSIDView) {
	ew.println("      SRv6 End.X SID:")
	ew.printf("        EndpointBehavior: %s, Flags: %d, Algorithm: %d, Weight: %d\n",
		sid.EndpointBehavior.Name, sid.EndpointBehavior.Flags, sid.EndpointBehavior.Algorithm, sid.Weight)
	ew.printf("        SIDs: %v\n", sid.Sids)

	if sid.SidStructure == nil {
		ew.println("        SID Structure: (not advertised)")
		return
	}

	ew.printf("        SID Structure: Block: %d, Node: %d, Func: %d, Arg: %d\n",
		sid.SidStructure.LocalBlock, sid.SidStructure.LocalNode, sid.SidStructure.LocalFunc, sid.SidStructure.LocalArg)
}

func writeTEDNodeSrv6SIDsText(ew *errWriter, node tedNodeView) {
	ew.println("  SRv6 SIDs:")

	for _, sid := range node.SRv6SIDs {
		writeTEDSrv6SIDText(ew, sid)
	}
}

func writeTEDSrv6SIDText(ew *errWriter, sid tedSrv6SIDView) {
	ew.printf("    SIDs: %v\n", sid.Sids)

	if sid.SidStructure == nil {
		ew.println("    SID Structure: (not advertised)")
	} else {
		ew.printf("    Block: %d, Node: %d, Func: %d, Arg: %d\n",
			sid.SidStructure.LocalBlock, sid.SidStructure.LocalNode, sid.SidStructure.LocalFunc, sid.SidStructure.LocalArg)
	}

	ew.printf("    EndpointBehavior: %s, Flags: %d, Algorithm: %d\n",
		sid.EndpointBehavior.Name, sid.EndpointBehavior.Flags, sid.EndpointBehavior.Algorithm)
	ew.printf("    MultiTopoIDs: %v\n", sid.MultiTopoIDs)
}
