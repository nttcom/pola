// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"io"
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

func orNone(s string) string {
	if s == "" {
		return "None"
	}

	return s
}

func writeTEDLinkText(ew *errWriter, link tedLinkView) {
	ew.printf("    Local: %s Remote: %s\n", orNone(link.LocalIP), orNone(link.RemoteIP))
	ew.printf("      RemoteRouterID: %s\n", orNone(link.RemoteRouterID))

	ew.println("      Metrics:")

	for _, m := range link.Metrics {
		ew.printf("        %s: %d\n", m.Type, m.Value)
	}

	ew.printf("      Adj-SID: %d\n", link.AdjSid)

	if link.Srv6EndXSID != nil {
		writeTEDSrv6EndXSIDText(ew, *link.Srv6EndXSID)
	}
}

func writeTEDSrv6EndXSIDText(ew *errWriter, sid tedSrv6EndXSIDView) {
	ew.println("      SRv6 End.X SID:")
	ew.printf("        EndpointBehavior: %s\n", sid.EndpointBehavior.Name)
	ew.printf("        SIDs: %v\n", sid.Sids)
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
	ew.printf("    Block: %d, Node: %d, Func: %d, Arg: %d\n",
		sid.SidStructure.LocalBlock, sid.SidStructure.LocalNode, sid.SidStructure.LocalFunc, sid.SidStructure.LocalArg)

	var flags, algorithm uint8
	if sid.EndpointBehavior.Flags != nil {
		flags = *sid.EndpointBehavior.Flags
	}

	if sid.EndpointBehavior.Algorithm != nil {
		algorithm = *sid.EndpointBehavior.Algorithm
	}

	ew.printf("    EndpointBehavior: %s, Flags: %d, Algorithm: %d\n",
		sid.EndpointBehavior.Name, flags, algorithm)
	ew.printf("    MultiTopoIDs: %v\n", sid.MultiTopoIDs)
}
