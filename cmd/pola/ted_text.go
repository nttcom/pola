// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"io"
)

// writeTEDText expects nodes to be sorted by router ID for deterministic output.
func writeTEDText(w io.Writer, nodes []tedNodeView) error {
	if len(nodes) == 0 {
		_, err := fmt.Fprintln(w, "TED is empty")
		return err
	}

	for i, node := range nodes {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "Node #%d: %s\n", i, node.RouterID); err != nil {
			return err
		}
		if err := writeTEDNodeBasic(w, node); err != nil {
			return err
		}
		if err := writeTEDNodePrefixes(w, node); err != nil {
			return err
		}
		if err := writeTEDNodeLinks(w, node); err != nil {
			return err
		}
		if err := writeTEDNodeSrv6SIDs(w, node); err != nil {
			return err
		}
	}
	return nil
}

func writeTEDNodeBasic(w io.Writer, node tedNodeView) error {
	if _, err := fmt.Fprintf(w, "  Hostname: %s\n", node.Hostname); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  ISIS Area ID: %s\n", node.IsisAreaID); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "  SRGB: %d - %d\n", node.Srgb.Begin, node.Srgb.End)
	return err
}

func writeTEDNodePrefixes(w io.Writer, node tedNodeView) error {
	if _, err := fmt.Fprintln(w, "  Prefixes:"); err != nil {
		return err
	}
	for _, p := range node.Prefixes {
		if _, err := fmt.Fprintf(w, "    %s\n", p.Prefix); err != nil {
			return err
		}
		if p.SidIndex != nil {
			if _, err := fmt.Fprintf(w, "      index: %d\n", *p.SidIndex); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeTEDNodeLinks(w io.Writer, node tedNodeView) error {
	if _, err := fmt.Fprintln(w, "  Links:"); err != nil {
		return err
	}
	for _, link := range node.Links {
		if err := writeTEDLink(w, link); err != nil {
			return err
		}
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "None"
	}
	return s
}

func writeTEDLink(w io.Writer, link tedLinkView) error {
	if _, err := fmt.Fprintf(w, "    Local: %s Remote: %s\n", orNone(link.LocalIP), orNone(link.RemoteIP)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "      RemoteRouterID: %s\n", orNone(link.RemoteRouterID)); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "      Metrics:"); err != nil {
		return err
	}
	for _, m := range link.Metrics {
		if _, err := fmt.Fprintf(w, "        %s: %d\n", m.Type, m.Value); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "      Adj-SID: %d\n", link.AdjSid); err != nil {
		return err
	}

	if link.Srv6EndXSID != nil {
		if err := writeTEDSrv6EndXSID(w, *link.Srv6EndXSID); err != nil {
			return err
		}
	}
	return nil
}

func writeTEDSrv6EndXSID(w io.Writer, sid tedSrv6EndXSIDView) error {
	if _, err := fmt.Fprintln(w, "      SRv6 End.X SID:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "        EndpointBehavior: %s\n", sid.EndpointBehavior.Name); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "        SIDs: %v\n", sid.Sids); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "        SID Structure: Block: %d, Node: %d, Func: %d, Arg: %d\n",
		sid.SidStructure.LocalBlock, sid.SidStructure.LocalNode, sid.SidStructure.LocalFunc, sid.SidStructure.LocalArg)
	return err
}

func writeTEDNodeSrv6SIDs(w io.Writer, node tedNodeView) error {
	if _, err := fmt.Fprintln(w, "  SRv6 SIDs:"); err != nil {
		return err
	}
	for _, sid := range node.SRv6SIDs {
		if err := writeTEDSrv6SID(w, sid); err != nil {
			return err
		}
	}
	return nil
}

func writeTEDSrv6SID(w io.Writer, sid tedSrv6SIDView) error {
	if _, err := fmt.Fprintf(w, "    SIDs: %v\n", sid.Sids); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "    Block: %d, Node: %d, Func: %d, Arg: %d\n",
		sid.SidStructure.LocalBlock, sid.SidStructure.LocalNode, sid.SidStructure.LocalFunc, sid.SidStructure.LocalArg); err != nil {
		return err
	}
	var flags, algorithm uint8
	if sid.EndpointBehavior.Flags != nil {
		flags = *sid.EndpointBehavior.Flags
	}
	if sid.EndpointBehavior.Algorithm != nil {
		algorithm = *sid.EndpointBehavior.Algorithm
	}
	if _, err := fmt.Fprintf(w, "    EndpointBehavior: %s, Flags: %d, Algorithm: %d\n",
		sid.EndpointBehavior.Name, flags, algorithm); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "    MultiTopoIDs: %v\n", sid.MultiTopoIDs)
	return err
}
