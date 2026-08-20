// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/nttcom/pola/pkg/table"
)

func writeSRPolicyText(w io.Writer, views []srPolicySessionView) error {
	for i, v := range views {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if err := writeSRPolicySession(w, v); err != nil {
			return err
		}
	}
	return nil
}

func writeSRPolicySession(w io.Writer, v srPolicySessionView) error {
	if _, err := fmt.Fprintf(w, "Session: %s (State: %s, LSP-DB Sync: %s)\n", v.PeerAddress, v.State, v.LSPDBSync); err != nil {
		return err
	}
	if len(v.SRPolicies) == 0 {
		if v.LSPDBSync == "finished" {
			if _, err := fmt.Fprintln(w, "  No SR Policies."); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintln(w, "  No SR Policies: session is still synchronizing."); err != nil {
			return err
		}
	}
	for _, policy := range v.SRPolicies {
		if err := writeSRPolicy(w, policy); err != nil {
			return err
		}
	}
	return nil
}

// errWriter records the first write error and allows chained writes.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

func writeSRPolicy(w io.Writer, policy table.SRPolicy) error {
	ew := &errWriter{w: w}
	ew.printf("  PolicyName: %s\n", policy.Name)
	ew.printf("    PlspID: %d\n", policy.PlspID)
	ew.printf("    LSPID: %d\n", policy.LSPID)
	ew.printf("    State: %s\n", policy.State)
	if policy.Type != "" {
		ew.printf("    Type: %s\n", policy.Type)
	}
	if policy.Metric != table.UnspecifiedMetric {
		ew.printf("    Metric: %s\n", policy.Metric.DisplayString())
	}
	ew.printf("    SrcAddr: %s\n", srcDstDisplay(policy.SrcAddr.String(), policy.SrcRouterID))
	ew.printf("    DstAddr: %s\n", srcDstDisplay(policy.DstAddr.String(), policy.DstRouterID))
	ew.printf("    Color: %d\n", policy.Color)
	ew.printf("    Preference: %d\n", policy.Preference)
	ew.printf("    SegmentList: %s\n", segmentListDisplayString(policy.SegmentList))
	return ew.err
}

func segmentListDisplayString(segmentList []table.Segment) string {
	if len(segmentList) == 0 {
		return "None"
	}
	tokens := make([]string, len(segmentList))
	for i, segment := range segmentList {
		tokens[i] = segmentDisplayString(segment)
	}
	return strings.Join(tokens, " -> ")
}

func srcDstDisplay(addr, routerID string) string {
	if routerID == "" {
		return addr
	}
	return fmt.Sprintf("%s (%s)", addr, routerID)
}

func segmentDisplayString(seg table.Segment) string {
	var localAddr, remoteAddr string
	switch v := seg.(type) {
	case table.SegmentSRv6:
		if v.LocalAddr.IsValid() {
			localAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			remoteAddr = v.RemoteAddr.String()
		}
	case table.SegmentSRMPLS:
		if v.LocalAddr.IsValid() {
			localAddr = v.LocalAddr.String()
		}
		if v.RemoteAddr.IsValid() {
			remoteAddr = v.RemoteAddr.String()
		}
	}

	switch {
	case localAddr == "" && remoteAddr == "":
		return seg.SidString()
	case remoteAddr == "":
		return fmt.Sprintf("%s (local=%s)", seg.SidString(), localAddr)
	case localAddr == "":
		return fmt.Sprintf("%s (remote=%s)", seg.SidString(), remoteAddr)
	default:
		return fmt.Sprintf("%s (local=%s, remote=%s)", seg.SidString(), localAddr, remoteAddr)
	}
}
