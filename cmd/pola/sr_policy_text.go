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
	ew := &errWriter{w: w}

	for i, v := range views {
		if i > 0 {
			ew.println()
		}

		writeSRPolicySessionText(ew, v)
	}

	return ew.err
}

func writeSRPolicySessionText(ew *errWriter, v srPolicySessionView) {
	ew.printf("Session: %s (State: %s, LSP-DB Sync: %s)\n", v.PeerAddress, v.State, v.LSPDBSync)

	if len(v.SRPolicies) == 0 {
		switch {
		case v.LSPDBSync == "finished":
			ew.println("  No SR Policies.")
		case v.State != "up":
			ew.println("  No SR Policies: session is not established.")
		default:
			ew.println("  No SR Policies: session is still synchronizing.")
		}
	}

	for _, policy := range v.SRPolicies {
		writeSRPolicyItemText(ew, policy)
	}
}

func writeSRPolicyItemText(ew *errWriter, policy table.SRPolicy) {
	ew.printf("  PolicyName: %s\n", policy.Name)
	ew.printf("    PlspID: %d\n", policy.PlspID)
	ew.printf("    LSPID: %d\n", policy.LSPID)
	ew.printf("    State: %s\n", policy.State)

	switch {
	case policy.CandidatePath.Dynamic != nil:
		ew.printf("    Type: dynamic\n")
		ew.printf("    Metric: %s\n", policy.CandidatePath.Dynamic.Metric.DisplayString())

		if plane := policy.CandidatePath.Dynamic.Plane; plane != (table.Plane{}) {
			ew.printf("    UnderlayFamily: %s\n", plane.Family)
			ew.printf("    DataPlane: %s\n", plane.DataPlane)
		}
	case policy.CandidatePath.Explicit != nil:
		ew.printf("    Type: explicit\n")
	}

	ew.printf("    Headend: %s\n", srcDstDisplay(policy.Headend.String(), policy.HeadendRouterID))
	ew.printf("    Endpoint: %s\n", srcDstDisplay(policy.Endpoint.String(), policy.EndpointRouterID))
	ew.printf("    Color: %d\n", policy.Color)
	ew.printf("    Preference: %d\n", policy.CandidatePath.Preference)
	ew.printf("    SegmentList: %s\n", segmentListDisplayString(policy.SegmentList))
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

func (ew *errWriter) println(a ...any) {
	if ew.err != nil {
		return
	}

	_, ew.err = fmt.Fprintln(ew.w, a...)
}

func segmentListDisplayString(segmentList []table.Segment) string {
	if len(segmentList) == 0 {
		return displayNone
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

	var localIfaceID, remoteIfaceID *uint32

	var behavior uint16

	switch v := seg.(type) {
	case table.SegmentSRv6:
		if v.LocalAddr.IsValid() {
			localAddr = v.LocalAddr.String()
		}

		if v.RemoteAddr.IsValid() {
			remoteAddr = v.RemoteAddr.String()
		}

		localIfaceID, remoteIfaceID = v.LocalIfaceID, v.RemoteIfaceID
		behavior = v.Behavior
	case table.SegmentSRMPLS:
		if v.LocalAddr.IsValid() {
			localAddr = v.LocalAddr.String()
		}

		if v.RemoteAddr.IsValid() {
			remoteAddr = v.RemoteAddr.String()
		}

		localIfaceID, remoteIfaceID = v.LocalIfaceID, v.RemoteIfaceID
	}

	var details []string

	if localAddr != "" {
		details = append(details, "local="+localAddr)
	}

	if remoteAddr != "" {
		details = append(details, "remote="+remoteAddr)
	}

	if localIfaceID != nil {
		details = append(details, fmt.Sprintf("localIface=%d", *localIfaceID))
	}

	if remoteIfaceID != nil {
		details = append(details, fmt.Sprintf("remoteIface=%d", *remoteIfaceID))
	}

	if behavior != 0 {
		details = append(details, "behavior="+table.BehaviorToString(behavior))
	}

	if len(details) == 0 {
		return seg.SidString()
	}

	return fmt.Sprintf("%s (%s)", seg.SidString(), strings.Join(details, ", "))
}
