// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

func writeSessionText(w io.Writer, views []sessionView) error {
	ew := &errWriter{w: w}

	for i, v := range views {
		if i > 0 {
			ew.println()
		}

		writeSessionSummaryText(ew, i, v)

		if v.isDetail() {
			writeSessionDetailText(ew, v)
		}
	}

	return ew.err
}

func writeSessionSummaryText(ew *errWriter, index int, v sessionView) {
	ew.printf("Session #%d: %s\n", index, v.PeerAddress)

	fields := []struct{ label, value string }{
		{"State", v.State},
		{"LSP-DB Sync", v.LSPDBSync},
		{"Role", v.Role},
	}
	if v.UpTime != "" {
		fields = append(fields, struct{ label, value string }{"Up Time", v.UpTime})
	}

	fields = append(fields,
		struct{ label, value string }{"Session ID", formatSessionID(v.SessionID)},
		struct{ label, value string }{"Transport", v.Transport.Protocol + ", auth=" + v.Transport.Auth},
	)
	for _, f := range fields {
		writeLabeledLineText(ew, 2, f.label, f.value)
	}

	writeTimerTableText(ew, v.Timers)
	writeCapabilitySectionsText(ew, v.Capabilities)
}

func writeSessionDetailText(ew *errWriter, v sessionView) {
	if v.SessionCreation != "" {
		writeLabeledLineText(ew, 2, "Session Creation", v.SessionCreation)
	}

	if v.Initiator != "" {
		writeLabeledLineText(ew, 2, "Initiator", v.Initiator)
	}

	if v.Stats != nil {
		writeStatsTableText(ew, *v.Stats)
	}
}

func writeLabeledLineText(ew *errWriter, indent int, label, value string) {
	ew.printf("%s%-18s %s\n", strings.Repeat(" ", indent), label+":", value)
}

func formatSessionID(id sessionIDView) string {
	return "Local=" + formatOptionalUint32(id.Local) + ", Peer=" + formatOptionalUint32(id.Peer)
}

func formatOptionalUint32(v *uint32) string {
	if v == nil {
		return "-"
	}

	return strconv.FormatUint(uint64(*v), 10)
}

// formatTimerValue formats a negotiated timer value.
// A value of 0 disables the timer per RFC 5440 §7.3.
func formatTimerValue(v *uint32) string {
	if v == nil {
		return "-"
	}

	if *v == 0 {
		return "disabled"
	}

	return strconv.FormatUint(uint64(*v), 10)
}

func writeTimerTableText(ew *errWriter, timers timersView) {
	if ew.err != nil {
		return
	}

	ew.println("  Timers:")

	tw := tabwriter.NewWriter(ew.w, 0, 0, 2, ' ', 0)
	tew := &errWriter{w: tw}
	tew.printf("    \tLocal\tPeer\tEffective\n")
	tew.printf("    Keepalive\t%s\t%s\t%s\n",
		formatTimerValue(timers.Keepalive.Local), formatTimerValue(timers.Keepalive.Peer),
		formatTimerValue(timers.Keepalive.Effective))
	tew.printf("    DeadTimer\t%s\t%s\t%s\n",
		formatTimerValue(timers.DeadTimer.Local), formatTimerValue(timers.DeadTimer.Peer),
		formatTimerValue(timers.DeadTimer.Effective))

	if ew.err == nil {
		ew.err = tew.err
	}

	if ew.err == nil {
		ew.err = tw.Flush()
	}
}

func writeCapabilitySectionsText(ew *errWriter, c capabilitiesView) {
	ew.println("  Capabilities:")
	writeCapabilityGroupSectionText(ew, "Common", c.commonLines())
	writeCapabilityGroupSectionText(ew, "Local only", capabilityLines(c.LocalOnly))
	writeCapabilityGroupSectionText(ew, "Peer only", capabilityLines(c.PeerOnly))
}

func writeCapabilityGroupSectionText(ew *errWriter, label string, lines []capDisplayLine) {
	if len(lines) == 0 {
		writeLabeledLineText(ew, 4, label, "-")
		return
	}

	ew.printf("    %s:\n", label)

	for _, line := range lines {
		if line.Items == nil {
			ew.printf("      %s\n", line.Header)
			continue
		}

		writeGroupedLineText(ew, 6, line.Header, line.Items)
	}
}

func writeGroupedLineText(ew *errWriter, indent int, header string, items []string) {
	ew.printf("%s%s:\n", strings.Repeat(" ", indent), header)

	if len(items) == 0 {
		items = []string{"-"}
	}

	itemIndent := strings.Repeat(" ", indent+2)
	for _, item := range items {
		ew.printf("%s%s\n", itemIndent, item)
	}
}

func writeStatsTableText(ew *errWriter, s statsView) {
	if ew.err != nil {
		return
	}

	ew.println("  Stats:")

	tw := tabwriter.NewWriter(ew.w, 0, 0, 2, ' ', 0)
	tew := &errWriter{w: tw}
	tew.printf("    \tSent\tRcvd\n")

	counters := []struct {
		name string
		c    counterView
	}{
		{"Open", s.Open},
		{"Keepalive", s.Keepalive},
		{"Close", s.Close},
		{"PCErr", s.PCErr},
		{"PCNtf", s.PCNtf},
		{"PCReq", s.PCReq},
		{"PCRep", s.PCRep},
		{"Report", s.Report},
		{"Update", s.Update},
		{"Initiate", s.Initiate},
	}
	for _, c := range counters {
		tew.printf("    %s\t%d\t%d\n", c.name, c.c.Sent, c.c.Rcvd)
	}

	if ew.err == nil {
		ew.err = tew.err
	}

	if ew.err == nil {
		ew.err = tw.Flush()
	}

	writeLabeledLineText(ew, 4, "Unrecognized Rcvd", strconv.FormatUint(s.UnrecognizedRcvd, 10))
	writeLabeledLineText(ew, 4, "Corrupt Rcvd", strconv.FormatUint(s.CorruptRcvd, 10))
	setup := fmt.Sprintf("ok=%d, fail=%d", s.SessionSetup.OK, s.SessionSetup.Fail)
	writeLabeledLineText(ew, 4, "Session Setup", setup)
}
