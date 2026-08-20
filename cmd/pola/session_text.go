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
	for i, v := range views {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if err := writeSessionSummary(w, i, v); err != nil {
			return err
		}
		if v.isDetail() {
			if err := writeSessionDetail(w, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeLabeledLine(w io.Writer, indent int, label, value string) error {
	_, err := fmt.Fprintf(w, "%s%-18s %s\n", strings.Repeat(" ", indent), label+":", value)
	return err
}

func writeSessionSummary(w io.Writer, index int, v sessionView) error {
	if _, err := fmt.Fprintf(w, "Session #%d: %s\n", index, v.PeerAddress); err != nil {
		return err
	}

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
		if err := writeLabeledLine(w, 2, f.label, f.value); err != nil {
			return err
		}
	}

	if err := writeTimerTable(w, v.Timers); err != nil {
		return err
	}
	return writeCapabilitySections(w, v.Capabilities)
}

func writeSessionDetail(w io.Writer, v sessionView) error {
	if v.SessionCreation != "" {
		if err := writeLabeledLine(w, 2, "Session Creation", v.SessionCreation); err != nil {
			return err
		}
	}
	if v.Initiator != "" {
		if err := writeLabeledLine(w, 2, "Initiator", v.Initiator); err != nil {
			return err
		}
	}
	if v.Stats != nil {
		return writeStatsTable(w, *v.Stats)
	}
	return nil
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

func writeTimerTable(w io.Writer, timers timersView) error {
	if _, err := fmt.Fprintln(w, "  Timers:"); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "    \tLocal\tPeer\tEffective"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "    Keepalive\t%s\t%s\t%s\n",
		formatTimerValue(timers.Keepalive.Local), formatTimerValue(timers.Keepalive.Peer),
		formatTimerValue(timers.Keepalive.Effective)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "    DeadTimer\t%s\t%s\t%s\n",
		formatTimerValue(timers.DeadTimer.Local), formatTimerValue(timers.DeadTimer.Peer),
		formatTimerValue(timers.DeadTimer.Effective)); err != nil {
		return err
	}
	return tw.Flush()
}

func writeCapabilitySections(w io.Writer, c capabilitiesView) error {
	if _, err := fmt.Fprintln(w, "  Capabilities:"); err != nil {
		return err
	}
	if err := writeCommonCapabilityLines(w, c); err != nil {
		return err
	}
	if err := writeOnlyLine(w, "Local only", c.LocalOnly); err != nil {
		return err
	}
	return writeOnlyLine(w, "Peer only", c.PeerOnly)
}

func writeCommonCapabilityLines(w io.Writer, c capabilitiesView) error {
	lines := c.commonLines()
	if len(lines) == 0 {
		return writeLabeledLine(w, 4, "Common", "-")
	}
	if _, err := fmt.Fprintln(w, "    Common:"); err != nil {
		return err
	}
	for _, line := range lines {
		if line.Items == nil {
			if _, err := fmt.Fprintf(w, "      %s\n", line.Header); err != nil {
				return err
			}
			continue
		}
		if err := writeGroupedLine(w, 6, line.Header, line.Items); err != nil {
			return err
		}
	}
	return nil
}

func writeOnlyLine(w io.Writer, label string, caps []capabilityView) error {
	tokens := make([]string, len(caps))
	for i, c := range caps {
		tokens[i] = formatCapabilityToken(c)
	}
	return writeGroupedLine(w, 4, label, tokens)
}

// writeGroupedLine writes a heading followed by each item on its own
// indented line, or "-" when there are no items.
func writeGroupedLine(w io.Writer, indent int, header string, items []string) error {
	if _, err := fmt.Fprintf(w, "%s%s:\n", strings.Repeat(" ", indent), header); err != nil {
		return err
	}
	if len(items) == 0 {
		items = []string{"-"}
	}
	itemIndent := strings.Repeat(" ", indent+2)
	for _, item := range items {
		if _, err := fmt.Fprintf(w, "%s%s\n", itemIndent, item); err != nil {
			return err
		}
	}
	return nil
}

func formatCapabilityToken(c capabilityView) string {
	if c.Value == "" {
		return c.Name
	}
	return c.Name + "=" + c.Value
}

func writeStatsTable(w io.Writer, s statsView) error {
	if _, err := fmt.Fprintln(w, "  Stats:"); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "    \tSent\tRcvd"); err != nil {
		return err
	}
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
		if _, err := fmt.Fprintf(tw, "    %s\t%d\t%d\n", c.name, c.c.Sent, c.c.Rcvd); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if err := writeLabeledLine(w, 4, "Unrecognized Rcvd", strconv.FormatUint(s.UnrecognizedRcvd, 10)); err != nil {
		return err
	}
	if err := writeLabeledLine(w, 4, "Corrupt Rcvd", strconv.FormatUint(s.CorruptRcvd, 10)); err != nil {
		return err
	}
	setup := fmt.Sprintf("ok=%d, fail=%d", s.SessionSetup.OK, s.SessionSetup.Fail)
	return writeLabeledLine(w, 4, "Session Setup", setup)
}
