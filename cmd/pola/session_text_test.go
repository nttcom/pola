// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fullSessionViewFixture() sessionView {
	local, peer := uint32(1), uint32(7)
	lk, pk, ld, pd := uint32(30), uint32(10), uint32(120), uint32(40)
	ek, ed := uint32(10), uint32(40)
	return sessionView{
		PeerAddress: testPeerAddr1,
		State:       "up",
		LSPDBSync:   "finished",
		UpTime:      "00:12:22",
		Role:        roleActiveStatefulPCE,
		SessionID:   sessionIDView{Local: &local, Peer: &peer},
		Timers: timersView{
			Keepalive: timerTriple{Local: &lk, Peer: &pk, Effective: &ek},
			DeadTimer: timerTriple{Local: &ld, Peer: &pd, Effective: &ed},
		},
		Transport: transportView{Protocol: "tcp", Auth: "none"},
		Capabilities: capabilitiesView{
			Common: commonCapView{
				Stateful: true, Update: true,
				PathSetupTypes: []string{}, AssociationTypes: []uint32{}, UnrecognizedTLVTypes: []uint32{},
			},
			LocalOnly:    []capGroupView{{Capability: "SR", Items: []string{"MSD=10"}}},
			PeerOnly:     []capGroupView{{Capability: "SR", Items: []string{"MSD=16"}}},
			commonGroups: []capGroupView{{Capability: capGroupStateful, Items: []string{"Stateful", "Update"}}},
		},
		SessionCreation: "2026-08-19T09:30:00Z",
		Initiator:       "remote",
		Stats: &statsView{
			Keepalive: counterView{Sent: 3, Rcvd: 3},
			PCErr:     counterView{Sent: 0, Rcvd: 0},
			Report:    counterView{Rcvd: 5},
		},
	}
}

func TestWriteSessionText_DetailWithNilStatsRendersWithoutError(t *testing.T) {
	t.Parallel()

	v := fullSessionViewFixture()
	v.Stats = nil

	w := &condFailWriter{}
	require.NoError(t, writeSessionText(w, []sessionView{v}))
	assert.NotContains(t, w.buf.String(), "Stats:")
}

// blankLineAfterFail matches the first bare newline after a write containing
// sub. This avoids matching newlines emitted internally by tabwriter.Flush.
func blankLineAfterFail(sub string) func(string) bool {
	armed := false
	return func(s string) bool {
		if armed && s == "\n" {
			return true
		}
		if strings.Contains(s, sub) {
			armed = true
		}
		return false
	}
}

func TestWriteSessionText_PropagatesWriteErrors(t *testing.T) {
	t.Parallel()

	v := fullSessionViewFixture()
	views := []sessionView{v}
	twoViews := []sessionView{v, v}

	tests := []struct {
		name  string
		views []sessionView
		fail  func(string) bool
	}{
		{"blank line between sessions", twoViews, blankLineAfterFail("Session Setup:")},
		{"session header", views, containsFail("Session #0")},
		{"labeled field", views, containsFail("State:")},
		{"timer table header", views, containsFail("Timers:")},
		{"session creation label", views, containsFail("Session Creation:")},
		{"initiator label", views, containsFail("Initiator:")},
		{"capabilities header", views, containsFail("Capabilities:")},
		{"common capabilities header", views, containsFail("Common:")},
		{"common capabilities line", views, containsFail("STATEFUL-PCE-CAPABILITY")},
		{"local only line", views, containsFail("Local only:")},
		{"stats header", views, containsFail("  Stats:")},
		{"stats table flush", views, containsFail("PCErr")},
		{"unrecognized rcvd", views, containsFail("Unrecognized Rcvd:")},
		{"corrupt rcvd", views, containsFail("Corrupt Rcvd:")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := &condFailWriter{fail: tt.fail}
			err := writeSessionText(w, tt.views)
			require.Error(t, err)
		})
	}
}

func TestWriteGroupedLine_PropagatesWriteErrorOnNonFirstItem(t *testing.T) {
	t.Parallel()

	c := capabilitiesView{
		LocalOnly: []capGroupView{{Capability: capGroupAssocTypeList, Items: []string{"SR Policy Association (0x0006) [RFC9862]"}}},
	}

	w := &condFailWriter{fail: containsFail("SR Policy Association")}
	ew := &errWriter{w: w}
	writeCapabilitySectionsText(ew, c)
	require.Error(t, ew.err)
}

func TestWriteCapabilityGroupSection_PropagatesGroupedLineWriteError(t *testing.T) {
	t.Parallel()

	c := capabilitiesView{
		commonGroups: []capGroupView{{Capability: capGroupAssocTypeList, Items: []string{"SR Policy Association (0x0006) [RFC9862]"}}},
	}

	w := &condFailWriter{fail: containsFail("ASSOC-TYPE-LIST")}
	ew := &errWriter{w: w}
	writeCapabilityGroupSectionText(ew, "Common", c.commonLines())
	require.Error(t, ew.err)
}

func TestWriteGroupedLine_EmptyItemsRendersDash(t *testing.T) {
	t.Parallel()

	c := capabilitiesView{
		LocalOnly: []capGroupView{{Capability: capGroupAssocTypeList, Items: []string{}}},
	}

	var buf strings.Builder
	ew := &errWriter{w: &buf}
	writeCapabilitySectionsText(ew, c)
	require.NoError(t, ew.err)
	assert.Contains(t, buf.String(), "      ASSOC-TYPE-LIST [RFC8697]:\n        -\n")
}

func TestFormatTimerValue(t *testing.T) {
	t.Parallel()

	zero := uint32(0)
	v := uint32(30)
	assert.Equal(t, "-", formatTimerValue(nil))
	assert.Equal(t, "disabled", formatTimerValue(&zero))
	assert.Equal(t, "30", formatTimerValue(&v))
}
