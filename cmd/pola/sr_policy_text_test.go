// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

func TestWriteSRPolicyText_PropagatesWriteErrors(t *testing.T) {
	t.Parallel()

	views := []srPolicySessionView{
		{
			PeerAddress: testPeerAddr1,
			State:       "up",
			LSPDBSync:   "finished",
			SRPolicies: []table.SRPolicy{
				{Name: "policy1", PlspID: 1, LSPID: 2, State: "up"},
			},
		},
	}

	tests := []struct {
		name string
		fail func(string) bool
	}{
		{"session header", containsFail("Session:")},
		{"policy name", containsFail("PolicyName:")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := &condFailWriter{fail: tt.fail}
			err := writeSRPolicyText(w, views)
			require.Error(t, err)
		})
	}
}

func TestWriteSRPolicySession_EmptyPolicies_PropagatesWriteError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    srPolicySessionView
		fail func(string) bool
	}{
		{
			name: "finished",
			v:    srPolicySessionView{PeerAddress: testPeerAddr1, State: "up", LSPDBSync: "finished"},
			fail: exactFail("  No SR Policies.\n"),
		},
		{
			name: "still synchronizing",
			v:    srPolicySessionView{PeerAddress: testPeerAddr1, State: "up", LSPDBSync: "pending"},
			fail: exactFail("  No SR Policies: session is still synchronizing.\n"),
		},
		{
			name: "not established",
			v:    srPolicySessionView{PeerAddress: testPeerAddr1, State: "tcp-pending", LSPDBSync: "pending"},
			fail: exactFail("  No SR Policies: session is not established.\n"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := &condFailWriter{fail: tt.fail}
			ew := &errWriter{w: w}
			writeSRPolicySessionText(ew, tt.v)
			require.Error(t, ew.err)
		})
	}
}

func TestWriteSRPolicyText_PropagatesSeparatorWriteError(t *testing.T) {
	t.Parallel()

	views := []srPolicySessionView{
		{PeerAddress: testPeerAddr1, State: "up", LSPDBSync: "finished"},
		{PeerAddress: testPeerAddr2, State: "up", LSPDBSync: "finished"},
	}
	w := &condFailWriter{fail: exactFail("\n")}
	err := writeSRPolicyText(w, views)
	require.Error(t, err)
}

func TestWriteSRPolicyText_SeparatesMultipleSessionsWithBlankLine(t *testing.T) {
	t.Parallel()

	views := []srPolicySessionView{
		{PeerAddress: testPeerAddr1, State: "up", LSPDBSync: "finished"},
		{PeerAddress: testPeerAddr2, State: "up", LSPDBSync: "finished"},
	}
	w := &condFailWriter{}
	require.NoError(t, writeSRPolicyText(w, views))
	require.False(t, strings.HasSuffix(w.buf.String(), "\n\n"), "output must not end with a blank line")
	require.Contains(t, w.buf.String(), "\n\nSession: 192.0.2.2")
}
