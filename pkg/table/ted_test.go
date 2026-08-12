// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"net/netip"
	"testing"
)

func TestLsNodeNodeSegment_PrefixSIDIndexZero(t *testing.T) {
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32"), SidIndex: 0, HasSidIndex: true},
		},
	}

	seg, err := node.NodeSegment()
	if err != nil {
		t.Fatalf("NodeSegment() error = %v, want nil", err)
	}
	if got, want := seg.SidString(), "16000"; got != want {
		t.Errorf("NodeSegment() = %s, want %s", got, want)
	}
}

func TestLsNodeNodeSegment_NoPrefixSID(t *testing.T) {
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
		},
	}

	if _, err := node.NodeSegment(); err == nil {
		t.Errorf("NodeSegment() error = nil, want error for a node without a Node SID")
	}
}
