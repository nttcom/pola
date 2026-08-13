// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	assert.Equal(t, "16000", seg.SidString())
}

func TestLsNodeNodeSegment_NoPrefixSID(t *testing.T) {
	node := &LsNode{
		RouterID:  "0000.0000.0001",
		SrgbBegin: 16000,
		Prefixes: []*LsPrefix{
			{Prefix: netip.MustParsePrefix("10.0.0.1/32")},
		},
	}

	_, err := node.NodeSegment()
	assert.Error(t, err, "expected an error for a node without a Node SID")
}
