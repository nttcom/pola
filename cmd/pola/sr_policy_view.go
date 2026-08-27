// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/pkg/table"
)

// srPolicySessionView groups SR policies by peer and preserves session state
// needed to distinguish unsynchronized sessions from synced sessions with no policies.
type srPolicySessionView struct {
	PeerAddress string           `json:"peerAddress"`
	State       string           `json:"state"`
	LSPDBSync   string           `json:"lspDbSync"`
	SRPolicies  []table.SRPolicy `json:"srPolicies"`
}

func newSRPolicySessionView(ss grpc.SRPolicySession) srPolicySessionView {
	policies := ss.SRPolicies
	if policies == nil {
		policies = []table.SRPolicy{}
	}
	return srPolicySessionView{
		PeerAddress: ss.PeerAddr.String(),
		State:       ss.State,
		LSPDBSync:   ss.SyncState,
		SRPolicies:  policies,
	}
}
