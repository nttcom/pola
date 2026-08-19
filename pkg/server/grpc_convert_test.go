// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"testing"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/stretchr/testify/assert"
)

func TestToPBSessionState(t *testing.T) {
	tests := []struct {
		name string
		in   sessionState
		want pb.SessionState
	}{
		{"TCPPending", sessionStateTCPPending, pb.SessionState_SESSION_STATE_TCP_PENDING},
		{"OpenWait", sessionStateOpenWait, pb.SessionState_SESSION_STATE_OPEN_WAIT},
		{"KeepWait", sessionStateKeepWait, pb.SessionState_SESSION_STATE_KEEP_WAIT},
		{"Up", sessionStateUp, pb.SessionState_SESSION_STATE_UP},
		{"unrecognized value maps to unspecified", sessionState(99), pb.SessionState_SESSION_STATE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toPBSessionState(tt.in))
		})
	}
}

func TestToPBPccType(t *testing.T) {
	tests := []struct {
		name string
		in   pcep.PccType
		want pb.PccType
	}{
		{"CiscoLegacy", pcep.CiscoLegacy, pb.PccType_PCC_TYPE_CISCO_LEGACY},
		{"JuniperLegacy", pcep.JuniperLegacy, pb.PccType_PCC_TYPE_JUNIPER_LEGACY},
		{"RFCCompliant", pcep.RFCCompliant, pb.PccType_PCC_TYPE_RFC_COMPLIANT},
		{"unrecognized value maps to unspecified", pcep.PccType(99), pb.PccType_PCC_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toPBPccType(tt.in))
		})
	}
}
