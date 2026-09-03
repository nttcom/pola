// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionRole(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		caps []grpc.Capability
		want string
	}{
		"no stateful capability": {nil, "stateless-pce"},
		"active (U=1)": {
			[]grpc.Capability{{Type: capGroupStateful, Detail: grpc.StatefulCapability{LSPUpdate: true}}},
			roleActiveStatefulPCE,
		},
		"passive (U=0)": {
			[]grpc.Capability{{Type: capGroupStateful, Detail: grpc.StatefulCapability{LSPUpdate: false}}},
			"passive-stateful-pce",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, sessionRole(tt.caps))
		})
	}
}

func TestSessionRole_IgnoresPeerCapabilities(t *testing.T) {
	t.Parallel()

	localCaps := []grpc.Capability{{Type: capGroupStateful, Detail: grpc.StatefulCapability{LSPUpdate: true}}}
	ss := grpc.Session{
		PeerAddr:          netip.MustParseAddr(testPeerAddr1),
		State:             "up",
		LocalCapabilities: localCaps,
		PeerCapabilities:  []grpc.Capability{{Type: capGroupStateful, Detail: grpc.StatefulCapability{LSPUpdate: false}}},
	}
	v := newSessionView(ss, false)
	assert.Equal(t, roleActiveStatefulPCE, v.Role)
}

func TestFormatUpTime(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		d    time.Duration
		want string
	}{
		"zero":                    {0, "00:00:00"},
		"typical":                 {12*time.Hour + 22*time.Minute + 5*time.Second, "12:22:05"},
		"over 24 hours":           {30*time.Hour + 5*time.Minute, "30:05:00"},
		"negative clamps to zero": {-5 * time.Second, "00:00:00"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatUpTime(tt.d))
		})
	}
}

func TestNewSessionView_UpTimeOmittedUnlessEstablished(t *testing.T) {
	t.Parallel()

	notEstablished := grpc.Session{PeerAddr: netip.MustParseAddr(testPeerAddr1), State: "open-wait"}
	assert.Empty(t, newSessionView(notEstablished, false).UpTime)

	established := grpc.Session{
		PeerAddr:      netip.MustParseAddr(testPeerAddr1),
		State:         "up",
		EstablishedAt: time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC),
		UptimeNanos:   3600000000000, // 1 hour in nanoseconds
	}
	assert.Equal(t, "01:00:00", newSessionView(established, false).UpTime)
}

func TestNewSessionView_DetailFieldsOnlyPopulatedWhenRequested(t *testing.T) {
	t.Parallel()

	ss := grpc.Session{
		PeerAddr:  netip.MustParseAddr(testPeerAddr1),
		State:     "up",
		CreatedAt: time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC),
		Initiator: "remote",
		SyncState: "finished",
		Stats:     &grpc.SessionStats{SessSetupOK: 1},
	}

	summary := newSessionView(ss, false)
	assert.Empty(t, summary.SessionCreation)
	assert.Empty(t, summary.Initiator)
	assert.Equal(t, "finished", summary.LSPDBSync)
	assert.Nil(t, summary.Stats)
	assert.False(t, summary.isDetail())

	detail := newSessionView(ss, true)
	assert.Equal(t, "2026-08-19T09:30:00Z", detail.SessionCreation)
	assert.Equal(t, "remote", detail.Initiator)
	assert.Equal(t, "finished", detail.LSPDBSync)
	require.NotNil(t, detail.Stats)
	assert.Equal(t, uint64(1), detail.Stats.SessionSetup.OK)
	assert.True(t, detail.isDetail())
}

func TestTimersViewFrom_NilTimersYieldNilLocalAndPeer(t *testing.T) {
	t.Parallel()

	keepalive, deadTimer := uint32(30), uint32(120)
	tv := timersViewFrom(nil, nil, grpc.EffectiveTimers{Keepalive: &keepalive, DeadTimer: &deadTimer})
	assert.Nil(t, tv.Keepalive.Local)
	assert.Nil(t, tv.Keepalive.Peer)
	require.NotNil(t, tv.Keepalive.Effective)
	assert.Equal(t, uint32(30), *tv.Keepalive.Effective)
	assert.Nil(t, tv.DeadTimer.Local)
	assert.Nil(t, tv.DeadTimer.Peer)
	require.NotNil(t, tv.DeadTimer.Effective)
	assert.Equal(t, uint32(120), *tv.DeadTimer.Effective)
}

func TestTimersViewFrom_PopulatedTimers(t *testing.T) {
	t.Parallel()

	local := &grpc.SessionTimers{Keepalive: 30, DeadTimer: 120}
	peer := &grpc.SessionTimers{Keepalive: 10, DeadTimer: 40}
	keepalive, deadTimer := uint32(10), uint32(40)

	tv := timersViewFrom(local, peer, grpc.EffectiveTimers{Keepalive: &keepalive, DeadTimer: &deadTimer})
	require.NotNil(t, tv.Keepalive.Local)
	require.NotNil(t, tv.Keepalive.Peer)
	assert.Equal(t, uint32(30), *tv.Keepalive.Local)
	assert.Equal(t, uint32(10), *tv.Keepalive.Peer)
}

func TestTimersViewFrom_EffectiveNilBeforeUpDistinguishesFromKeepaliveZero(t *testing.T) {
	t.Parallel()

	tv := timersViewFrom(nil, nil, grpc.EffectiveTimers{})
	assert.Nil(t, tv.Keepalive.Effective)
	assert.Nil(t, tv.DeadTimer.Effective)
}
