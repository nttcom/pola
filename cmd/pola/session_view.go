// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"time"

	"github.com/nttcom/pola/cmd/pola/grpc"
)

// sessionView fields follow the operator-facing reading order.
type sessionView struct {
	PeerAddress  string           `json:"peerAddress"`
	State        string           `json:"state"`
	LSPDBSync    string           `json:"lspDbSync"`
	UpTime       string           `json:"upTime,omitempty"`
	Role         string           `json:"role"`
	SessionID    sessionIDView    `json:"sessionId"`
	Timers       timersView       `json:"timers"`
	Transport    transportView    `json:"transport"`
	Capabilities capabilitiesView `json:"capabilities"`

	// Detail-only fields; omitted from summary output.
	SessionCreation string     `json:"sessionCreation,omitempty"`
	Initiator       string     `json:"initiator,omitempty"`
	Stats           *statsView `json:"stats,omitempty"`
}

func (v sessionView) isDetail() bool {
	return v.SessionCreation != "" || v.Initiator != "" || v.Stats != nil
}

type sessionIDView struct {
	Local *uint32 `json:"local,omitempty"`
	Peer  *uint32 `json:"peer,omitempty"`
}

type timersView struct {
	Keepalive timerTriple `json:"keepalive"`
	DeadTimer timerTriple `json:"deadTimer"`
}

// timerTriple carries the three RFC 5440 §5.5.3 timer values.
// Local and Peer are nil until the corresponding Open message is exchanged.
// Effective is nil until the session reaches SESSION_STATE_UP.
type timerTriple struct {
	Local     *uint32 `json:"local"`
	Peer      *uint32 `json:"peer"`
	Effective *uint32 `json:"effective"`
}

type transportView struct {
	Protocol string `json:"protocol"`
	Auth     string `json:"auth"`
}

type counterView struct {
	Sent uint64 `json:"sent"`
	Rcvd uint64 `json:"rcvd"`
}

type sessionSetupView struct {
	OK   uint64 `json:"ok"`
	Fail uint64 `json:"fail"`
}

// statsView maps per-session PCEP statistics to the CLI/JSON representation.
// Most fields correspond to RFC 9826 ietf-pcep-stats; open and close are
// Pola-specific additions for session lifecycle visibility.
type statsView struct {
	Open             counterView      `json:"open"`
	Keepalive        counterView      `json:"keepalive"`
	Close            counterView      `json:"close"`
	PCErr            counterView      `json:"pcerr"`
	PCNtf            counterView      `json:"pcntf"`
	PCReq            counterView      `json:"pcreq"`
	PCRep            counterView      `json:"pcrep"`
	Report           counterView      `json:"report"`
	Update           counterView      `json:"update"`
	Initiate         counterView      `json:"initiate"`
	UnrecognizedRcvd uint64           `json:"unrecognizedRcvd"`
	CorruptRcvd      uint64           `json:"corruptRcvd"`
	SessionSetup     sessionSetupView `json:"sessionSetup"`
}

// sessionRole reports Pola's PCE role based on its own advertised U-flag.
func sessionRole(localCaps []grpc.Capability) string {
	for _, c := range localCaps {
		if sc, ok := c.Detail.(grpc.StatefulCapability); ok {
			if sc.LSPUpdate {
				return "active-stateful-pce"
			}
			return "passive-stateful-pce"
		}
	}
	return "stateless-pce"
}

// formatUpTime formats a non-negative duration as "HH:MM:SS". Hours are not
// capped at 24, so durations over a day are rendered with hours greater than 24.
func formatUpTime(d time.Duration) string {
	total := max(int64(d.Seconds()), 0)
	hours := total / 3600
	minutes := (total % 3600) / 60
	seconds := total % 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func timersViewFrom(local, peer *grpc.SessionTimers, effective grpc.EffectiveTimers) timersView {
	var localKeepalive, localDeadTimer, peerKeepalive, peerDeadTimer *uint32
	if local != nil {
		localKeepalive = new(local.Keepalive)
		localDeadTimer = new(local.DeadTimer)
	}
	if peer != nil {
		peerKeepalive = new(peer.Keepalive)
		peerDeadTimer = new(peer.DeadTimer)
	}
	return timersView{
		Keepalive: timerTriple{Local: localKeepalive, Peer: peerKeepalive, Effective: effective.Keepalive},
		DeadTimer: timerTriple{Local: localDeadTimer, Peer: peerDeadTimer, Effective: effective.DeadTimer},
	}
}

func statsViewFrom(s grpc.SessionStats) *statsView {
	toCounter := func(c grpc.MessageCounter) counterView { return counterView{Sent: c.Sent, Rcvd: c.Rcvd} }
	return &statsView{
		Open:             toCounter(s.Open),
		Keepalive:        toCounter(s.Keepalive),
		Close:            toCounter(s.Close),
		PCErr:            toCounter(s.PCErr),
		PCNtf:            toCounter(s.PCNtf),
		PCReq:            toCounter(s.PCReq),
		PCRep:            toCounter(s.PCRep),
		Report:           toCounter(s.Report),
		Update:           toCounter(s.Update),
		Initiate:         toCounter(s.Initiate),
		UnrecognizedRcvd: s.UnrecognizedRcvd,
		CorruptRcvd:      s.CorruptRcvd,
		SessionSetup:     sessionSetupView{OK: s.SessSetupOK, Fail: s.SessSetupFail},
	}
}

// newSessionView derives the CLI/JSON view from a grpc.Session.
// Detail mode adds session creation time, initiator, and statistics.
func newSessionView(ss grpc.Session, detail bool) sessionView {
	v := sessionView{
		PeerAddress:  ss.PeerAddr.String(),
		State:        ss.State,
		LSPDBSync:    ss.SyncState,
		Role:         sessionRole(ss.LocalCapabilities),
		SessionID:    sessionIDView{Local: ss.LocalSessionID, Peer: ss.PeerSessionID},
		Timers:       timersViewFrom(ss.LocalTimers, ss.PeerTimers, ss.EffectiveTimers),
		Transport:    transportView{Protocol: "tcp", Auth: "none"},
		Capabilities: buildCapabilitiesView(ss.LocalCapabilities, ss.PeerCapabilities),
	}

	if ss.UptimeNanos > 0 {
		v.UpTime = formatUpTime(time.Duration(ss.UptimeNanos))
	}

	if detail {
		if !ss.CreatedAt.IsZero() {
			v.SessionCreation = ss.CreatedAt.UTC().Format(time.RFC3339)
		}
		v.Initiator = ss.Initiator
		if ss.Stats != nil {
			v.Stats = statsViewFrom(*ss.Stats)
		}
	}

	return v
}
