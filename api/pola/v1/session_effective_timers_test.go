// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package v1

import "testing"

func TestEffectiveKeepalive(t *testing.T) {
	t.Parallel()

	effective := &EffectiveTimers{Keepalive: 30, DeadTimer: 120}

	if v, ok := EffectiveKeepalive(SessionState_SESSION_STATE_UP, effective); v != 30 || !ok {
		t.Errorf("got (%d, %v), want (30, true)", v, ok)
	}

	if v, ok := EffectiveKeepalive(SessionState_SESSION_STATE_KEEP_WAIT, effective); v != 0 || ok {
		t.Errorf("got (%d, %v), want (0, false)", v, ok)
	}

	if v, ok := EffectiveKeepalive(SessionState_SESSION_STATE_UP, nil); v != 0 || ok {
		t.Errorf("got (%d, %v), want (0, false)", v, ok)
	}
}

func TestEffectiveDeadTimer(t *testing.T) {
	t.Parallel()

	effective := &EffectiveTimers{Keepalive: 30, DeadTimer: 120}

	if v, ok := EffectiveDeadTimer(SessionState_SESSION_STATE_UP, effective); v != 120 || !ok {
		t.Errorf("got (%d, %v), want (120, true)", v, ok)
	}

	if v, ok := EffectiveDeadTimer(SessionState_SESSION_STATE_TCP_PENDING, effective); v != 0 || ok {
		t.Errorf("got (%d, %v), want (0, false)", v, ok)
	}

	if v, ok := EffectiveDeadTimer(SessionState_SESSION_STATE_UP, nil); v != 0 || ok {
		t.Errorf("got (%d, %v), want (0, false)", v, ok)
	}
}
