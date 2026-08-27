// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package v1

// EffectiveKeepalive reports the session's effective Keepalive and whether
// it is available.
func EffectiveKeepalive(state SessionState, effective *EffectiveTimers) (value uint32, ok bool) {
	if state != SessionState_SESSION_STATE_UP || effective == nil {
		return 0, false
	}
	return effective.GetKeepalive(), true
}

// EffectiveDeadTimer reports the session's effective DeadTimer and whether
// it is available.
func EffectiveDeadTimer(state SessionState, effective *EffectiveTimers) (value uint32, ok bool) {
	if state != SessionState_SESSION_STATE_UP || effective == nil {
		return 0, false
	}
	return effective.GetDeadTimer(), true
}
