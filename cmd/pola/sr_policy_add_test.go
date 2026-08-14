// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nttcom/pola/pkg/server"
)

// TestReasonConstantsMatchServer ensures the duplicated Reason constants stay in sync.
// cmd/pola cannot import pkg/server without pulling in the server implementation.
func TestReasonConstantsMatchServer(t *testing.T) {
	assert.Equal(t, server.ReasonTEDDisabled, reasonTEDDisabled)
	assert.Equal(t, server.ReasonTEDNotSynced, reasonTEDNotSynced)
	assert.Equal(t, server.ReasonDestinationUnreachable, reasonDestinationUnreach)
	assert.Equal(t, server.ReasonMetricNotCarried, reasonMetricNotCarried)
	assert.Equal(t, server.ReasonPCEPSessionNotSynced, reasonPCEPSessionNotSynced)
	assert.Equal(t, server.ReasonSIDValidationFailed, reasonSIDValidationFailed)
}

func TestTranslateCreateSRPolicyError(t *testing.T) {
	newErr := func(code codes.Code, reason, msg string) error {
		st := status.New(code, msg)
		withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "pola"})
		if err != nil {
			t.Fatalf("failed to attach ErrorInfo: %v", err)
		}
		return withDetails.Err()
	}

	tests := []struct {
		name     string
		err      error
		wantHint string
	}{
		{"SID validation failure gets the no-sid-validate hint", newErr(codes.FailedPrecondition, "SID_VALIDATION_FAILED", "SID validation failed"), "--no-sid-validate"},
		{"TED disabled gets a TED hint, not the SID hint", newErr(codes.FailedPrecondition, "TED_DISABLED", "ted is disabled"), "enable TED sync"},
		{"TED not synced gets a retry hint", newErr(codes.FailedPrecondition, "TED_NOT_SYNCED", "no node in TED"), "retry shortly"},
		{"unsynced PCEP session gets a session hint", newErr(codes.FailedPrecondition, "PCEP_SESSION_NOT_SYNCED", "no synced session with 10.0.0.1"), "PCEP session"},
		{"unreachable destination gets a topology hint", newErr(codes.FailedPrecondition, "DESTINATION_UNREACHABLE", "next node not found"), "no path exists"},
		{"uncarried metric gets a metric hint", newErr(codes.FailedPrecondition, "METRIC_NOT_CARRIED", "metric METRIC_TYPE_TE not defined"), "not advertised"},
		{"invalid argument gets no hint", newErr(codes.InvalidArgument, "INVALID_REQUEST", "ASN must not be zero"), ""},
		{"a plain error passes through unchanged", assert.AnError, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateCreateSRPolicyError(tt.err)
			if tt.wantHint == "" {
				assert.NotContains(t, got.Error(), "hint:")
				return
			}
			assert.Contains(t, got.Error(), tt.wantHint)
		})
	}
}
