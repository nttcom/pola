// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	errorInfoDomain = "pola"

	ReasonInvalidRequest         = "INVALID_REQUEST"
	ReasonTEDDisabled            = "TED_DISABLED"
	ReasonTEDNotSynced           = "TED_NOT_SYNCED"
	ReasonTEDDataIncomplete      = "TED_DATA_INCOMPLETE"
	ReasonDestinationUnreachable = "DESTINATION_UNREACHABLE"
	ReasonMetricNotCarried       = "METRIC_NOT_CARRIED"
	ReasonPCEPSessionNotSynced   = "PCEP_SESSION_NOT_SYNCED"
	ReasonPCEPSessionNotFound    = "PCEP_SESSION_NOT_FOUND"
	ReasonSIDValidationFailed    = "SID_VALIDATION_FAILED"
	ReasonSRPolicyNotFound       = "SR_POLICY_NOT_FOUND"
	ReasonPCEPRequestFailed      = "PCEP_REQUEST_FAILED"
)

func newStatus(code codes.Code, reason, format string, a ...any) error {
	st := status.Newf(code, format, a...)
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: reason,
		Domain: errorInfoDomain,
	})
	if err != nil {
		// WithDetails only fails for codes.OK, whose status.Errorf would return nil.
		return st.Err()
	}
	return withDetails.Err()
}
