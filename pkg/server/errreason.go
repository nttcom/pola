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

	// ReasonInvalidRequest indicates an invalid request.
	ReasonInvalidRequest = "INVALID_REQUEST"
	// ReasonTEDDisabled indicates the TED is disabled.
	ReasonTEDDisabled = "TED_DISABLED"
	// ReasonTEDNotSynced indicates the TED has not been synchronized.
	ReasonTEDNotSynced = "TED_NOT_SYNCED"
	// ReasonTEDDataIncomplete indicates the TED data is incomplete.
	ReasonTEDDataIncomplete = "TED_DATA_INCOMPLETE"
	// ReasonDestinationUnreachable indicates the destination is unreachable.
	ReasonDestinationUnreachable = "DESTINATION_UNREACHABLE"
	// ReasonMetricNotCarried indicates the metric is not carried.
	ReasonMetricNotCarried = "METRIC_NOT_CARRIED"
	// ReasonPCEPSessionNotSynced indicates the PCEP session has not been synchronized.
	ReasonPCEPSessionNotSynced = "PCEP_SESSION_NOT_SYNCED"
	// ReasonPCEPSessionNotFound indicates the PCEP session was not found.
	ReasonPCEPSessionNotFound = "PCEP_SESSION_NOT_FOUND"
	// ReasonSIDValidationFailed indicates SID validation failed.
	ReasonSIDValidationFailed = "SID_VALIDATION_FAILED"
	// ReasonSRPolicyNotFound indicates the SR Policy was not found.
	ReasonSRPolicyNotFound = "SR_POLICY_NOT_FOUND"
	// ReasonPCEPRequestFailed indicates a PCEP request failed.
	ReasonPCEPRequestFailed = "PCEP_REQUEST_FAILED"
	// ReasonPathComputationFailed indicates path computation failed.
	ReasonPathComputationFailed = "PATH_COMPUTATION_FAILED"
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
