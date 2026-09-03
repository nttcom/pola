// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package server implements the pola PCE: PCEP session management and the gRPC API.
package server

// Error represents an error from a PCE server component.
type Error struct {
	Error  error
	Server string
}
