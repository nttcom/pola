// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package server

// Error represents an error from a PCE server component.
type Error struct {
	Error  error
	Server string
}
