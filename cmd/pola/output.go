// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// outputFormat selects how command output is rendered.
type outputFormat int

const (
	outputText outputFormat = iota
	outputJSON
)

func resolveOutputFormat(jsonFlag bool) outputFormat {
	if jsonFlag {
		return outputJSON
	}

	return outputText
}

type statusResult struct {
	Status string `json:"status"`
}

const (
	statusSuccess = "success"
	cmdNameDelete = "delete"
)

func writeJSON(w io.Writer, v any) error {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal output as JSON: %w", err)
	}

	_, err = fmt.Fprintln(w, string(out))

	return err
}
