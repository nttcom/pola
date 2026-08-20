// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// outputFormat selects how command output is rendered.
type outputFormat int

const (
	outputText outputFormat = iota
	outputJSON
	outputYANG
)

func resolveOutputFormat(jsonFlag, yangFlag bool) (outputFormat, error) {
	if jsonFlag && yangFlag {
		return outputText, errors.New("-j and -y are mutually exclusive")
	}
	if jsonFlag {
		return outputJSON, nil
	}
	if yangFlag {
		return outputText, errors.New("YANG output is not implemented")
	}
	return outputText, nil
}

type statusResult struct {
	Status string `json:"status"`
}

func writeJSON(w io.Writer, v any) error {
	out, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(out))
	return err
}
