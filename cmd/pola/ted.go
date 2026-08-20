// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newTEDCmd() *cobra.Command {
	return &cobra.Command{
		Use: "ted",
		RunE: func(_ *cobra.Command, _ []string) error {
			format, err := resolveOutputFormat(jsonFmt, false)
			if err != nil {
				return err
			}
			return showTED(os.Stdout, format)
		},
	}
}

func showTED(w io.Writer, format outputFormat) error {
	ted, err := grpc.GetTED(client)
	if err != nil {
		return err
	}

	if ted == nil {
		return errors.New("TED is disabled by polad")
	}

	views := newTEDNodeViews(ted.Nodes)

	if format == outputJSON {
		return writeJSON(w, views)
	}
	return writeTEDText(w, views)
}
