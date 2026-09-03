// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"io"

	"github.com/spf13/cobra"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newTEDCmd(c *cli) *cobra.Command {
	cmd := &cobra.Command{
		Use: "ted",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return showTED(cmd.OutOrStdout(), resolveOutputFormat(c.jsonFmt), c.client)
		},
	}
	return cmd
}

func showTED(w io.Writer, format outputFormat, client pb.PCEServiceClient) error {
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
