// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/nttcom/pola/internal/version"
)

func main() {
	os.Exit(mainRun(os.Args[1:], os.Stdout, os.Stderr))
}

func mainRun(args []string, out, errOut io.Writer) int {
	if len(args) > 0 && args[0] == "--version" {
		fmt.Fprintf(out, "pola %s\n", version.Version())
		return 0
	}

	cmd := newRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	if err := cmd.Execute(); err != nil {
		return 1
	}

	return 0
}
