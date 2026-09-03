// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"os"

	"github.com/nttcom/pola/internal/version"
)

func main() {
	os.Exit(mainRun(os.Args[1:]))
}

func mainRun(args []string) int {
	if len(args) > 0 && args[0] == "--version" {
		fmt.Printf("pola %s\n", version.Version())
		return 0
	}

	cmd := newRootCmd()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		return 1
	}
	return 0
}
