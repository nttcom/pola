// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package version

import "fmt"

const Major uint = 1
const Minor uint = 3
const Patch uint = 1

func Version() string {
	return fmt.Sprintf("%d.%d.%d", Major, Minor, Patch)
}
