// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package version

import "fmt"

const MAJOR uint = 1
const MINOR uint = 3
const PATCH uint = 0

func Version() string {
	return fmt.Sprintf("%d.%d.%d-rc", MAJOR, MINOR, PATCH)
}
