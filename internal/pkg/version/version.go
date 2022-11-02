package version

import "fmt"

const MAJOR uint = 1
const MINOR uint = 1
const PATCH uint = 1

func Version() string {
	return fmt.Sprintf("%d.%d.%d", MAJOR, MINOR, PATCH)
}
