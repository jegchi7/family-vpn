// This executable is a fail-fast placeholder, not a working service.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "foreign-probe: not implemented in iteration 01; no network or system changes performed")
	os.Exit(2)
}
