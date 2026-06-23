//go:build !lambda

package main

import (
	"fmt"
	"os"
)

// runLambda is a no-op when the binary is built without -tags lambda.
// The CryptaMap CLI fails fast and tells the user to rebuild for Lambda.
func runLambda() {
	fmt.Fprintln(os.Stderr, "CRYPTAMAP_MODE=lambda set, but binary was not built with -tags lambda. Rebuild with `make build-lambda`.")
	os.Exit(1)
}
