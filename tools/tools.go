//go:build tools

package tools

// Force direct dependency on code-generator so that it may be executed with go run
import (
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
