// +build tools

// This file exists to track tool dependencies for the project.
// This file imports those dependencies, so that they are not removed by `go mod tidy`.
// This allows dependabot to manage the dependency versions by having the dependencies in `go.mod`.

package relayer

import (
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
)