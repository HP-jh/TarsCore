// Package version provides semantic version and build metadata for TarsCore.
package version

import "fmt"

var (
	// Version is the current release tag (e.g. "v5.0.0").
	Version = "5.0.0-dev"
	// GitCommit is the short SHA of the commit this binary was built from.
	GitCommit = "unknown"
	// BuildTime is when the binary was built (RFC3339, empty if unknown).
	BuildTime = ""
)

// String returns a human-readable version line.
func String() string {
	if BuildTime != "" {
		return fmt.Sprintf("%s (%s, %s)", Version, GitCommit, BuildTime)
	}
	return fmt.Sprintf("%s (%s)", Version, GitCommit)
}
