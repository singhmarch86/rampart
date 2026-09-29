// Package version reports build identity - who maintains this binary and
// where its canonical source lives - so a rebuilt or rebranded copy still
// reports its origin when run with -version. This is Rampart's runtime
// counterpart to the NOTICE file: NOTICE binds attribution to the source,
// this binds it to the compiled artifact.
package version

// Author and Repo are fixed source-of-truth identifiers, not build-time
// overrides - a fork is expected to change these if it changes anything,
// same as it would edit LICENSE/NOTICE.
const (
	Author = "Gauravdeep Singh (github.com/singhmarch86)"
	Repo   = "https://github.com/singhmarch86/rampart"
)

var (
	// Version and Commit are set via -ldflags at release build time
	// (see .github/workflows/ci.yml or your own release script), e.g.:
	//   go build -ldflags "-X github.com/singhmarch86/rampart/internal/version.Version=v0.3.0 -X github.com/singhmarch86/rampart/internal/version.Commit=$(git rev-parse --short HEAD)"
	// A plain `go build` with no ldflags is still fully attributed - only
	// the release-identifying fields fall back to placeholders.
	Version = "dev"
	Commit  = "unknown"
)

// String is the full text printed by `rampart -version`.
func String() string {
	return "rampart " + Version + " (" + Commit + ")\n" + Author + "\n" + Repo
}
