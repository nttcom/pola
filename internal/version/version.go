// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package version reports the running binary's version and build metadata.
package version

import (
	"runtime"
	"runtime/debug"
)

const devVersion = "dev"

// version is embedded at build time via ldflags.
var version = devVersion

// Version returns the release version, or "dev" for local builds.
func Version() string {
	return version
}

// Info holds version and build metadata for the running binary.
type Info struct {
	Version   string
	GoVersion string
	Revision  string
	Time      string
	Modified  bool
}

// Get returns the current build Info.
func Get() Info {
	return getWith(version)
}

func getWith(v string) Info {
	info := Info{
		Version:   v,
		GoVersion: runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.Revision, info.Time, info.Modified = vcsSettings(bi.Settings)
	}
	return info
}

func vcsSettings(settings []debug.BuildSetting) (revision, t string, modified bool) {
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			t = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	return revision, t, modified
}
