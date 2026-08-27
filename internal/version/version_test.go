// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package version

import (
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testRevision = "abc123"

func TestVersion_Default(t *testing.T) {
	assert.Equal(t, devVersion, Version())
}

func TestVersion_Ldflags(t *testing.T) {
	old := version
	defer func() { version = old }()

	version = "1.2.3"
	assert.Equal(t, "1.2.3", Version())
}

func TestGet(t *testing.T) {
	old := version
	defer func() { version = old }()

	version = "1.2.3"
	info := Get()
	assert.Equal(t, "1.2.3", info.Version)
	assert.Equal(t, runtime.Version(), info.GoVersion)
}

func TestVcsSettings(t *testing.T) {
	tests := []struct {
		name         string
		settings     []debug.BuildSetting
		wantRevision string
		wantTime     string
		wantModified bool
	}{
		{
			name: "vcs info present and clean",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: testRevision},
				{Key: "vcs.time", Value: "2026-08-14T00:00:00Z"},
				{Key: "vcs.modified", Value: "false"},
			},
			wantRevision: testRevision,
			wantTime:     "2026-08-14T00:00:00Z",
			wantModified: false,
		},
		{
			name: "vcs info present and modified",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: testRevision},
				{Key: "vcs.modified", Value: "true"},
			},
			wantRevision: testRevision,
			wantModified: true,
		},
		{
			name:         "no vcs info",
			settings:     []debug.BuildSetting{{Key: "GOARCH", Value: "amd64"}},
			wantRevision: "",
			wantTime:     "",
			wantModified: false,
		},
		{
			name:         "no settings",
			settings:     nil,
			wantRevision: "",
			wantTime:     "",
			wantModified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			revision, ts, modified := vcsSettings(tt.settings)
			assert.Equal(t, tt.wantRevision, revision)
			assert.Equal(t, tt.wantTime, ts)
			assert.Equal(t, tt.wantModified, modified)
		})
	}
}
