// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const module = "github.com/nttcom/pola"

func keepAll(string) bool { return true }

func TestInstrumentable(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"pkg/table/table.go", true},
		{"pkg/table/table_test.go", false},
		{"README.md", false},
		{"test/conftest.py", false},
		{"pkg/gone.go", true},
	}
	for _, tt := range tests {
		if got := instrumentable(tt.path); got != tt.want {
			t.Errorf("instrumentable(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestParseHunks(t *testing.T) {
	tests := []struct {
		name string
		diff string
		want changedLines
	}{
		{
			name: "added lines with explicit count",
			diff: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -10,0 +11,3 @@\n+x\n+y\n+z\n",
			want: changedLines{"a.go": {11: true, 12: true, 13: true}},
		},
		{
			name: "single changed line omits the count",
			diff: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -21 +21 @@\n-old\n+new\n",
			want: changedLines{"a.go": {21: true}},
		},
		{
			name: "deletion-only hunk adds nothing",
			diff: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -30,2 +32,0 @@\n-gone\n-gone\n",
			want: changedLines{},
		},
		{
			name: "new file",
			diff: "diff --git a/n.go b/n.go\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/n.go\n@@ -0,0 +1,2 @@\n+a\n+b\n",
			want: changedLines{"n.go": {1: true, 2: true}},
		},
		{
			name: "deleted file is skipped",
			diff: "diff --git a/d.go b/d.go\ndeleted file mode 100644\n--- a/d.go\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n",
			want: changedLines{},
		},
		{
			name: "multiple files and hunks",
			diff: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1,0 +2,1 @@\n+a\n@@ -9,0 +11,2 @@\n+b\n+c\n" +
				"diff --git a/b.go b/b.go\n--- a/b.go\n+++ b/b.go\n@@ -5,0 +6,1 @@\n+d\n",
			want: changedLines{"a.go": {2: true, 11: true, 12: true}, "b.go": {6: true}},
		},
		{
			name: "content line starting with +++",
			diff: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1,0 +2,2 @@\n+++ b/evil.go\n+@@ -1 +99 @@\n",
			want: changedLines{"a.go": {2: true, 3: true}},
		},
		{
			name: "combined diff hunk header",
			diff: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@@ -1,2 -3,4 +5,2 @@@\n+a\n+b\n",
			want: changedLines{"a.go": {5: true, 6: true}},
		},
		{
			name: "empty diff",
			diff: "",
			want: changedLines{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHunks(strings.NewReader(tt.diff), keepAll)
			if err != nil {
				t.Fatalf("parseHunks() error = %v", err)
			}
			assertChangedLines(t, got, tt.want)
		})
	}
}

func TestParseHunksAppliesKeep(t *testing.T) {
	diff := "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1,0 +2,1 @@\n+a\n" +
		"diff --git a/a_test.go b/a_test.go\n--- a/a_test.go\n+++ b/a_test.go\n@@ -1,0 +2,1 @@\n+a\n"
	got, err := parseHunks(strings.NewReader(diff), instrumentable)
	if err != nil {
		t.Fatalf("parseHunks() error = %v", err)
	}
	assertChangedLines(t, got, changedLines{"a.go": {2: true}})
}

func assertChangedLines(t *testing.T, got, want changedLines) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("files = %v, want %v", keys(got), keys(want))
	}
	for file, wantLines := range want {
		gotLines := got[file]
		if len(gotLines) != len(wantLines) {
			t.Errorf("%s: lines = %v, want %v", file, gotLines, wantLines)
			continue
		}
		for ln := range wantLines {
			if !gotLines[ln] {
				t.Errorf("%s: line %d missing", file, ln)
			}
		}
	}
}

func keys(c changedLines) []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	return out
}

func TestParseProfileLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want block
		ok   bool
	}{
		{
			name: "valid",
			line: "github.com/nttcom/pola/pkg/table/table.go:12.34,56.7 8 9",
			want: block{file: "github.com/nttcom/pola/pkg/table/table.go", start: 12, end: 56, count: 9},
			ok:   true,
		},
		{
			name: "zero count",
			line: "m/a.go:1.1,2.2 1 0",
			want: block{file: "m/a.go", start: 1, end: 2, count: 0},
			ok:   true,
		},
		{name: "mode preamble", line: "mode: set"},
		{name: "empty", line: ""},
		{name: "missing count field", line: "m/a.go:1.1,2.2 1"},
		{name: "no colon", line: "a.go 1 2"},
		{name: "no comma", line: "m/a.go:1.1 1 2"},
		{name: "no column", line: "m/a.go:1,2 1 2"},
		{name: "non-numeric line", line: "m/a.go:x.1,2.2 1 2"},
		{name: "non-numeric count", line: "m/a.go:1.1,2.2 1 x"},
		{name: "end before start", line: "m/a.go:9.1,2.2 1 2"},
		{name: "zero line", line: "m/a.go:0.1,2.2 1 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseProfileLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("block = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name          string
		profile       string
		changed       changedLines
		wantTotal     int
		wantCovered   int
		wantUncovered map[string][]int
	}{
		{
			name: "covered and uncovered blocks",
			profile: "mode: set\n" +
				module + "/a.go:1.1,3.2 2 1\n" +
				module + "/a.go:5.1,6.2 1 0\n",
			changed:       changedLines{"a.go": {1: true, 2: true, 5: true, 6: true}},
			wantTotal:     4,
			wantCovered:   2,
			wantUncovered: map[string][]int{"a.go": {5, 6}},
		},
		{
			name:          "block partially overlapping the hunk",
			profile:       "mode: set\n" + module + "/a.go:10.20,14.3 1 0\n",
			changed:       changedLines{"a.go": {12: true, 13: true}},
			wantTotal:     2,
			wantCovered:   0,
			wantUncovered: map[string][]int{"a.go": {12, 13}},
		},
		{
			name: "overlapping blocks union their counts",
			profile: "mode: set\n" +
				module + "/i.go:120.2,121.9 2 1\n" +
				module + "/i.go:121.9,123.3 1 0\n",
			changed:       changedLines{"i.go": {120: true, 121: true, 122: true, 123: true}},
			wantTotal:     4,
			wantCovered:   2,
			wantUncovered: map[string][]int{"i.go": {122, 123}},
		},
		{
			name: "duplicate blocks are idempotent",
			profile: "mode: set\n" +
				module + "/a.go:1.1,2.2 1 1\n" +
				module + "/a.go:1.1,2.2 1 1\n" +
				module + "/a.go:1.1,2.2 1 1\n",
			changed:     changedLines{"a.go": {1: true, 2: true}},
			wantTotal:   2,
			wantCovered: 2,
		},
		{
			name:        "changed lines holding no statements are not counted",
			profile:     "mode: set\n" + module + "/a.go:10.1,12.2 1 1\n",
			changed:     changedLines{"a.go": {1: true, 2: true, 99: true}},
			wantTotal:   0,
			wantCovered: 0,
		},
		{
			name:        "unchanged files are ignored",
			profile:     "mode: set\n" + module + "/other.go:1.1,9.2 1 0\n",
			changed:     changedLines{"a.go": {1: true}},
			wantTotal:   0,
			wantCovered: 0,
		},
		{
			name:        "paths outside the module are ignored",
			profile:     "mode: set\nexample.com/dep/a.go:1.1,2.2 1 0\n",
			changed:     changedLines{"a.go": {1: true, 2: true}},
			wantTotal:   0,
			wantCovered: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseProfile(strings.NewReader(tt.profile), module, tt.changed)
			if err != nil {
				t.Fatalf("parseProfile() error = %v", err)
			}
			if res.total != tt.wantTotal || res.covered != tt.wantCovered {
				t.Errorf("total/covered = %d/%d, want %d/%d", res.total, res.covered, tt.wantTotal, tt.wantCovered)
			}
			for _, fr := range res.files {
				want, ok := tt.wantUncovered[fr.file]
				if !ok {
					if len(fr.uncovered) > 0 {
						t.Errorf("%s: unexpected uncovered %v", fr.file, fr.uncovered)
					}
					continue
				}
				if !equalInts(fr.uncovered, want) {
					t.Errorf("%s: uncovered = %v, want %v", fr.file, fr.uncovered, want)
				}
			}
		})
	}
}

func TestParseProfileSortsFiles(t *testing.T) {
	profile := "mode: set\n" +
		module + "/z.go:1.1,1.2 1 0\n" +
		module + "/a.go:1.1,1.2 1 0\n" +
		module + "/m.go:1.1,1.2 1 0\n"
	changed := changedLines{"z.go": {1: true}, "a.go": {1: true}, "m.go": {1: true}}

	res, err := parseProfile(strings.NewReader(profile), module, changed)
	if err != nil {
		t.Fatalf("parseProfile() error = %v", err)
	}
	var got []string
	for _, fr := range res.files {
		got = append(got, fr.file)
	}
	if !equalStrings(got, []string{"a.go", "m.go", "z.go"}) {
		t.Errorf("files = %v, want sorted", got)
	}
}

func TestStripModule(t *testing.T) {
	if got := stripModule(module+"/pkg/a.go", module); got != "pkg/a.go" {
		t.Errorf("stripModule() = %q, want %q", got, "pkg/a.go")
	}
	if got := stripModule("example.com/x/a.go", module); got != "example.com/x/a.go" {
		t.Errorf("stripModule() = %q, want unchanged", got)
	}
	if got := stripModule(module+"-extra/a.go", module); got != module+"-extra/a.go" {
		t.Errorf("stripModule() = %q, want unchanged", got)
	}
}

func TestFormatRanges(t *testing.T) {
	tests := []struct {
		lines []int
		want  string
	}{
		{nil, ""},
		{[]int{5}, "5"},
		{[]int{1, 2, 3}, "1-3"},
		{[]int{122, 123, 185, 230, 231, 232, 264}, "122-123,185,230-232,264"},
		{[]int{1, 3, 5}, "1,3,5"},
		{[]int{1, 2, 4, 5}, "1-2,4-5"},
	}
	for _, tt := range tests {
		if got := formatRanges(tt.lines); got != tt.want {
			t.Errorf("formatRanges(%v) = %q, want %q", tt.lines, got, tt.want)
		}
	}
}

func TestResultPercent(t *testing.T) {
	if got := (&result{}).percent(); got != 100 {
		t.Errorf("percent() on empty = %v, want 100", got)
	}
	if got := (&result{total: 4, covered: 3}).percent(); got != 75 {
		t.Errorf("percent() = %v, want 75", got)
	}
}

func TestReport(t *testing.T) {
	tests := []struct {
		name        string
		res         *result
		min         float64
		wantErr     bool
		wantContain []string
	}{
		{
			name:        "no instrumented lines changed",
			res:         &result{},
			min:         90,
			wantContain: []string{"no instrumented lines changed"},
		},
		{
			name: "below threshold fails",
			res: &result{
				files:   []fileResult{{file: "a.go", total: 4, covered: 2, uncovered: []int{5, 6}}},
				total:   4,
				covered: 2,
			},
			min:         90,
			wantErr:     true,
			wantContain: []string{"a.go: uncovered added lines 5-6", "diff coverage: 50.0%", "(2/4"},
		},
		{
			name:        "above threshold passes",
			res:         &result{total: 10, covered: 10},
			min:         90,
			wantContain: []string{"diff coverage: 100.0%"},
		},
		{
			name:        "negative min disables the gate",
			res:         &result{files: []fileResult{{file: "a.go", total: 1, uncovered: []int{3}}}, total: 1},
			min:         -1,
			wantContain: []string{"diff coverage: 0.0%"},
		},
		{
			name:        "threshold compares against the printed value",
			res:         &result{total: 10000, covered: 8996},
			min:         90,
			wantContain: []string{"diff coverage: 90.0%"},
		},
		{
			name:        "exact tie rounds like %.1f",
			res:         &result{total: 400, covered: 349},
			min:         87.3,
			wantErr:     true,
			wantContain: []string{"diff coverage: 87.2%"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := report(tt.res, tt.min, "0123456789abcdef", &buf)
			if tt.wantErr && !errors.Is(err, errBelowThreshold) {
				t.Fatalf("error = %v, want errBelowThreshold", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error = %v", err)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("output %q missing %q", buf.String(), want)
				}
			}
		})
	}
}

func TestShort(t *testing.T) {
	if got := short("0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("short() = %q", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("short() = %q, want unchanged", got)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
