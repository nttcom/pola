// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command coverage-diff reports added lines that are not covered by tests.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// generated code under api/ and examples/ are excluded from coverage.
var defaultPaths = []string{"cmd", "internal", "pkg"}

const maxLine = 4 << 20

// errBelowThreshold indicates a coverage gate failure.
var errBelowThreshold = errors.New("patch coverage below threshold")

type config struct {
	base    string
	profile string
	min     float64
	paths   []string
}

func main() {
	var cfg config
	flag.StringVar(&cfg.base, "base", "origin/main", "branch or commit to compare against; its merge base with HEAD is used")
	flag.StringVar(&cfg.profile, "profile", "coverage.out", "coverage profile produced by go test -coverprofile")
	flag.Float64Var(&cfg.min, "min", -1, "fail if patch coverage is below this percentage; negative disables the gate")
	flag.Parse()

	cfg.paths = flag.Args()
	if len(cfg.paths) == 0 {
		cfg.paths = defaultPaths
	}

	os.Exit(realMain(cfg))
}

func realMain(cfg config) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch err := run(ctx, cfg, os.Stdout); {
	case err == nil:
		return 0
	case errors.Is(err, errBelowThreshold):
		fmt.Fprintf(os.Stderr, "coverage-diff: %v\n", err)
		return 1
	default:
		fmt.Fprintf(os.Stderr, "coverage-diff: %v\n", err)
		return 2
	}
}

func run(ctx context.Context, cfg config, out io.Writer) error {
	module, err := goModule(ctx)
	if err != nil {
		return err
	}

	mergeBase, err := git(ctx, "merge-base", cfg.base, "HEAD")
	if err != nil {
		return fmt.Errorf("no merge base for %q and HEAD (in CI, check out with fetch-depth: 0): %w", cfg.base, err)
	}

	diff, err := gitDiff(ctx, mergeBase, cfg.paths)
	if err != nil {
		return err
	}

	changed, err := parseHunks(bytes.NewReader(diff), instrumentable)
	if err != nil {
		return fmt.Errorf("parsing diff: %w", err)
	}

	f, err := os.Open(cfg.profile)
	if err != nil {
		return fmt.Errorf("open coverage profile %q: %w", cfg.profile, err)
	}
	defer func() {
		_ = f.Close()
	}()

	res, err := parseProfile(f, module, changed)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", cfg.profile, err)
	}

	return report(res, cfg.min, mergeBase, out)
}

func report(res *result, minPercent float64, mergeBase string, out io.Writer) error {
	if _, err := io.WriteString(out, formatReport(res, mergeBase)); err != nil {
		return fmt.Errorf("write coverage report: %w", err)
	}

	if res.total == 0 {
		return nil
	}

	pct := res.percent()
	if minPercent >= 0 && rounded(pct) < minPercent {
		return fmt.Errorf("%w: %.1f%% < %.1f%%", errBelowThreshold, pct, minPercent)
	}

	return nil
}

func formatReport(res *result, mergeBase string) string {
	if res.total == 0 {
		return fmt.Sprintf("diff coverage: no instrumented lines changed since %s\n", short(mergeBase))
	}

	var lines []string

	for _, f := range res.files {
		if len(f.uncovered) > 0 {
			lines = append(lines, fmt.Sprintf("%s: uncovered added lines %s", f.file, formatRanges(f.uncovered)))
		}
	}

	lines = append(lines, fmt.Sprintf("diff coverage: %.1f%% (%d/%d changed instrumented lines covered since %s)",
		res.percent(), res.covered, res.total, short(mergeBase)))

	return strings.Join(lines, "\n") + "\n"
}

// instrumentable reports whether a path can appear in a coverage profile.
func instrumentable(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

// rounded matches %.1f formatting used in the report.
func rounded(pct float64) float64 {
	formatted := strconv.FormatFloat(pct, 'f', 1, 64)

	v, err := strconv.ParseFloat(formatted, 64)
	if err != nil {
		return pct
	}

	return v
}

func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}

	return rev
}

func gitDiff(ctx context.Context, mergeBase string, paths []string) ([]byte, error) {
	// -U0 reports only added lines; the other flags make the parsed diff format
	// independent of external diff, color, and prefix configuration.
	args := make([]string, 0, 8+len(paths))
	args = append(args,
		"diff", "-U0", "--no-ext-diff", "--no-color",
		"--src-prefix=a/", "--dst-prefix=b/", mergeBase, "--",
	)
	args = append(args, paths...)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff since %s: %w", mergeBase, err)
	}

	return out, nil
}

func git(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stderr = io.Discard
	b, err := cmd.Output()

	return strings.TrimSpace(string(b)), err
}

func goModule(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m")
	cmd.Stderr = os.Stderr

	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolving module path: %w", err)
	}

	return strings.TrimSpace(string(b)), nil
}

type (
	lineSet      map[int]bool
	changedLines map[string]lineSet
)

var hunkRe = regexp.MustCompile(`^@@+ .*?\+(\d+)(?:,(\d+))? @@`)

// parseHunks extracts added lines from a unified diff, keeping only paths
// accepted by keep. File headers are recognized only after "diff --git" so
// content beginning with "+++" is not mistaken for a header.
func parseHunks(r io.Reader, keep func(string) bool) (changedLines, error) {
	out := changedLines{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	var (
		cur                   string
		inHeader, wantNewPath bool
	)

	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			cur, inHeader, wantNewPath = "", true, false
		case inHeader && strings.HasPrefix(line, "--- "):
			wantNewPath = true
		case wantNewPath && strings.HasPrefix(line, "+++ "):
			cur, inHeader, wantNewPath = newPath(line, keep), false, false
		case cur != "" && strings.HasPrefix(line, "@@"):
			addHunk(out, cur, line)
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading diff output: %w", err)
	}

	return out, nil
}

func newPath(header string, keep func(string) bool) string {
	p := strings.TrimPrefix(header, "+++ ")
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}

	if p == "/dev/null" {
		return ""
	}

	p = strings.TrimPrefix(p, "b/")
	if !keep(p) {
		return ""
	}

	return p
}

func addHunk(out changedLines, file, header string) {
	m := hunkRe.FindStringSubmatch(header)
	if m == nil {
		return
	}

	start, err := strconv.Atoi(m[1])
	if err != nil {
		return
	}

	count := 1 // omitted count means one line
	if m[2] != "" {
		if count, err = strconv.Atoi(m[2]); err != nil {
			return
		}
	}

	for i := range count {
		mark(out, file, start+i)
	}
}

func mark(m map[string]lineSet, file string, line int) {
	if m[file] == nil {
		m[file] = lineSet{}
	}

	m[file][line] = true
}

type block struct {
	file     string
	start    int
	startCol int
	end      int
	endCol   int
	count    int
}

// supportedModes lists the coverage modes supported by go test.
var supportedModes = []string{"set", "count", "atomic"}

func validateModeLine(line string, sawMode bool) error {
	if sawMode {
		return fmt.Errorf("duplicate coverage mode header: %q", line)
	}

	mode := strings.TrimPrefix(line, "mode: ")
	if !slices.Contains(supportedModes, mode) {
		return fmt.Errorf("unsupported coverage mode: %q", mode)
	}

	return nil
}

func markBlockLines(seen, covered map[string]lineSet, src *sourceIndex, file string, b block, added lineSet) {
	for ln := range added {
		if ln < b.start || ln > b.end || !src.hasStatement(file, b, ln) {
			continue
		}

		mark(seen, file, ln)

		if b.count > 0 {
			mark(covered, file, ln)
		}
	}
}

func parseProfile(r io.Reader, module string, changed changedLines) (*result, error) {
	seen := map[string]lineSet{}
	covered := map[string]lineSet{}
	src := newSourceIndex()

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	sawMode := false

	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode: ") {
			if err := validateModeLine(line, sawMode); err != nil {
				return nil, err
			}

			sawMode = true

			continue
		}

		if !sawMode {
			return nil, errors.New("coverage profile missing mode header")
		}

		b, ok := parseProfileLine(line)
		if !ok {
			return nil, fmt.Errorf("malformed coverage profile line: %q", line)
		}

		file := stripModule(b.file, module)

		added := changed[file]
		if added == nil {
			continue
		}

		markBlockLines(seen, covered, src, file, b, added)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading coverage profile: %w", err)
	}

	if !sawMode {
		return nil, errors.New("coverage profile missing mode header")
	}

	return summarize(seen, covered), nil
}

// parseProfileLine parses "<import path>/<file>.go:<sl>.<sc>,<el>.<ec> <stmts> <count>".
func parseProfileLine(s string) (block, bool) {
	fields := strings.Fields(s)
	if len(fields) != 3 {
		return block{}, false
	}

	colon := strings.LastIndexByte(fields[0], ':')
	if colon < 0 {
		return block{}, false
	}

	spans := strings.SplitN(fields[0][colon+1:], ",", 2)
	if len(spans) != 2 {
		return block{}, false
	}

	startLine, startCol, ok1 := posOf(spans[0])
	endLine, endCol, ok2 := posOf(spans[1])
	stmts, stmtsErr := strconv.Atoi(fields[1])

	count, countErr := strconv.Atoi(fields[2])
	if !ok1 || !ok2 || stmtsErr != nil || countErr != nil || stmts < 0 || count < 0 {
		return block{}, false
	}

	if endLine < startLine || (endLine == startLine && endCol < startCol) {
		return block{}, false
	}

	return block{file: fields[0][:colon], start: startLine, startCol: startCol, end: endLine, endCol: endCol, count: count}, true
}

// posOf parses a "<line>.<col>" coverage profile position.
func posOf(pos string) (line, col int, ok bool) {
	before, after, ok0 := strings.Cut(pos, ".")
	if !ok0 {
		return 0, 0, false
	}

	line, err := strconv.Atoi(before)
	if err != nil || line < 1 {
		return 0, 0, false
	}

	col, err = strconv.Atoi(after)
	if err != nil || col < 1 {
		return 0, 0, false
	}

	return line, col, true
}

func stripModule(name, module string) string {
	return strings.TrimPrefix(name, module+"/")
}

// sourceIndex indexes source code positions for coverage blocks.
type sourceIndex struct {
	fset  *token.FileSet
	files map[string]*token.File
	code  map[string][]token.Pos // positions of non-brace tokens, ascending
	fail  map[string]bool
}

func newSourceIndex() *sourceIndex {
	return &sourceIndex{
		fset:  token.NewFileSet(),
		files: map[string]*token.File{},
		code:  map[string][]token.Pos{},
		fail:  map[string]bool{},
	}
}

func (idx *sourceIndex) ensure(file string) {
	if _, ok := idx.files[file]; ok || idx.fail[file] {
		return
	}

	src, err := os.ReadFile(file)
	if err != nil {
		idx.fail[file] = true
		return
	}

	tf := idx.fset.AddFile(file, -1, len(src))

	var sc scanner.Scanner
	sc.Init(tf, src, nil, scanner.ScanComments)

	var code []token.Pos

	for {
		pos, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		//nolint:exhaustive // only COMMENT, LBRACE, and RBRACE need special handling
		switch tok {
		case token.COMMENT:
			if isLineDirective(lit) {
				idx.fail[file] = true
				return
			}

			continue
		case token.LBRACE, token.RBRACE:
			continue
		}

		code = append(code, pos)

		if tok == token.STRING {
			if n := strings.Count(lit, "\n"); n > 0 {
				startLine := tf.PositionFor(pos, false).Line
				for line := startLine + 1; line <= startLine+n; line++ {
					code = append(code, tf.LineStart(line))
				}
			}
		}
	}

	slices.Sort(code)

	idx.files[file] = tf
	idx.code[file] = code
}

// isLineDirective reports whether a comment may be a //line directive.
func isLineDirective(lit string) bool {
	return strings.HasPrefix(lit, "//line ") || strings.HasPrefix(lit, "/*line ")
}

// hasStatement reports whether the block range on line ln contains code.
// Unanalyzable files conservatively count the line as code.
func (idx *sourceIndex) hasStatement(file string, b block, ln int) bool {
	idx.ensure(file)

	if idx.fail[file] {
		return true
	}

	tf := idx.files[file]
	if ln < 1 || ln > tf.LineCount() {
		return true
	}

	segStart := tf.LineStart(ln)
	if ln == b.start {
		segStart += token.Pos(b.startCol - 1)
	}

	segEnd := token.Pos(tf.Base() + tf.Size())
	if ln == b.end {
		segEnd = tf.LineStart(ln) + token.Pos(b.endCol-1)
	} else if ln < tf.LineCount() {
		segEnd = tf.LineStart(ln + 1)
	}

	code := idx.code[file]
	i := sort.Search(len(code), func(i int) bool { return code[i] >= segStart })

	return i < len(code) && code[i] < segEnd
}

type fileResult struct {
	file      string
	total     int
	covered   int
	uncovered []int
}

type result struct {
	files   []fileResult
	total   int
	covered int
}

func (r *result) percent() float64 {
	if r.total == 0 {
		return 100
	}

	return 100 * float64(r.covered) / float64(r.total)
}

func summarize(seen, covered map[string]lineSet) *result {
	res := &result{}

	for file, lines := range seen {
		fr := fileResult{file: file, total: len(lines)}
		for ln := range lines {
			if covered[file][ln] {
				fr.covered++
			} else {
				fr.uncovered = append(fr.uncovered, ln)
			}
		}

		slices.Sort(fr.uncovered)
		res.files = append(res.files, fr)
		res.total += fr.total
		res.covered += fr.covered
	}

	slices.SortFunc(res.files, func(a, b fileResult) int { return strings.Compare(a.file, b.file) })

	return res
}

// formatRanges formats sorted line numbers as compact ranges.
func formatRanges(lines []int) string {
	var parts []string

	for i := 0; i < len(lines); {
		j := i
		for j+1 < len(lines) && lines[j+1] == lines[j]+1 {
			j++
		}

		if j == i {
			parts = append(parts, strconv.Itoa(lines[i]))
		} else {
			parts = append(parts, strconv.Itoa(lines[i])+"-"+strconv.Itoa(lines[j]))
		}

		i = j + 1
	}

	return strings.Join(parts, ",")
}
