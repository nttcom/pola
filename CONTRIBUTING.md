# Contributing

Thank you for contributing to Pola PCE! Guidelines below.

## Creating Pull Requests

All updates must be reviewed via pull request.

## Creating Issues

If you have a bug report, feature request, or other question, please create an issue.
However, please refer to the [security policy](SECURITY.md)
for vulnerabilities.

## Development Workflow (Make)

This project uses Make for development tasks.

### Show Available Targets

```bash
make help
```

### Initial Setup

Install development tools for linting, formatting, and proto checks.

```bash
make setup
```

### Common Commands

```bash
# Build binaries (bin/pola, bin/polad)
make build

# Run formatters and auto-fixes
make fmt
make fix

# Run linters
make lint

# Run Go unit tests
make test

# Run unit tests with race detector
make test-race

# Run unit tests and print a coverage summary
make test-coverage

# Same, then open the line-by-line report in a browser
make test-coverage-html

# Report lines this branch adds that no test exercises
make test-coverage-diff

# Coverage covers the main application packages under `cmd/`, `internal/`, and `pkg/`.
# Generated protobuf code under `api/` and standalone examples under `examples/` are excluded.

# Generate protobuf code
make proto

# Verify generated protobuf code is up to date
make check-proto

# Regenerate the third-party license file (run after adding/updating dependencies)
make licenses

# Build Docker images
make image
make image-debug

# Run the same checks as CI
make ci
```

### Test Coverage

CI checks **patch coverage**: what percentage of *new* lines your branch adds are exercised by tests (default 90% minimum). This is a better signal than total coverage changes.

To see what your branch would be flagged for:

```bash
make test-coverage-diff
```

It prints the offending lines and a summary:

```text
internal/gobgp/interface.go: uncovered added lines 122-123,185
diff coverage: 99.3% (2371/2388 changed instrumented lines covered since 318d86a86ef3)
```

Then use `make test-coverage-html` to see those lines in context.

Notes:

* Comparison starts at the merge base of your branch and `DIFF_BASE` (default `origin/develop`) — the same changes a PR shows under "Files changed".
* Coverage is measured against your working tree, not `HEAD`, so uncommitted changes to tracked files are included. Untracked files must be staged with `git add` to be included.
* Only instrumented lines count (Go skips declarations, comments, blanks, closing braces).
* Threshold is `DIFF_COVER_MIN` (default `90`). Override with `make test-coverage-diff DIFF_BASE=origin/develop DIFF_COVER_MIN=85`.

For untestable lines, mention it in the PR rather than working around the check.

### Scenario Tests

Scenario tests run with containerlab and pytest.

```bash
make test-scenario
```

You can pass extra pytest arguments:

```bash
make test-scenario PYTEST_ARGS='-k dynamic_path -s'
```

Run scenario tests in parallel:

```bash
make test-scenario-parallel
```

See [test/README.md](test/README.md) for details.

### Cleanup

```bash
make clean
```

### Notes

* The authoritative list of targets and behavior is in [Makefile](Makefile).
* Docker image runtime examples are documented in [build/package/README.md](build/package/README.md).
