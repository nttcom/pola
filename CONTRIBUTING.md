# Contributing

Thank you for considering contributing to Pola PCE!
Below are the guidelines for contributing.

## Creating Pull Requests

All updates, including those contributed by project members,
must be reviewed via pull request.

## Creating Issues

If you have a bug report, feature request, or other question, please create an issue.
However, please refer to the [security policy](SECURITY.md)
for vulnerabilities.

## Development Workflow (Make)

This project uses Make as the primary interface for development tasks.
For contributor workflows, this document is the recommended entry point.

### Show Available Targets

```bash
make help
```

### Initial Setup

Install development tools used by linting, formatting, and proto checks.

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

# Generate protobuf code
make proto

# Verify generated protobuf code is up to date
make check-proto

# Build Docker images
make image
make image-debug

# Run the same checks as CI
make ci
```

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
