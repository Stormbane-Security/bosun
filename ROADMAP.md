# Bosun Roadmap

## Current State (2026-04-09)

Bosun provides reusable GitHub Actions workflows for Stormbane projects. The main workflow is `go-ci.yml` — a reusable Go CI pipeline.

- **go-ci.yml**: Parallelized lint || build+test || security (govulncheck + gosec)
- **docker.yml**: Docker build + push workflow
- **release.yml**: Release automation
- **release-on-merge.yml**: Auto-release on merge to main

## Recent Changes

### Parallelized Go CI (2026-04-09)
Split single sequential CI job into 3 parallel jobs:
- **lint** (~30s): golangci-lint
- **build-test** (~2min): go build + go test with race detector
- **security** (~1min): govulncheck + gosec

This cut CI time from ~5min to ~2min for all consumers (beacon, drydock).

## Immediate

### Configurable Job Selection
Allow callers to skip jobs they don't need:
```yaml
with:
  skip-security: true  # skip govulncheck + gosec
  skip-lint: true      # skip golangci-lint
```

### Test Coverage Reporting
Add code coverage collection and upload to the build-test job. Report coverage percentage in the summary.

## Medium Term

### Reusable Drydock Workflow
Extract the drydock CI pattern from beacon into a reusable workflow:
```yaml
uses: stormbane-security/bosun/.github/workflows/drydock.yml@main
with:
  test-dir: tests/scanners
  batches: 6
  timeout-minutes: 60
```

### Dependency Update Automation
Renovate/Dependabot config template for Go projects. Auto-merge patch updates, create PRs for minor/major.
