# Network Recon Agent Development Guide

A lightweight network reconnaissance agent for basic network discovery tasks.

## Purpose

Performs basic network reconnaissance:
- Port scanning
- Service detection
- DNS resolution

## Architecture

```
network-recon/
├── main.go           # Entry point
├── config.go         # Configuration
├── execute.go        # Execution logic
└── internal/
    ├── scan/         # Port scanning
    └── resolve/      # DNS resolution
```

## Taxonomy Usage

- **Node Types**: `host`, `port`, `service`
- **Relationships**: `HAS_PORT`, `RUNS_SERVICE`
- **Findings**: Network-level discoveries

## Development

**IMPORTANT: AI agents must use make commands, not raw go commands.**

```bash
# Build
make build

# Test
make test

# Run all checks (fmt, vet, lint, test)
make check

# See all available targets
make help

# Run via Gibson (PREFERRED)
gibson agent run network-recon --target <target-id>

# Build and run locally (development only)
make run
```

### DON'T: Use Raw Go Commands

```bash
# NEVER do these - they bypass Makefile configuration
go build -o network-recon .  # Use: make build
go test ./...                # Use: make test
go run .                     # Use: make run
```

## SDK Dependency

- Current version: Check `go.mod`
- Update: `go get github.com/zero-day-ai/sdk@vX.Y.Z && go mod tidy`

## Spec Workflow

**IMPORTANT**: The spec-workflow directory ALWAYS lives at `~/Code/zero-day.ai/.spec-workflow`

All specifications, requirements, design documents, and task breakdowns are managed through the spec-workflow MCP tools and stored in this central location, regardless of which subdirectory you're working in.

## See Also

- `../../sdk/CLAUDE.md` - SDK development guide
