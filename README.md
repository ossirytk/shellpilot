# shellpilot

Safe subprocess runner MCP server with command allowlist and audit log.

> **Status:** 🚧 Work in progress

shellpilot is a single Rust binary that exposes a curated set of shell commands as MCP tools. Every execution is validated against an explicit allowlist and recorded to an audit log, keeping AI-driven automation safe and auditable.

---

## Tools

| Tool | Description |
|------|-------------|
| `run` | Execute an allowlisted command with optional arguments and working directory |
| `list_allowed` | Return the current command allowlist |
| `audit_log` | Retrieve recent subprocess execution audit log entries |

---

## Installation

> Coming soon.

---

## Development

```sh
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Run tests
cargo test
```
