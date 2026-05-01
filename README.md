# shellpilot

Safe subprocess runner MCP server with command allowlist and audit log.

shellpilot is a single Rust binary that exposes a curated set of shell commands as MCP tools. Every execution is validated against an explicit allowlist and recorded to an audit log, keeping AI-driven automation safe and auditable.

---

## Tools

| Tool | Description |
|------|-------------|
| `run` | Execute an allowlisted command with optional arguments and working directory |
| `list_allowed` | Return the current command allowlist |
| `audit_log` | Retrieve recent subprocess execution audit log entries |

---

## Configuration

### Allowlist

On first run, shellpilot creates a default allowlist at:

```
~/.config/shellpilot/allowlist.json
```

Default allowed commands: `cat`, `date`, `echo`, `grep`, `head`, `ls`, `pwd`, `tail`, `wc`, `which`, `whoami`

Edit this file to add or remove commands. The server re-reads it on every invocation, so changes take effect immediately without restarting.

> **Note:** Commands containing `/`, `\`, or `..` are always rejected, regardless of the allowlist, to prevent path-traversal exploits. Commands like `find` and `env` that can exec arbitrary binaries are intentionally excluded from the defaults.

### Audit log

Every invocation (including denied and failed ones) is appended to:

```
~/.local/share/shellpilot/audit.log
```

Each entry is a JSON line with: `ts`, `command`, `args`, `cwd`, `exit_code`, `outcome`, `duration_ms`.

---

## Safety properties

- **No shell interpolation** — subprocesses are spawned with `Command::new(name).args(args)`, never via `sh -c`.
- **Hard timeout** — commands are killed after 30 seconds.
- **Output cap** — stdout and stderr are each capped at 64 KB; excess output is replaced with `[...truncated]`.
- **Fail-closed allowlist** — a malformed allowlist file causes an error rather than falling back to defaults.
- **Full audit trail** — all attempts are logged, including denied and failed ones.

---

## Installation

```sh
cargo build --release
# Copy the binary somewhere on your PATH:
cp target/release/shellpilot ~/.local/bin/
```

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

# Check format without modifying
cargo fmt --check

# Run tests
cargo test
```
