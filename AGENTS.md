# AGENTS.md — Project Rules for AI Assistants (Rust)

shellpilot is a safe subprocess runner MCP server written in Rust. It executes shell commands against an explicit allowlist, records every invocation to an audit log, and exposes the interface as a single statically linked binary communicating over stdio.

---

## Tech Stack

- **Language:** Rust (edition 2024)
- **MCP transport:** newline-delimited JSON-RPC over stdio
- **Build:** cargo (stable toolchain)
- **Linter:** cargo clippy
- **Formatter:** cargo fmt
- **Tests:** cargo test + tempfile

---

## Development Commands

```sh
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run clippy
cargo clippy -- -D warnings

# Format
cargo fmt

# Check format without modifying
cargo fmt --check

# Run tests
cargo test
```

---

## Project Structure

```
shellpilot/
├── src/
│   ├── main.rs      # Async entry point — calls lib::run()
│   ├── lib.rs       # MCP stdio loop (JSON-RPC dispatch)
│   └── tools.rs     # Tool definitions (JSON schemas) and handlers
├── Cargo.toml       # Package metadata and dependencies
├── Cargo.lock       # Locked dependency versions
├── AGENTS.md        # This file
└── README.md        # User-facing documentation
```

---

## Key Conventions

- Tool schemas live in `src/tools.rs` alongside their handler functions.
- The allowlist and audit log implementation will live in `src/allowlist.rs` and `src/audit.rs` once scaffolded.
- `cargo clippy -- -D warnings` and `cargo fmt --check` must pass before every commit.
- Do not add dependencies outside the Cargo ecosystem.
