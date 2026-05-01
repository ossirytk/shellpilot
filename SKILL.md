---
name: shellpilot
description: Safe subprocess runner with command allowlist and audit log. Use this skill when the user wants to run a shell command that isn't covered by a structured tool, but should remain auditable and sandboxed. Invoke for prompts like "run this command", "what commands are allowed?", or "show the audit log". Prefer structured tools (toolpilot, gitpilot) over shellpilot when they cover the operation.
---

## Overview

shellpilot is a Rust binary that executes commands from a configurable allowlist via `Command::new()` — no shell interpolation, no `sh -c`. Every execution is recorded to an audit log. Hard timeout of 30 seconds; output capped at 64 KB per stream.

## Available Tools

| Tool | When to use |
|------|-------------|
| `shellpilot-run` | Execute an allowlisted command. Required: `command`, `args` (array). Optional: `cwd`. Returns `stdout`, `stderr`, `exit_code`, `duration_ms`. |
| `shellpilot-list_allowed` | Return the current command allowlist. Use to check what's permitted before attempting a run. |
| `shellpilot-audit_log` | Retrieve recent audit log entries. Includes denied and failed attempts. |

## Default Allowlist

`date`, `echo`, `pwd`, `which`, `whoami`

Commands covered by structured MCP tools are intentionally excluded:
- `cat`, `head`, `tail`, `wc`, `ls`, `grep` → use **toolpilot** instead
- `git` → use **gitpilot** instead

Edit `~/.config/shellpilot/allowlist.json` to add or remove commands. Re-read on every call — no restart needed.

## Guidance

- **Prefer structured tools first**: use toolpilot for file search/inspection, gitpilot for git operations. Fall back to shellpilot only when no structured tool covers the need.
- **Safety**: commands containing `/`, `\`, or `..` are always rejected regardless of the allowlist.
- **Audit**: use `audit_log` to review what was run, including denied attempts.
- **Allowlist check**: when unsure if a command is allowed, call `list_allowed` first.
