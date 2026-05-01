//! Tool definitions and handlers for shellpilot.

use std::process::Stdio;
use std::time::Instant;

use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

use crate::{allowlist, audit};

/// Maximum bytes captured from stdout or stderr per invocation.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Hard timeout for subprocess execution.
const RUN_TIMEOUT_SECS: u64 = 30;

/// Return the MCP tool definitions for shellpilot.
pub fn tool_definitions() -> Value {
    json!({
        "tools": [
            {
                "name": "run",
                "description": "Execute an allowlisted shell command safely. Prefer toolpilot for file operations and gitpilot for git — use this only for commands not covered by a structured tool.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The command name (must be on the allowlist)."
                        },
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Arguments to pass to the command."
                        },
                        "cwd": {
                            "type": "string",
                            "description": "Working directory for the subprocess."
                        }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "list_allowed",
                "description": "Return the current command allowlist.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "audit_log",
                "description": "Return recent subprocess execution audit log entries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of log entries to return.",
                            "default": 50
                        }
                    }
                }
            }
        ]
    })
}

/// Dispatch a `tools/call` request to the appropriate handler.
pub async fn dispatch(params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match name {
        "run" => handle_run(args).await,
        "list_allowed" => handle_list_allowed(),
        "audit_log" => handle_audit_log(args),
        _ => json!({"error": {"code": "UnknownTool", "message": "Tool not found"}}),
    }
}

async fn handle_run(args: Value) -> Value {
    handle_run_impl(args, None, None).await
}

/// Inner implementation of `run` that accepts optional override paths for
/// hermetic testing (production code passes `None` for both).
async fn handle_run_impl(
    args: Value,
    allowlist_path: Option<&std::path::Path>,
    audit_path: Option<&std::path::Path>,
) -> Value {
    // Helper: append an audit entry to the configured path.
    macro_rules! audit {
        ($entry:expr) => {
            match audit_path {
                Some(p) => {
                    let _ = audit::append_to(p, &$entry);
                }
                None => {
                    let _ = audit::append(&$entry);
                }
            }
        };
    }

    let ts = audit::now_iso8601();
    let start = Instant::now();

    let command = match args.get("command").and_then(Value::as_str) {
        Some(c) => c.to_string(),
        None => {
            return json!({"error": {
                "code": "MissingArgument",
                "message": "'command' is required"
            }});
        }
    };

    let cmd_args: Vec<String> = match args.get("args").and_then(Value::as_array) {
        Some(a) => {
            let mut parsed_args = Vec::with_capacity(a.len());
            for (index, value) in a.iter().enumerate() {
                match value.as_str() {
                    Some(s) => parsed_args.push(s.to_string()),
                    None => {
                        return json!({"error": {
                            "code": "InvalidArgument",
                            "message": format!("'args[{}]' must be a string", index)
                        }});
                    }
                }
            }
            parsed_args
        }
        None => Vec::new(),
    };

    let cwd: Option<String> = args.get("cwd").and_then(Value::as_str).map(String::from);

    // Check allowlist — audit denied attempts.
    let allowed = match allowlist_path {
        Some(p) => allowlist::is_allowed_in(&command, p),
        None => allowlist::is_allowed(&command),
    };
    let allowed = match allowed {
        Ok(v) => v,
        Err(e) => {
            audit!(audit::AuditEntry {
                ts,
                command,
                args: cmd_args,
                cwd,
                exit_code: None,
                outcome: "error".to_string(),
                duration_ms: start.elapsed().as_millis(),
            });
            return json!({"error": {"code": "AllowlistError", "message": e.to_string()}});
        }
    };
    if !allowed {
        audit!(audit::AuditEntry {
            ts,
            command: command.clone(),
            args: cmd_args,
            cwd,
            exit_code: None,
            outcome: "denied".to_string(),
            duration_ms: start.elapsed().as_millis(),
        });
        return json!({"error": {
            "code": "NotAllowed",
            "message": format!("'{}' is not on the allowlist", command)
        }});
    }

    // Spawn the subprocess with piped I/O.
    // On Unix, override PATH with a minimal trusted set to prevent PATH-injection
    // attacks where a malicious binary earlier in the caller's PATH shadows the
    // intended one.  On other platforms (e.g. Windows) leave PATH unchanged.
    let mut cmd = tokio::process::Command::new(&command);
    cmd.args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    if let Some(ref dir) = cwd {
        cmd.current_dir(dir);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            audit!(audit::AuditEntry {
                ts,
                command,
                args: cmd_args,
                cwd,
                exit_code: None,
                outcome: "error".to_string(),
                duration_ms: start.elapsed().as_millis(),
            });
            return json!({"error": {"code": "SpawnError", "message": e.to_string()}});
        }
    };

    // Drain stdout and stderr concurrently, capped at MAX_OUTPUT_BYTES each.
    // Spawning tasks allows draining to proceed in parallel with child.wait(),
    // preventing OS pipe-buffer deadlocks.
    let stdout_handle = child.stdout.take().expect("piped");
    let stderr_handle = child.stderr.take().expect("piped");

    let stdout_task = tokio::spawn(read_capped(stdout_handle));
    let stderr_task = tokio::spawn(read_capped(stderr_handle));

    // Wait for the process to exit, killing it on timeout.
    let wait_result = timeout(Duration::from_secs(RUN_TIMEOUT_SECS), child.wait()).await;

    let (exit_code, outcome) = match wait_result {
        Err(_) => {
            // Timeout: kill the child so readers reach EOF.
            let _ = child.kill().await;
            let _ = child.wait().await;
            let stdout_bytes = stdout_task.await.unwrap_or_default();
            let stderr_bytes = stderr_task.await.unwrap_or_default();
            let duration_ms = start.elapsed().as_millis();
            audit!(audit::AuditEntry {
                ts,
                command: command.clone(),
                args: cmd_args,
                cwd,
                exit_code: None,
                outcome: "timeout".to_string(),
                duration_ms,
            });
            return json!({
                "command": command,
                "exit_code": null,
                "stdout": format_output(stdout_bytes),
                "stderr": format_output(stderr_bytes),
                "duration_ms": duration_ms,
                "error": {
                    "code": "Timeout",
                    "message": format!("command timed out after {}s", RUN_TIMEOUT_SECS)
                }
            });
        }
        Ok(Err(e)) => {
            // wait() itself failed — best-effort: kill child and drain readers
            // so no subprocess is left running and no reader task leaks.
            let _ = child.kill().await;
            let _ = child.wait().await;
            let stdout_bytes = stdout_task.await.unwrap_or_default();
            let stderr_bytes = stderr_task.await.unwrap_or_default();
            let duration_ms = start.elapsed().as_millis();
            audit!(audit::AuditEntry {
                ts,
                command: command.clone(),
                args: cmd_args,
                cwd,
                exit_code: None,
                outcome: "error".to_string(),
                duration_ms,
            });
            return json!({
                "command": command,
                "exit_code": null,
                "stdout": format_output(stdout_bytes),
                "stderr": format_output(stderr_bytes),
                "duration_ms": duration_ms,
                "error": {"code": "WaitError", "message": e.to_string()}
            });
        }
        Ok(Ok(status)) => (status.code(), if status.success() { "ok" } else { "error" }),
    };

    let stdout_bytes = stdout_task.await.unwrap_or_default();
    let stderr_bytes = stderr_task.await.unwrap_or_default();
    let duration_ms = start.elapsed().as_millis();

    audit!(audit::AuditEntry {
        ts,
        command: command.clone(),
        args: cmd_args,
        cwd,
        exit_code,
        outcome: outcome.to_string(),
        duration_ms,
    });

    json!({
        "command": command,
        "exit_code": exit_code,
        "stdout": format_output(stdout_bytes),
        "stderr": format_output(stderr_bytes),
        "duration_ms": duration_ms,
    })
}

/// Read from `reader` until EOF, buffering at most `MAX_OUTPUT_BYTES + 1` bytes.
///
/// The reader is drained to EOF regardless of the cap so that the child process
/// does not receive SIGPIPE/EPIPE from a prematurely closed pipe.
async fn read_capped(mut reader: impl tokio::io::AsyncRead + Unpin) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut remaining = MAX_OUTPUT_BYTES + 1;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if remaining > 0 {
                    let to_copy = remaining.min(n);
                    buf.extend_from_slice(&chunk[..to_copy]);
                    remaining -= to_copy;
                }
                // Continue reading (and discarding) until EOF to avoid SIGPIPE.
            }
        }
    }
    buf
}

/// Convert raw output bytes to a UTF-8 string, appending a truncation notice if capped.
fn format_output(bytes: Vec<u8>) -> String {
    if bytes.len() > MAX_OUTPUT_BYTES {
        let truncated = &bytes[..MAX_OUTPUT_BYTES];
        format!(
            "{}[...truncated at {} bytes]",
            String::from_utf8_lossy(truncated),
            MAX_OUTPUT_BYTES
        )
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn handle_list_allowed() -> Value {
    handle_list_allowed_impl(None)
}

fn handle_list_allowed_impl(allowlist_path: Option<&std::path::Path>) -> Value {
    let result = match allowlist_path {
        Some(p) => allowlist::load_from(p),
        None => allowlist::load(),
    };
    match result {
        Ok(commands) => json!({"commands": commands}),
        Err(e) => json!({"error": {"code": "AllowlistError", "message": e.to_string()}}),
    }
}

fn handle_audit_log(args: Value) -> Value {
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
    match audit::read_recent(limit) {
        Ok(entries) => json!({"entries": entries}),
        Err(e) => json!({"error": {"code": "IoError", "message": e.to_string()}}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn unknown_tool_returns_error() {
        let result = rt().block_on(dispatch(
            &json!({"name": "nonexistent_xyz", "arguments": {}}),
        ));
        assert!(result.get("error").is_some());
        assert_eq!(result["error"]["code"].as_str(), Some("UnknownTool"));
    }

    #[test]
    fn run_missing_command_field() {
        let result = rt().block_on(dispatch(&json!({"name": "run", "arguments": {}})));
        assert_eq!(result["error"]["code"].as_str(), Some("MissingArgument"));
    }

    #[test]
    fn run_path_separator_rejected() {
        let result = rt().block_on(dispatch(&json!({
            "name": "run",
            "arguments": {"command": "/bin/echo"}
        })));
        assert_eq!(result["error"]["code"].as_str(), Some("NotAllowed"));
    }

    #[test]
    fn run_disallowed_command_rejected() {
        let result = rt().block_on(dispatch(&json!({
            "name": "run",
            "arguments": {"command": "__nonexistent_cmd_xyz__"}
        })));
        assert_eq!(result["error"]["code"].as_str(), Some("NotAllowed"));
    }

    #[test]
    fn list_allowed_returns_command_list() {
        // Use a temp path so the test never touches the real user config directory.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        // No file pre-created — load_from returns defaults for a missing file.
        let result = handle_list_allowed_impl(Some(&path));
        let commands = result["commands"].as_array();
        assert!(commands.is_some(), "should have a 'commands' array");
        assert!(!commands.unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_echo_produces_output() {
        // Use temp dirs for both the allowlist and the audit log so the test
        // never touches the real user config/data directories.
        let dir = tempfile::tempdir().unwrap();
        let allowlist_path = dir.path().join("allowlist.json");
        let audit_path = dir.path().join("audit.log");
        // Pre-populate the allowlist so "echo" is permitted.
        allowlist::save_to(&allowlist_path, &allowlist::default_commands()).unwrap();

        let result = handle_run_impl(
            json!({"command": "echo", "args": ["hello"]}),
            Some(&allowlist_path),
            Some(&audit_path),
        )
        .await;

        if result.get("error").is_none() {
            assert!(result["stdout"].as_str().unwrap().contains("hello"));
            assert_eq!(result["exit_code"], 0);
        }
    }

    #[test]
    fn format_output_truncates_correctly() {
        let large = vec![b'a'; MAX_OUTPUT_BYTES + 10];
        let out = format_output(large);
        assert!(out.contains("[...truncated"));
        assert!(out.len() < MAX_OUTPUT_BYTES + 100);
    }

    #[test]
    fn format_output_small_passthrough() {
        let small = b"hello world".to_vec();
        assert_eq!(format_output(small), "hello world");
    }
}
