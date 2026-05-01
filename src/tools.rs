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
                "description": "Execute an allowlisted shell command safely.",
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

    let cmd_args: Vec<String> = args
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let cwd: Option<String> = args.get("cwd").and_then(Value::as_str).map(String::from);

    // Check allowlist — audit denied attempts.
    let allowed = match allowlist::is_allowed(&command) {
        Ok(v) => v,
        Err(e) => {
            let _ = audit::append(&audit::AuditEntry {
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
        let _ = audit::append(&audit::AuditEntry {
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
    let mut cmd = tokio::process::Command::new(&command);
    cmd.args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(ref dir) = cwd {
        cmd.current_dir(dir);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = audit::append(&audit::AuditEntry {
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
            let _ = audit::append(&audit::AuditEntry {
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
            stdout_task.abort();
            stderr_task.abort();
            let _ = audit::append(&audit::AuditEntry {
                ts,
                command,
                args: cmd_args,
                cwd,
                exit_code: None,
                outcome: "error".to_string(),
                duration_ms: start.elapsed().as_millis(),
            });
            return json!({"error": {"code": "WaitError", "message": e.to_string()}});
        }
        Ok(Ok(status)) => (status.code(), if status.success() { "ok" } else { "error" }),
    };

    let stdout_bytes = stdout_task.await.unwrap_or_default();
    let stderr_bytes = stderr_task.await.unwrap_or_default();
    let duration_ms = start.elapsed().as_millis();

    let _ = audit::append(&audit::AuditEntry {
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

/// Read up to `MAX_OUTPUT_BYTES` from `reader` into a `Vec<u8>`.
async fn read_capped(reader: impl tokio::io::AsyncRead + Unpin) -> Vec<u8> {
    let mut buf = Vec::new();
    // Read one byte beyond the cap so we know whether truncation occurred.
    let _ = reader
        .take((MAX_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .await;
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
    match allowlist::load() {
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
        let result = handle_list_allowed();
        let commands = result["commands"].as_array();
        assert!(commands.is_some(), "should have a 'commands' array");
        assert!(!commands.unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_echo_produces_output() {
        // "echo" is in the default allowlist.
        let result = handle_run(json!({"command": "echo", "args": ["hello"]})).await;
        // Only check output structure; skip if echo is not on this system's allowlist.
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
