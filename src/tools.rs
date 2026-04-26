//! Tool definitions and stub handlers for shellpilot.

use serde_json::{Value, json};

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

/// Dispatch a tools/call request to the appropriate handler.
pub fn dispatch(params: &Value) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "run" => handle_run(args),
        "list_allowed" => handle_list_allowed(),
        "audit_log" => handle_audit_log(args),
        _ => json!({"error": {"code": "UnknownTool", "message": "Tool not found"}}),
    }
}

fn handle_run(_args: Value) -> Value {
    json!({"error": "not yet implemented"})
}

fn handle_list_allowed() -> Value {
    json!({"error": "not yet implemented"})
}

fn handle_audit_log(_args: Value) -> Value {
    json!({"error": "not yet implemented"})
}
