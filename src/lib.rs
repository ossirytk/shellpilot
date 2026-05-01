//! shellpilot — safe subprocess runner MCP server.

mod allowlist;
mod audit;
mod tools;

use std::io;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

async fn handle_request(request: RpcRequest) -> Option<RpcResponse> {
    // Notifications (no id) must not receive a response.
    let id = request.id?;

    let result = match request.method.as_str() {
        "initialize" => Some(json!({
            "protocolVersion": request.params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "shellpilot", "version": "0.1.0"},
            "instructions": (
                "shellpilot is a safe subprocess runner — use it only for commands not covered \
                 by a structured MCP tool. Prefer toolpilot for file search and inspection \
                 (fs_glob, fs_tree, text_search), and gitpilot for all git operations. \
                 Before calling 'run', check 'list_allowed' to confirm the command is permitted. \
                 Every invocation is recorded in the audit log regardless of outcome."
            )
        })),
        "tools/list" => Some(tools::tool_definitions()),
        "tools/call" => {
            let payload = tools::dispatch(&request.params).await;
            let text = serde_json::to_string(&payload).unwrap_or_default();
            Some(json!({
                "content": [{"type": "text", "text": text}],
                "structuredContent": payload
            }))
        }
        "ping" => Some(json!({})),
        _ => None,
    };

    if let Some(result) = result {
        Some(RpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        })
    } else {
        Some(RpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(json!({"code": -32601, "message": "Method not found"})),
        })
    }
}

pub async fn run() -> io::Result<()> {
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut writer = tokio::io::stdout();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let value: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                let resp = RpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(json!({"code": -32700, "message": "Parse error"})),
                };
                let mut out = serde_json::to_vec(&resp).unwrap_or_default();
                out.push(b'\n');
                writer.write_all(&out).await?;
                writer.flush().await?;
                continue;
            }
        };

        let request_id = value.get("id").cloned().unwrap_or(Value::Null);
        let request: RpcRequest = match serde_json::from_value(value) {
            Ok(r) => r,
            Err(_) => {
                let resp = RpcResponse {
                    jsonrpc: "2.0",
                    id: request_id,
                    result: None,
                    error: Some(json!({"code": -32600, "message": "Invalid Request"})),
                };
                let mut out = serde_json::to_vec(&resp).unwrap_or_default();
                out.push(b'\n');
                writer.write_all(&out).await?;
                writer.flush().await?;
                continue;
            }
        };

        if let Some(response) = handle_request(request).await {
            let mut out = serde_json::to_vec(&response).unwrap_or_default();
            out.push(b'\n');
            writer.write_all(&out).await?;
            writer.flush().await?;
        }
    }
    Ok(())
}
