//! Append-only audit log — one JSON line per invocation.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditEntry {
    /// ISO 8601 UTC timestamp.
    pub ts: String,
    pub command: String,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// `None` when the process was killed or never started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Outcome tag: "ok", "denied", "timeout", "error".
    pub outcome: String,
    pub duration_ms: u128,
}

/// Path to the audit log file.
pub fn log_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("shellpilot")
        .join("audit.log")
}

/// Current time as an ISO 8601 UTC string.
pub fn now_iso8601() -> String {
    Utc::now().to_rfc3339()
}

/// Append `entry` to `path`, creating parent directories as needed.
pub fn append_to(path: &Path, entry: &AuditEntry) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(entry).map_err(io::Error::other)?;
    writeln!(file, "{line}")
}

/// Append `entry` to the default log path.
pub fn append(entry: &AuditEntry) -> io::Result<()> {
    append_to(&log_path(), entry)
}

/// Return the last `limit` entries from `path`.
///
/// Lines are streamed one at a time via `BufReader` so the entire log file is
/// never loaded into memory at once. Only the last `limit` parsed entries are
/// retained in memory, regardless of the total log size.
pub fn read_recent_from(path: &Path, limit: usize) -> io::Result<Vec<AuditEntry>> {
    use std::collections::VecDeque;
    use std::io::BufRead as _;

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let reader = io::BufReader::new(file);
    let mut ring: VecDeque<AuditEntry> = VecDeque::with_capacity(limit.saturating_add(1));
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
            if limit > 0 && ring.len() >= limit {
                ring.pop_front();
            }
            ring.push_back(entry);
        }
    }
    Ok(ring.into_iter().collect())
}

/// Return the last `limit` entries from the default log path.
pub fn read_recent(limit: usize) -> io::Result<Vec<AuditEntry>> {
    read_recent_from(&log_path(), limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample(command: &str, outcome: &str) -> AuditEntry {
        AuditEntry {
            ts: "2024-01-01T00:00:00Z".to_string(),
            command: command.to_string(),
            args: vec!["-l".to_string()],
            cwd: Some("/tmp".to_string()),
            exit_code: if outcome == "ok" { Some(0) } else { None },
            outcome: outcome.to_string(),
            duration_ms: 42,
        }
    }

    #[test]
    fn read_missing_log_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        assert!(read_recent_from(&path, 10).unwrap().is_empty());
    }

    #[test]
    fn append_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        append_to(&path, &sample("ls", "ok")).unwrap();
        let entries = read_recent_from(&path, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command, "ls");
        assert_eq!(entries[0].exit_code, Some(0));
        assert_eq!(entries[0].outcome, "ok");
    }

    #[test]
    fn read_recent_respects_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        for i in 0u8..10 {
            let mut e = sample("echo", "ok");
            e.args = vec![i.to_string()];
            append_to(&path, &e).unwrap();
        }
        let entries = read_recent_from(&path, 3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].args[0], "9");
    }

    #[test]
    fn multiple_appends_preserve_order() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        for cmd in ["ls", "echo", "pwd"] {
            append_to(&path, &sample(cmd, "ok")).unwrap();
        }
        let entries = read_recent_from(&path, 100).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].command, "ls");
        assert_eq!(entries[1].command, "echo");
        assert_eq!(entries[2].command, "pwd");
    }

    #[test]
    fn denied_entries_are_stored() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        append_to(&path, &sample("rm", "denied")).unwrap();
        let entries = read_recent_from(&path, 10).unwrap();
        assert_eq!(entries[0].outcome, "denied");
        assert_eq!(entries[0].exit_code, None);
    }
}
