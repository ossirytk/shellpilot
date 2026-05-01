//! Command allowlist — load, save, and validate.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct AllowlistFile {
    commands: Vec<String>,
}

/// Path to the allowlist config file.
pub fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("shellpilot")
        .join("allowlist.json")
}

/// Conservative default command set — no wrappers that can exec arbitrary binaries.
pub fn default_commands() -> Vec<String> {
    [
        "cat", "date", "echo", "grep", "head", "ls", "pwd", "tail", "wc", "which", "whoami",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Load the allowlist from `path`.
///
/// - Returns `Err` if the file exists but cannot be read or parsed (fail-closed).
/// - Returns the default list if the file does not yet exist.
pub fn load_from(path: &Path) -> io::Result<Vec<String>> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let parsed: AllowlistFile = serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(parsed.commands)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(default_commands()),
        Err(e) => Err(e),
    }
}

/// Save `commands` to `path`, creating parent directories as needed.
pub fn save_to(path: &Path, commands: &[String]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = AllowlistFile {
        commands: commands.to_vec(),
    };
    let content = serde_json::to_string_pretty(&data).map_err(io::Error::other)?;
    fs::write(path, content)
}

/// Load the allowlist from the default config path, bootstrapping it on first run.
pub fn load() -> io::Result<Vec<String>> {
    let path = config_path();
    let commands = load_from(&path)?;
    // First run: persist the defaults so the user can inspect/edit them.
    if !path.exists() {
        save_to(&path, &commands)?;
    }
    Ok(commands)
}

/// Return `true` if `command` is on the allowlist at `path`.
///
/// Any command containing a path separator or `..` is unconditionally rejected.
#[cfg_attr(not(test), allow(dead_code))]
pub fn is_allowed_in(command: &str, path: &Path) -> Result<bool, io::Error> {
    if contains_path_chars(command) {
        return Ok(false);
    }
    let commands = load_from(path)?;
    let set: HashSet<&str> = commands.iter().map(String::as_str).collect();
    Ok(set.contains(command))
}

/// Return `true` if `command` is on the default-path allowlist.
pub fn is_allowed(command: &str) -> Result<bool, io::Error> {
    if contains_path_chars(command) {
        return Ok(false);
    }
    let commands = load()?;
    let set: HashSet<&str> = commands.iter().map(String::as_str).collect();
    Ok(set.contains(command))
}

fn contains_path_chars(s: &str) -> bool {
    s.contains('/') || s.contains('\\') || s.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn defaults_include_safe_commands() {
        let defaults = default_commands();
        assert!(defaults.contains(&"echo".to_string()));
        assert!(defaults.contains(&"ls".to_string()));
        assert!(defaults.contains(&"cat".to_string()));
    }

    #[test]
    fn defaults_exclude_dangerous_wrappers() {
        let defaults = default_commands();
        assert!(
            !defaults.contains(&"find".to_string()),
            "find can exec arbitrary commands"
        );
        assert!(
            !defaults.contains(&"env".to_string()),
            "env can exec arbitrary commands"
        );
        assert!(!defaults.contains(&"rm".to_string()));
        assert!(!defaults.contains(&"sudo".to_string()));
    }

    #[test]
    fn path_separators_always_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        save_to(&path, &["ls".to_string()]).unwrap();
        assert!(!is_allowed_in("/bin/ls", &path).unwrap());
        assert!(!is_allowed_in("../ls", &path).unwrap());
        assert!(!is_allowed_in("bin\\ls", &path).unwrap());
        assert!(!is_allowed_in("a..b", &path).unwrap());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        let commands = vec![
            "echo".to_string(),
            "ls".to_string(),
            "custom_tool".to_string(),
        ];
        save_to(&path, &commands).unwrap();
        let loaded = load_from(&path).unwrap();
        assert_eq!(loaded, commands);
    }

    #[test]
    fn load_missing_file_returns_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let loaded = load_from(&path).unwrap();
        assert_eq!(loaded, default_commands());
    }

    #[test]
    fn load_malformed_file_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        fs::write(&path, "not valid json {{{{").unwrap();
        assert!(load_from(&path).is_err());
    }

    #[test]
    fn is_allowed_in_matches_saved_list() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        save_to(&path, &["echo".to_string(), "ls".to_string()]).unwrap();
        assert!(is_allowed_in("echo", &path).unwrap());
        assert!(is_allowed_in("ls", &path).unwrap());
        assert!(!is_allowed_in("rm", &path).unwrap());
        assert!(!is_allowed_in("grep", &path).unwrap());
    }
}
