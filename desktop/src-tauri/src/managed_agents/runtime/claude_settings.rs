use std::path::Path;

use crate::managed_agents::KnownAcpRuntime;

/// Merge Buzz's Claude project-scope defaults into `<nest>/.claude/settings.json`.
///
/// The project file overrides user settings without relocating Claude auth,
/// history, or other state. It is best effort: a failed write must never
/// prevent an agent from spawning because these are vendor-managed settings.
///
/// Claude Code 2.1.221 accepts windows from 100,000 to 1,000,000.
const AUTO_COMPACT_WINDOW_DEFAULT: u64 = 200_000;
fn write(workdir: &Path) -> Result<(), String> {
    debug_assert!((100_000..=1_000_000).contains(&AUTO_COMPACT_WINDOW_DEFAULT));
    let settings_dir = workdir.join(".claude");
    std::fs::create_dir_all(&settings_dir)
        .map_err(|error| format!("create {}: {error}", settings_dir.display()))?;
    let settings_path = settings_dir.join("settings.json");
    let mut settings = match std::fs::read(&settings_path) {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(serde_json::Value::Object(settings)) => settings,
            Ok(_) => {
                return Err(format!(
                    "{} is not a JSON object; leaving Claude project settings unchanged",
                    settings_path.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "parse {}: {error}; leaving Claude project settings unchanged",
                    settings_path.display()
                ));
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::Map::new(),
        Err(error) => return Err(format!("read {}: {error}", settings_path.display())),
    };

    // These defaults are inserted only when absent so a user may override
    // project settings without Buzz resetting their choice at every spawn.
    settings
        .entry("autoCompactWindow".to_string())
        .or_insert_with(|| serde_json::Value::from(AUTO_COMPACT_WINDOW_DEFAULT));
    settings
        .entry("alwaysThinkingEnabled".to_string())
        .or_insert(serde_json::Value::Bool(true));

    let payload = serde_json::to_vec_pretty(&serde_json::Value::Object(settings))
        .map_err(|error| format!("serialize {}: {error}", settings_path.display()))?;
    crate::managed_agents::storage::atomic_write_json(&settings_path, &payload)
}

/// Best-effort Claude project-settings persistence used by the spawn path.
pub(super) fn configure(runtime: Option<&KnownAcpRuntime>, workdir: Option<&Path>) {
    if runtime.is_none_or(|runtime| runtime.id != "claude") {
        return;
    }
    let Some(workdir) = workdir else {
        eprintln!("buzz-desktop: Claude project settings skipped: no agent working directory");
        return;
    };
    if let Err(error) = write(workdir) {
        eprintln!("buzz-desktop: Claude project settings not written: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_missing_file_with_defaults() {
        let temp = tempfile::tempdir().expect("temp dir");
        write(temp.path()).expect("write settings");

        let settings: serde_json::Value = serde_json::from_slice(
            &std::fs::read(temp.path().join(".claude/settings.json")).expect("read settings"),
        )
        .expect("parse settings");
        assert_eq!(settings["autoCompactWindow"], 200_000);
        assert_eq!(settings["alwaysThinkingEnabled"], true);
    }

    #[test]
    fn preserves_existing_settings() {
        let temp = tempfile::tempdir().expect("temp dir");
        let settings_dir = temp.path().join(".claude");
        std::fs::create_dir(&settings_dir).expect("create settings dir");
        std::fs::write(
            settings_dir.join("settings.json"),
            br#"{"model":"claude-sonnet","permissions":{"allow":["Read"]},"autoCompactWindow":500000,"alwaysThinkingEnabled":false}"#,
        )
        .expect("seed settings");

        write(temp.path()).expect("merge settings");

        let settings: serde_json::Value = serde_json::from_slice(
            &std::fs::read(settings_dir.join("settings.json")).expect("read settings"),
        )
        .expect("parse settings");
        assert_eq!(settings["model"], "claude-sonnet");
        assert_eq!(
            settings["permissions"]["allow"],
            serde_json::json!(["Read"])
        );
        assert_eq!(settings["autoCompactWindow"], 500_000);
        assert_eq!(settings["alwaysThinkingEnabled"], false);
    }

    #[test]
    fn rejects_invalid_existing_json_without_overwriting() {
        let temp = tempfile::tempdir().expect("temp dir");
        let settings_dir = temp.path().join(".claude");
        std::fs::create_dir(&settings_dir).expect("create settings dir");
        let settings_path = settings_dir.join("settings.json");
        std::fs::write(&settings_path, b"not json").expect("seed invalid settings");

        assert!(write(temp.path()).is_err());
        assert_eq!(
            std::fs::read(&settings_path).expect("read settings"),
            b"not json"
        );
    }

    #[test]
    fn only_applies_to_claude_runtime() {
        let temp = tempfile::tempdir().expect("temp dir");
        configure(
            crate::managed_agents::known_acp_runtime("codex-acp"),
            Some(temp.path()),
        );
        assert!(
            !temp.path().join(".claude/settings.json").exists(),
            "Codex must not receive Claude settings"
        );
    }
}
