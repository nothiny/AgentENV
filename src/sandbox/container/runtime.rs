//! A thin wrapper over an OCI runtime CLI (runc, crun or runsc).
//!
//! Containers run in the foreground: `run` stays the parent of the container
//! init and exits with it, so the server reaps the runtime process like any
//! other child and no container process is ever orphaned.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::process::{Child, Command};

/// How long one `state` query may take.
const STATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(super) struct OciRuntime {
    binary: String,
    root: PathBuf,
}

#[derive(Deserialize)]
struct ListedContainer {
    id: String,
}

#[derive(Deserialize)]
struct ContainerState {
    status: String,
}

impl OciRuntime {
    /// `root` is the runtime's state directory, private to this server.
    pub(super) fn new(binary: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            root: root.into(),
        }
    }

    /// The runtime's command name, as configured.
    pub(super) fn binary(&self) -> &str {
        &self.binary
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg("--root").arg(&self.root);
        command
    }

    /// Starts `id` from `bundle` in the foreground. The container's stdout
    /// and stderr are piped; the caller drains them.
    pub(super) fn run(&self, bundle: &Path, id: &str) -> Result<Child> {
        let mut command = self.command();
        command.arg("run").arg("--bundle").arg(bundle).arg(id);
        self.spawn_foreground(command, "run", id)
    }

    /// Restores `id` from the CRIU images in `image_dir` into `bundle`, in the
    /// foreground like [`run`][Self::run]: the restored processes get the
    /// same piped stdio a started container has, so a later dump finds no
    /// file it cannot follow. CRIU's log goes to `work_dir/restore.log`.
    /// The bundle names the CRIU options a restore needs (see
    /// `bundle::CRIU_CONFIG`).
    pub(super) fn restore(
        &self,
        bundle: &Path,
        id: &str,
        image_dir: &Path,
        work_dir: &Path,
    ) -> Result<Child> {
        std::fs::create_dir_all(work_dir)
            .with_context(|| format!("create {}", work_dir.display()))?;
        let mut command = self.command();
        command
            .arg("restore")
            .arg("--tcp-established")
            .arg("--file-locks")
            .arg("--image-path")
            .arg(image_dir)
            .arg("--work-path")
            .arg(work_dir)
            .arg("--bundle")
            .arg(bundle)
            .arg(id);
        self.spawn_foreground(command, "restore", id)
    }

    fn spawn_foreground(&self, mut command: Command, verb: &str, id: &str) -> Result<Child> {
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("create runtime root {}", self.root.display()))?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn {} {verb} {id}", self.binary))
    }

    async fn checked(&self, args: &[&str]) -> Result<()> {
        let output = self
            .command()
            .args(args)
            .output()
            .await
            .with_context(|| format!("spawn {} {}", self.binary, args.join(" ")))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The container is already gone: nothing left to do.
        if stderr.contains("does not exist") || stderr.contains("not found") {
            return Ok(());
        }
        bail!("{} {}: {}", self.binary, args.join(" "), stderr.trim())
    }

    /// Sends `signal` to every process of `id`. A missing or stopped
    /// container is success.
    pub(super) async fn kill(&self, id: &str, signal: &str) -> Result<()> {
        match self.checked(&["kill", "--all", id, signal]).await {
            Err(err) if err.to_string().contains("not running") => Ok(()),
            other => other,
        }
    }

    /// Removes `id` whatever its state. A missing container is success.
    pub(super) async fn delete(&self, id: &str) -> Result<()> {
        self.checked(&["delete", "--force", id]).await
    }

    /// The runtime's status for `id` (`creating`, `running`, `paused`, ...),
    /// or `None` while the runtime does not know it.
    /// The query is killed if the caller stops waiting, and gives up after
    /// [`STATE_TIMEOUT`].
    pub(super) async fn status(&self, id: &str) -> Result<Option<String>> {
        let mut command = self.command();
        command.args(["state", id]).kill_on_drop(true);
        let output = tokio::time::timeout(STATE_TIMEOUT, command.output())
            .await
            .with_context(|| format!("{} state {id} did not answer", self.binary))?
            .with_context(|| format!("spawn {} state {id}", self.binary))?;
        if !output.status.success() {
            return Ok(None);
        }
        let state: ContainerState =
            serde_json::from_slice(&output.stdout).context("parse runtime container state")?;
        Ok(Some(state.status))
    }

    /// Freezes every process of `id` (cgroup freeze).
    pub(super) async fn pause(&self, id: &str) -> Result<()> {
        self.strict(&["pause", id]).await
    }

    /// Thaws `id`. A container that is not paused is success.
    pub(super) async fn resume(&self, id: &str) -> Result<()> {
        match self.strict(&["resume", id]).await {
            Err(err) if err.to_string().contains("not paused") => Ok(()),
            other => other,
        }
    }

    /// Dumps the processes of `id` with CRIU into `image_dir`, leaving them
    /// as they were: a frozen container stays frozen. Established TCP
    /// connections are saved so the dump does not refuse them; a restore
    /// closes them. CRIU's log goes to `work_dir/dump.log`, and its errors
    /// into the returned error.
    pub(super) async fn checkpoint(
        &self,
        id: &str,
        image_dir: &Path,
        work_dir: &Path,
    ) -> Result<()> {
        std::fs::create_dir_all(image_dir)
            .with_context(|| format!("create {}", image_dir.display()))?;
        std::fs::create_dir_all(work_dir)
            .with_context(|| format!("create {}", work_dir.display()))?;
        let image = image_dir.to_string_lossy();
        let work = work_dir.to_string_lossy();
        let result = self
            .strict(&[
                "checkpoint",
                "--leave-running",
                "--tcp-established",
                "--file-locks",
                "--image-path",
                &image,
                "--work-path",
                &work,
                id,
            ])
            .await;
        result.map_err(|err| {
            let errors = criu_errors(&work_dir.join("dump.log"));
            if errors.is_empty() {
                err
            } else {
                err.context(format!("criu: {errors}"))
            }
        })
    }

    /// Runs a command whose failure is an error even if the container is gone.
    async fn strict(&self, args: &[&str]) -> Result<()> {
        let output = self
            .command()
            .args(args)
            .output()
            .await
            .with_context(|| format!("spawn {} {}", self.binary, args.join(" ")))?;
        if output.status.success() {
            return Ok(());
        }
        bail!(
            "{} {}: {}",
            self.binary,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }

    /// IDs of the containers this runtime root knows about.
    pub(super) async fn list(&self) -> Result<Vec<String>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let output = self
            .command()
            .args(["list", "--format", "json"])
            .output()
            .await
            .with_context(|| format!("spawn {} list", self.binary))?;
        if !output.status.success() {
            bail!(
                "{} list: {}",
                self.binary,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        parse_list(&output.stdout)
    }
}

/// Whether two runtime commands name the same executable: equal names, or
/// paths (as given, or found on `PATH`) that resolve to one file.
pub(super) fn same_executable(a: &str, b: &str) -> bool {
    a == b
        || match (resolve_executable(a), resolve_executable(b)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
}

fn resolve_executable(command: &str) -> Option<PathBuf> {
    let found = if command.contains('/') {
        PathBuf::from(command)
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|dir| dir.join(command))
            .find(|path| path.is_file())?
    };
    std::fs::canonicalize(found).ok()
}

/// The `Error` lines of a CRIU log, joined; empty if there are none.
pub(super) fn criu_errors(log: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(log) else {
        return String::new();
    };
    parse_criu_errors(&text)
}

fn parse_criu_errors(text: &str) -> String {
    text.lines()
        .filter_map(|line| line.split_once("Error ").map(|(_, rest)| rest.trim()))
        .take(3)
        .collect::<Vec<_>>()
        .join("; ")
}

fn parse_list(stdout: &[u8]) -> Result<Vec<String>> {
    // runc prints `null` when there are no containers.
    let listed: Option<Vec<ListedContainer>> =
        serde_json::from_slice(stdout).context("parse runtime container list")?;
    Ok(listed
        .unwrap_or_default()
        .into_iter()
        .map(|container| container.id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runtime_named_by_path_is_the_same_runtime() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let binary = temp.path().join("runc");
        std::fs::write(&binary, b"")?;
        let link = temp.path().join("runc-link");
        std::os::unix::fs::symlink(&binary, &link)?;
        let (binary, link) = (binary.to_string_lossy(), link.to_string_lossy());
        assert!(same_executable("runc", "runc"));
        assert!(same_executable(&binary, &link));
        assert!(!same_executable(&binary, "/nonexistent/runc"));
        assert!(!same_executable("runc", "crun") || resolve_executable("runc").is_none());
        Ok(())
    }

    #[test]
    fn picks_the_error_lines_of_a_criu_log() {
        let log = "(00.24) 4: fdinfo\n\
                   (00.24) Error (criu/sk-inet.c:130): inet: Unsupported proto 262\n\
                   (00.24) ----\n\
                   (00.24) Error (criu/cr-dump.c:1681): Dump files failed with -1\n";
        assert_eq!(
            parse_criu_errors(log),
            "(criu/sk-inet.c:130): inet: Unsupported proto 262; \
             (criu/cr-dump.c:1681): Dump files failed with -1"
        );
        assert_eq!(parse_criu_errors("(00.1) fine\n"), "");
    }

    #[test]
    fn parses_empty_and_populated_lists() {
        assert!(parse_list(b"null").unwrap().is_empty());
        assert!(parse_list(b"[]").unwrap().is_empty());
        assert_eq!(
            parse_list(br#"[{"id":"aenv-a","pid":1,"status":"running"},{"id":"b"}]"#).unwrap(),
            vec!["aenv-a".to_string(), "b".to_string()]
        );
    }
}
