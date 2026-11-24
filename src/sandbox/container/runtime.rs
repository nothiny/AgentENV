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

#[derive(Clone, Debug)]
pub(super) struct OciRuntime {
    binary: String,
    root: PathBuf,
}

#[derive(Deserialize)]
struct ListedContainer {
    id: String,
}

impl OciRuntime {
    /// `root` is the runtime's state directory, private to this server.
    pub(super) fn new(binary: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            root: root.into(),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg("--root").arg(&self.root);
        command
    }

    /// Starts `id` from `bundle` in the foreground. The container's stdout
    /// and stderr are piped; the caller drains them.
    pub(super) fn run(&self, bundle: &Path, id: &str) -> Result<Child> {
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("create runtime root {}", self.root.display()))?;
        self.command()
            .arg("run")
            .arg("--bundle")
            .arg(bundle)
            .arg(id)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn {} run {id}", self.binary))
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
    fn parses_empty_and_populated_lists() {
        assert!(parse_list(b"null").unwrap().is_empty());
        assert!(parse_list(b"[]").unwrap().is_empty());
        assert_eq!(
            parse_list(br#"[{"id":"aenv-a","pid":1,"status":"running"},{"id":"b"}]"#).unwrap(),
            vec!["aenv-a".to_string(), "b".to_string()]
        );
    }
}
