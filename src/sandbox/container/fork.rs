//! Full fork: one CRIU dump, restored into any number of children.
//!
//! [`ContainerSandbox::capture_for_fork`] freezes the source, dumps its
//! processes and seals its writable volumes and rootfs in that one frozen
//! window, then lets it run again. Volumes are sealed into their own
//! directories, so the fork's caller clones each child's volumes from exactly
//! what this capture sealed, after the capture and before any child starts.
//!
//! Each child is a new sandbox (own ID, rootfs upper, volumes, network slot,
//! cgroup) that `runc restore`s the shared dump, the way a resume restores a
//! paused one. Restores only read the dump and write their logs into their
//! own work directories, so children can restore it concurrently or one after
//! another; the dump is removed when the capture is dropped. Each child holds
//! its own references to the sealed rootfs layers.
//!
//! A restored envd still holds the source's access token. A child of a
//! secure sandbox therefore names its own token's hash in its auth directory
//! before restoring (see [`super::bundle::ACCESS_TOKEN_HASH`]), and the
//! normal `/init` with that token switches envd over. The child is routed
//! only after that succeeds.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use tracing::{info, warn};

use super::layers::LayerRefs;
use super::runtime::OciRuntime;
use super::{ContainerPaths, ContainerSandbox, Restore};
use crate::sandbox::backend::{
    SandboxBackend, SandboxForkCapture, SandboxForkResult, SandboxForkSpec, UnstoppedForkChild,
};
use crate::sandbox::{
    CustomExtensionParams, FreshSandboxBuildSpec, SandboxLaunchConfig, SandboxNetworkPolicy,
};
use crate::types::ExtraDrive;

/// The tools image patch that lets a restored envd take a new access token.
pub(super) const ACCESS_TOKEN_PATCH: &str = "0001-envd-access-token-hash-file";

/// Children restored from one capture at a time. Each restore reads the
/// whole dump and allocates its memory, so an unbounded batch of 100 would
/// mostly contend.
const RESTORE_CONCURRENCY: usize = 8;

/// A capture's own directory, removed when the capture is dropped.
#[derive(Debug)]
pub(super) struct CaptureDir(PathBuf);

impl CaptureDir {
    pub(super) fn create(base: &Path) -> Result<Self> {
        let dir = base.join(uuid::Uuid::now_v7().simple().to_string());
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create fork capture directory {}", dir.display()))?;
        Ok(Self(dir))
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for CaptureDir {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => warn!(
                capture = %self.0.display(),
                error = %err,
                "failed to remove fork capture"
            ),
        }
    }
}

/// A drive of the source as its children attach it.
#[derive(Clone, Debug)]
pub(super) struct CapturedDrive {
    /// The source's drive, sized as it was dumped.
    pub drive: ExtraDrive,
    /// A volume: each child attaches its own volume at the same path.
    pub per_child: bool,
}

/// What every child of one full fork restores from.
pub(super) struct ContainerForkCapture {
    /// References to the sealed rootfs layers, held until the capture goes.
    pub layers: std::sync::Mutex<LayerRefs>,
    pub dir: CaptureDir,
    pub criu_dir: PathBuf,
    pub rootfs_image_config: PathBuf,
    pub rootfs_virtual_size: Option<u64>,
    pub tools_image_config: PathBuf,
    pub envd_port: u16,
    pub auth_mount: bool,
    pub drives: Vec<CapturedDrive>,
    pub build_spec: FreshSandboxBuildSpec,
    pub snapshot_id: String,
    pub env_vars: Option<std::collections::HashMap<String, String>>,
    pub network: Option<SandboxNetworkPolicy>,
    pub custom_extension_params: Option<CustomExtensionParams>,
    pub runtime: OciRuntime,
    pub paths: ContainerPaths,
}

impl Drop for ContainerForkCapture {
    fn drop(&mut self) {
        // Children hold their own references; this drops the capture's.
        self.layers.lock().unwrap().release();
        info!(capture = %self.dir.path().display(), "fork capture released");
    }
}

impl ContainerForkCapture {
    /// The drives a child attaches: the source's, in the source's order (so
    /// the restored mounts match the dumped ones), each volume replaced by
    /// the child's own volume at the same path.
    fn child_drives(&self, spec: &SandboxForkSpec) -> Result<Vec<ExtraDrive>> {
        self.drives
            .iter()
            .map(|captured| {
                if !captured.per_child {
                    return Ok(captured.drive.clone());
                }
                let mount_path = captured.drive.mount_path();
                let own = spec
                    .extra_drives
                    .iter()
                    .find(|drive| drive.mount_path() == mount_path)
                    .ok_or_else(|| {
                        anyhow!(
                            "fork child has no volume for {}, which the source mounts",
                            mount_path.display()
                        )
                    })?;
                match captured.drive.virtual_size() {
                    Some(size) => own.try_with_virtual_size(size),
                    None => Ok(own.clone()),
                }
            })
            .collect()
    }

    /// A sandbox that restores this capture as the child `spec` describes.
    fn child(&self, spec: &SandboxForkSpec) -> Result<ContainerSandbox> {
        if spec.envd_access_token.is_some() && !self.auth_mount {
            anyhow::bail!(
                "the source container was started before fork children could take \
                 their own access token; recreate it to fork it"
            );
        }
        let build_spec = FreshSandboxBuildSpec {
            image_config_path: self.rootfs_image_config.clone(),
            extra_drives: self.child_drives(spec)?,
            ..self.build_spec.clone()
        };
        let launch = SandboxLaunchConfig {
            sandbox_id: spec.sandbox_id,
            snapshot_id: self.snapshot_id.clone(),
            env_vars: self.env_vars.clone(),
            network: self.network.clone(),
            custom_extension_params: self.custom_extension_params.clone(),
            envd_access_token: spec.envd_access_token.clone(),
            ..Default::default()
        };
        let layers = self.layers.lock().unwrap().inherit();
        let mut child = ContainerSandbox::new(
            build_spec,
            launch,
            self.runtime.clone(),
            &self.paths,
            layers,
        );
        child.restore = Some(Restore {
            criu_dir: self.criu_dir.clone(),
            tools_image_config: self.tools_image_config.clone(),
            rootfs_virtual_size: self.rootfs_virtual_size,
            envd_port: self.envd_port,
        });
        child.auth_mount = self.auth_mount;
        child.fork_child = true;
        Ok(child)
    }

    async fn start_child(&self, spec: &SandboxForkSpec) -> SandboxForkResult {
        let mut child = self.child(spec)?;
        match child.start().await {
            Ok(()) => Ok(Box::new(child) as Box<dyn SandboxBackend>),
            Err(err) => {
                let err = err.context("restore forked container");
                match child.stop().await {
                    Ok(()) => Err(err),
                    Err(stop_err) => {
                        warn!(
                            sandbox_id = %spec.sandbox_id,
                            error = %format_args!("{stop_err:#}"),
                            "failed to stop fork child after restore failure"
                        );
                        // Its devices may still use its volumes: hand it back
                        // for another teardown instead of dropping it.
                        Err(UnstoppedForkChild::error(
                            err,
                            Some(Box::new(child)),
                            &stop_err,
                        ))
                    }
                }
            }
        }
    }
}

#[async_trait]
impl SandboxForkCapture for ContainerForkCapture {
    async fn spawn(&self, spec: &[SandboxForkSpec]) -> Vec<SandboxForkResult> {
        // By index: a closure over `&SandboxForkSpec` trips async-trait's
        // Send check on higher-ranked lifetimes.
        futures::stream::iter(0..spec.len())
            .map(|index| self.start_child(&spec[index]))
            .buffered(RESTORE_CONCURRENCY)
            .collect()
            .await
    }
}
