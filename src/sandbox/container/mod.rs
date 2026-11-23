//! OCI container backend: sandboxes run under an OCI runtime (runc, crun or
//! runsc) on the same OverlayBD rootfs and slot network Firecracker uses.
//!
//! The factory is registered when `container` is in `enabled_backends`;
//! launching sandboxes is not implemented yet, so every build fails with a
//! clear error instead of reaching an unfinished runtime.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};
use serde_json::Value;

use super::backend::{PausedSandboxState, SandboxBackend, SandboxBackendFactory};
use super::{EnvdAccessToken, FreshSandboxBuildSpec, SandboxLaunchConfig};
use crate::cfg::ContainerConfig;
use crate::snapshot::RunnableSnapshot;
use crate::types::SandboxId;

pub struct ContainerSandboxFactory {
    runtime: String,
}

impl ContainerSandboxFactory {
    pub fn from_config(config: &ContainerConfig) -> Self {
        Self {
            runtime: config.runtime.clone(),
        }
    }
}

impl SandboxBackendFactory for ContainerSandboxFactory {
    fn build(
        &self,
        _build_spec: FreshSandboxBuildSpec,
        _launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        bail!(
            "the container backend ({}) cannot launch sandboxes yet",
            self.runtime
        )
    }

    fn build_from_snapshot(
        &self,
        _snapshot: &RunnableSnapshot,
        _launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        bail!("container sandboxes cannot be launched from snapshots")
    }

    fn decode_paused_state(
        &self,
        _artifact_root: PathBuf,
        _state: Value,
    ) -> Result<Arc<dyn PausedSandboxState>> {
        bail!("container sandboxes cannot be paused")
    }

    fn build_from_paused_state(
        &self,
        _sandbox_id: SandboxId,
        _state: &dyn PausedSandboxState,
        _envd_access_token: Option<EnvdAccessToken>,
    ) -> Result<Box<dyn SandboxBackend>> {
        bail!("container sandboxes cannot be paused")
    }
}
