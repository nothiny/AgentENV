//! Persisted state of a paused container sandbox.
//!
//! A pause dumps the container's processes with CRIU and seals its rootfs and
//! drives into the paused sandbox's artifact root, then releases every
//! runtime resource: the container, its devices, network slot and cgroup.
//! Resuming rebuilds those and restores the processes from the dump.
//!
//! The state records what the rebuild needs. Its paths are absolute and point
//! into the artifact root, the image cache (the tools image and the bottom of
//! the rootfs stack) or a volume's own directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::backend::PausedSandboxState;
use super::super::SandboxNetworkPolicy;
use crate::snapshot::CommandContext;
use crate::types::{
    CustomExtensionParams, ExtraDrive, RuntimeArtifactSet, SandboxBackendKind, SandboxResources,
};

/// Bumped when the persisted form changes incompatibly.
pub(super) const STATE_VERSION: u32 = 1;

/// CRIU writes this file last when a dump completes.
const CRIU_INVENTORY: &str = "inventory.img";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContainerPausedState {
    pub version: u32,
    /// The OCI runtime that dumped the processes; restoring needs the same.
    pub runtime: String,
    /// CRIU images of the container's processes.
    pub criu_dir: PathBuf,
    /// Image config of the sealed rootfs stack.
    pub rootfs_image_config: PathBuf,
    pub rootfs_virtual_size: Option<u64>,
    /// The tools image the processes run envd and busybox from. A restore
    /// maps the same binaries back, so it must be this exact image.
    pub tools_image_config: PathBuf,
    /// Drives in attachment order, each pointing at its sealed image config.
    pub extra_drives: Vec<ExtraDrive>,
    pub resources: SandboxResources,
    pub context: CommandContext,
    pub snapshot_id: String,
    pub env_vars: Option<HashMap<String, String>>,
    pub network: Option<SandboxNetworkPolicy>,
    pub custom_extension_params: Option<CustomExtensionParams>,
    pub envd_port: u16,
    /// Whether the dumped container had the auth directory bound in. CRIU
    /// restores exactly the mounts it dumped, so the restore binds it only
    /// then. Absent from containers paused before it existed.
    #[serde(default)]
    pub auth_mount: bool,
}

impl ContainerPausedState {
    /// Decodes persisted state and checks that its artifacts are still there.
    pub(super) fn decode(state: Value) -> Result<Self> {
        let state: Self =
            serde_json::from_value(state).context("deserialize container paused state")?;
        if state.version != STATE_VERSION {
            bail!(
                "container paused state version {} is not supported (expected {STATE_VERSION})",
                state.version
            );
        }
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<()> {
        require_file(&self.criu_dir.join(CRIU_INVENTORY), "CRIU dump")?;
        require_file(&self.rootfs_image_config, "rootfs image config")?;
        require_file(&self.tools_image_config, "tools image config")?;
        for drive in &self.extra_drives {
            require_file(
                drive.image_config_path(),
                &format!("drive '{}' image config", drive.drive_id()),
            )?;
        }
        if self.rootfs_virtual_size == Some(0) {
            bail!("rootfs virtual size must be non-zero");
        }
        Ok(())
    }
}

fn require_file(path: &Path, what: &str) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        bail!("{what} not found at {}", path.display())
    }
}

impl PausedSandboxState for ContainerPausedState {
    fn encode(&self) -> Result<Value> {
        serde_json::to_value(self).context("serialize container paused state")
    }

    fn runtime_artifacts(&self) -> RuntimeArtifactSet {
        let mut configs = vec![
            self.rootfs_image_config.clone(),
            self.tools_image_config.clone(),
        ];
        configs.extend(
            self.extra_drives
                .iter()
                .map(|drive| drive.image_config_path().to_path_buf()),
        );
        RuntimeArtifactSet::from_overlaybd_image_configs(configs)
    }

    fn control_plane_port(&self) -> Option<u16> {
        Some(self.envd_port)
    }

    fn backend(&self) -> SandboxBackendKind {
        SandboxBackendKind::Container
    }

    /// The restored processes no longer need their dump; the sealed rootfs
    /// and drives stay, since the running devices stack on them. A paused
    /// state has exactly one consumer: fork captures, which many children
    /// restore from, never come through here.
    fn release_after_resume(&self) {
        match std::fs::remove_dir_all(&self.criu_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => tracing::warn!(
                dump = %self.criu_dir.display(),
                error = %err,
                "failed to remove the CRIU dump of a resumed container"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(root: &Path) -> ContainerPausedState {
        ContainerPausedState {
            version: STATE_VERSION,
            runtime: "runc".into(),
            criu_dir: root.join("criu"),
            rootfs_image_config: root.join("rootfs/image.json"),
            rootfs_virtual_size: Some(64 << 20),
            tools_image_config: root.join("tools.json"),
            extra_drives: Vec::new(),
            resources: SandboxResources::default(),
            context: CommandContext::default(),
            snapshot_id: "snap".into(),
            env_vars: Some(HashMap::from([("K".into(), "V".into())])),
            network: None,
            custom_extension_params: None,
            envd_port: 49983,
            auth_mount: true,
        }
    }

    fn write_artifacts(root: &Path) {
        std::fs::create_dir_all(root.join("criu")).unwrap();
        std::fs::create_dir_all(root.join("rootfs")).unwrap();
        std::fs::write(root.join("criu").join(CRIU_INVENTORY), b"").unwrap();
        std::fs::write(root.join("rootfs/image.json"), b"{}").unwrap();
        std::fs::write(root.join("tools.json"), b"{}").unwrap();
    }

    #[test]
    fn round_trips_through_its_encoding() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path());
        let paused = state(temp.path());
        let decoded = ContainerPausedState::decode(paused.encode()?)?;
        assert_eq!(decoded, paused);
        assert_eq!(decoded.backend(), SandboxBackendKind::Container);
        assert_eq!(decoded.control_plane_port(), Some(49983));
        Ok(())
    }

    #[test]
    fn refuses_state_whose_dump_is_gone() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path());
        let encoded = state(temp.path()).encode()?;
        std::fs::remove_file(temp.path().join("criu").join(CRIU_INVENTORY))?;
        let err = ContainerPausedState::decode(encoded).unwrap_err();
        assert!(
            format!("{err:#}").contains("CRIU dump not found"),
            "{err:#}"
        );
        Ok(())
    }

    #[test]
    fn a_resume_releases_only_the_dump() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path());
        state(temp.path()).release_after_resume();
        assert!(!temp.path().join("criu").exists());
        assert!(temp.path().join("rootfs/image.json").exists());
        Ok(())
    }

    #[test]
    fn state_paused_before_the_auth_mount_restores_without_it() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path());
        let mut encoded = state(temp.path()).encode()?;
        encoded.as_object_mut().unwrap().remove("authMount");
        assert!(!ContainerPausedState::decode(encoded)?.auth_mount);
        Ok(())
    }

    #[test]
    fn refuses_other_versions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path());
        let mut encoded = state(temp.path()).encode()?;
        encoded["version"] = Value::from(STATE_VERSION + 1);
        assert!(ContainerPausedState::decode(encoded).is_err());
        Ok(())
    }
}
