//! OCI container backend.
//!
//! A container sandbox runs under an OCI runtime (runc, crun or runsc) on the
//! same OverlayBD rootfs device Firecracker would attach, with the tools drive
//! mounted read-only at `/agentenv` and envd as PID 1. Its network is a leased
//! slot whose `tap0` is replaced by a veth pair into the container's own
//! namespace (see [`netns`]).
//!
//! Requires the server to run as root: rootful OCI runtimes need the full
//! capability set, which the non-root systemd unit does not grant.
//!
//! Supported: cold start, exec, files, proxy, delete. Pause, snapshot, fork,
//! volumes, attached drives and egress rules are rejected before they reach
//! this backend (see `SandboxBackendKind::supports`).

mod bundle;
mod netns;
mod runtime;

use std::any::Any;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use uvm_ublk_daemon::CreateOverlaybdRuntimeDeviceRequest;

use self::bundle::BundleSpec;
use self::netns::GuestLink;
use self::runtime::OciRuntime;
use super::backend::{
    CapturedSandboxSnapshot, PausedSandboxState, SandboxBackend, SandboxBackendFactory,
    SandboxCaptureError, SandboxCaptureResult, SandboxForkResult, SandboxForkSpec,
    SandboxRuntimeInfo,
};
use super::envd::EnvdInstance;
use super::network::{NetworkManager, SlotLease};
use super::process::Executor;
use super::ublk::{SharedReadOnlyDevice, UblkCreateSpec, UblkDevice};
use super::{
    resolve_tools_image, CustomExtensionParams, EnvdAccessToken, EnvdApi, FreshSandboxBuildSpec,
    SandboxExecutor, SandboxLaunchConfig, SandboxNetworkPolicy, UblkDeviceManager,
};
use crate::cfg::{AppConfig, ConfigManager};
use crate::snapshot::{RunnableSnapshot, SandboxSnapshotManifest};
use crate::types::{RuntimeArtifactSet, SandboxId, SandboxResources};

/// Container names and cgroups carry this prefix, so startup reconciliation
/// only touches containers this server created.
const CONTAINER_PREFIX: &str = "aenv-";
const CGROUP_PARENT: &str = "/aenv-container";
const HOSTNAME: &str = "instance";
const DEFAULT_PIDS_LIMIT: u32 = 4096;
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Where container sandboxes keep their state, from the node config.
#[derive(Clone, Debug)]
struct ContainerPaths {
    /// One directory per sandbox: bundle, mounts, netns, log.
    work_base: PathBuf,
    /// The OCI runtime's state directory.
    runtime_root: PathBuf,
}

impl ContainerPaths {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            work_base: config.home_path.join("container/sandboxes"),
            runtime_root: config.runtime_path.join("container/runtime"),
        }
    }
}

pub struct ContainerSandboxFactory {
    runtime: OciRuntime,
    paths: ContainerPaths,
}

impl ContainerSandboxFactory {
    pub fn from_config(config: &AppConfig) -> Self {
        let paths = ContainerPaths::from_config(config);
        Self {
            runtime: OciRuntime::new(config.container.runtime.clone(), &paths.runtime_root),
            paths,
        }
    }

    /// Removes containers, network namespaces and mounts left by a previous
    /// run of this server. Call before serving requests: container sandboxes
    /// do not survive a restart.
    pub async fn reconcile(&self) -> Result<()> {
        let mut failures = Vec::new();
        for id in self.runtime.list().await? {
            if !id.starts_with(CONTAINER_PREFIX) {
                continue;
            }
            info!(container = %id, "removing container left by a previous run");
            if let Err(err) = self.runtime.delete(&id).await {
                failures.push(format!("{id}: {err:#}"));
            }
        }
        let entries = match std::fs::read_dir(&self.paths.work_base) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return finish(failures),
            Err(err) => return Err(err).context("read container work directory"),
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            info!(work_dir = %dir.display(), "removing container work directory left by a previous run");
            if let Err(err) = remove_work_dir(&dir) {
                failures.push(format!("{}: {err:#}", dir.display()));
            }
        }
        finish(failures)
    }
}

fn finish(failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("container reconciliation: {}", failures.join("; "))
    }
}

/// Unmounts everything under a sandbox work directory and removes it.
fn remove_work_dir(dir: &Path) -> Result<()> {
    netns::remove_netns(&dir.join("netns"))?;
    for mount_point in ["tools", "rootfs"] {
        unmount(&dir.join(mount_point))?;
    }
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", dir.display())),
    }
}

/// Whether `path` is a mount point in this mount namespace.
fn is_mount_point(path: &Path) -> Result<bool> {
    let mountinfo =
        std::fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    let mounted = mount_points(&mountinfo).any(|point| Path::new(&point) == path);
    Ok(mounted)
}

/// Mount points listed in a mountinfo file, with octal escapes decoded.
fn mount_points(mountinfo: &str) -> impl Iterator<Item = String> + '_ {
    mountinfo.lines().filter_map(|line| {
        let escaped = line.split(' ').nth(4)?;
        let mut point = String::with_capacity(escaped.len());
        let mut rest = escaped;
        while let Some(index) = rest.find('\\') {
            point.push_str(&rest[..index]);
            let code = rest.get(index + 1..index + 4)?;
            point.push(u8::from_str_radix(code, 8).ok()? as char);
            rest = &rest[index + 4..];
        }
        point.push_str(rest);
        Some(point)
    })
}

/// Unmounts every mount stacked on `path`. Not mounted is success.
fn unmount(path: &Path) -> Result<()> {
    while is_mount_point(path)? {
        match umount2(path, MntFlags::empty()) {
            Ok(()) => {}
            Err(nix::errno::Errno::EBUSY) => {
                warn!(path = %path.display(), "mount busy; detaching");
                umount2(path, MntFlags::MNT_DETACH)
                    .with_context(|| format!("detach {}", path.display()))?;
            }
            Err(err) => bail!("unmount {}: {err}", path.display()),
        }
    }
    Ok(())
}

fn mount_ext4(device: &Path, target: &Path, read_only: bool) -> Result<()> {
    std::fs::create_dir_all(target).with_context(|| format!("create {}", target.display()))?;
    let mut flags = MsFlags::MS_NOATIME | MsFlags::MS_NODEV;
    if read_only {
        flags |= MsFlags::MS_RDONLY;
    }
    mount(Some(device), target, Some("ext4"), flags, None::<&str>)
        .with_context(|| format!("mount {} on {}", device.display(), target.display()))
}

impl SandboxBackendFactory for ContainerSandboxFactory {
    fn build(
        &self,
        build_spec: FreshSandboxBuildSpec,
        launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        if !nix::unistd::Uid::effective().is_root() {
            bail!("the container backend requires the server to run as root");
        }
        Ok(Box::new(ContainerSandbox::new(
            build_spec,
            launch_config,
            self.runtime.clone(),
            &self.paths,
        )))
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

/// Exit of the runtime process, published once it has been reaped.
type ExitState = Option<String>;

pub struct ContainerSandbox {
    id: SandboxId,
    container_id: String,
    build_spec: FreshSandboxBuildSpec,
    launch: SandboxLaunchConfig,
    runtime: OciRuntime,
    work_dir: PathBuf,
    resources: SandboxResources,
    custom_extension_params: Option<CustomExtensionParams>,
    network_policy: Option<SandboxNetworkPolicy>,
    // Runtime state, released by `stop` in reverse order of acquisition.
    tools: Option<SharedReadOnlyDevice>,
    rootfs: Option<UblkDevice>,
    rootfs_image_config: Option<PathBuf>,
    rootfs_virtual_size: Option<u64>,
    mounts: Vec<PathBuf>,
    slot: Option<SlotLease>,
    guest_netns: Option<PathBuf>,
    exited: Option<watch::Receiver<ExitState>>,
    envd: Option<EnvdInstance>,
}

impl ContainerSandbox {
    fn new(
        build_spec: FreshSandboxBuildSpec,
        launch: SandboxLaunchConfig,
        runtime: OciRuntime,
        paths: &ContainerPaths,
    ) -> Self {
        let id = launch.sandbox_id;
        Self {
            id,
            container_id: format!("{CONTAINER_PREFIX}{id}"),
            resources: build_spec.resources,
            custom_extension_params: launch.custom_extension_params.clone(),
            network_policy: launch.network.clone(),
            work_dir: paths.work_base.join(id.to_string()),
            build_spec,
            launch,
            runtime,
            tools: None,
            rootfs: None,
            rootfs_image_config: None,
            rootfs_virtual_size: None,
            mounts: Vec::new(),
            slot: None,
            guest_netns: None,
            exited: None,
            envd: None,
        }
    }

    fn log_path(&self) -> PathBuf {
        self.work_dir.join("container.log")
    }

    async fn attach_storage(&mut self, config: &AppConfig) -> Result<()> {
        let global_config = config.ublk.overlaybd.global_config_path.clone();
        let tools_config = resolve_tools_image(config, config.resolved_tools_version())
            .await?
            .context("the container backend needs an OverlayBD tools image")?;
        let tools = UblkDeviceManager::global()
            .get_or_create_shared_tools(&UblkCreateSpec::Overlaybd {
                image_config: tools_config,
                global_config: global_config.clone(),
            })
            .await
            .context("attach tools drive")?;
        let tools_device = tools.device_path().to_path_buf();
        self.tools = Some(tools);

        let requested_virtual_size = match self.resources.disk_size_mib {
            0 => None,
            mib => Some(
                u64::from(mib)
                    .checked_mul(1024 * 1024)
                    .context("requested rootfs size overflows bytes")?,
            ),
        };
        let rootfs = UblkDeviceManager::global()
            .create_overlaybd_runtime_device(CreateOverlaybdRuntimeDeviceRequest {
                source_image_config: &self.build_spec.image_config_path,
                global_config: &global_config,
                runtime_dir: &self.work_dir.join("overlaybd"),
                read_only: false,
                runtime_upper_mode: config.ublk.overlaybd.runtime_upper_mode,
                requested_virtual_size,
                known_source_virtual_size: None,
                allow_shrink: config.ublk.overlaybd.allow_shrink,
            })
            .await
            .context("create rootfs device")?;
        let rootfs_device = rootfs.device.device_path().to_path_buf();
        self.rootfs_virtual_size = Some(rootfs.actual_virtual_size);
        self.rootfs_image_config = Some(rootfs.image_config_path);
        self.rootfs = Some(rootfs.device);

        let rootfs_dir = self.work_dir.join("rootfs");
        mount_ext4(&rootfs_device, &rootfs_dir, false)?;
        self.mounts.push(rootfs_dir);
        let tools_dir = self.work_dir.join("tools");
        mount_ext4(&tools_device, &tools_dir, true)?;
        self.mounts.push(tools_dir);
        Ok(())
    }

    async fn attach_network(&mut self) -> Result<GuestLink> {
        let slot = NetworkManager::global()
            .allocate_configured(self.network_policy.clone())
            .await
            .context("allocate network slot")?;
        let (tap_ip, guest_ip, prefix) = slot.guest_link();
        let link = GuestLink {
            tap_ip,
            guest_ip,
            prefix,
        };
        let slot_netns = slot.namespace_path();
        self.slot = Some(slot);

        let guest_netns = self.work_dir.join("netns");
        self.guest_netns = Some(guest_netns.clone());
        tokio::task::spawn_blocking(move || {
            netns::create_netns(&guest_netns)?;
            netns::attach_guest(&slot_netns, &guest_netns, link)
        })
        .await
        .context("join container network setup")??;
        Ok(link)
    }

    fn start_runtime(&mut self) -> Result<()> {
        let mut child = self
            .runtime
            .run(&self.work_dir, &self.container_id, &self.log_path())?;
        let (tx, rx) = watch::channel(None);
        let container = self.container_id.clone();
        tokio::spawn(async move {
            let exit = match child.wait().await {
                Ok(status) => status.to_string(),
                Err(err) => format!("wait failed: {err}"),
            };
            debug!(container = %container, %exit, "container runtime exited");
            let _ = tx.send(Some(exit));
        });
        self.exited = Some(rx);
        Ok(())
    }

    async fn start_inner(&mut self) -> Result<()> {
        let config = ConfigManager::global_config();
        std::fs::create_dir_all(&self.work_dir)
            .with_context(|| format!("create {}", self.work_dir.display()))?;
        self.attach_storage(config).await?;
        let link = self.attach_network().await?;
        let dns = self
            .slot
            .as_ref()
            .map(|slot| slot.guest_dns_server())
            .context("network slot missing")?;
        let cgroups_path = format!("{CGROUP_PARENT}/{}", self.container_id);
        bundle::write_bundle(&BundleSpec {
            work_dir: &self.work_dir,
            hostname: HOSTNAME,
            guest_ip: link.guest_ip,
            nameservers: &[dns],
            resources: self.resources,
            pids_limit: DEFAULT_PIDS_LIMIT,
            envd_port: config.tools.control_plane_port,
            cgroups_path: &cgroups_path,
        })?;
        self.start_runtime()?;

        let host_ip = self.host_interaction_ip().context("network slot missing")?;
        self.envd = Some(EnvdInstance::new(
            format!("http://{host_ip}:{}", config.tools.control_plane_port),
            self.launch.envd_access_token.clone(),
        ));
        info!(container = %self.container_id, work_dir = %self.work_dir.display(), "container started");
        Ok(())
    }

    async fn ready_inner(&self) -> Result<()> {
        let config = ConfigManager::global_config();
        let envd = self.envd.as_ref().context("container has not started")?;
        let mut exited = self.exited.clone().context("container has not started")?;
        let ready = envd.wait_for_ready(
            Duration::from_secs(config.envd.init_timeout_secs),
            Duration::from_millis(config.envd.poll_ms),
        );
        tokio::select! {
            result = ready => result?,
            changed = exited.wait_for(Option::is_some) => {
                let exit = changed
                    .map(|exit| exit.clone().unwrap_or_default())
                    .unwrap_or_else(|_| "unknown".to_owned());
                bail!(
                    "container exited before envd was ready ({exit}); see {}",
                    self.log_path().display()
                );
            }
        }
        for device_key in [
            self.tools
                .as_ref()
                .map(|tools| tools.image_config_path().to_path_buf()),
            self.rootfs_image_config.clone(),
        ]
        .into_iter()
        .flatten()
        {
            UblkDeviceManager::global()
                .notify_sandbox_ready(&device_key)
                .await;
        }

        let context = &self.build_spec.context;
        let mut env_vars: HashMap<String, String> = context.env_vars.clone();
        if let Some(launch_env) = &self.launch.env_vars {
            env_vars.extend(launch_env.clone());
        }
        envd.init(
            (!env_vars.is_empty()).then_some(env_vars),
            Some(context.workdir.clone()),
            context.user.clone(),
        )
        .await
        .context("initialize envd")
    }

    async fn stop_inner(&mut self) -> Result<()> {
        if let Some(envd) = self.envd.take() {
            envd.invalidate();
        }
        let mut failures = Vec::new();
        if let Some(mut exited) = self.exited.take() {
            if exited.borrow().is_none() {
                if let Err(err) = self.runtime.kill(&self.container_id, "KILL").await {
                    failures.push(format!("kill: {err:#}"));
                }
                if tokio::time::timeout(STOP_TIMEOUT, exited.wait_for(Option::is_some))
                    .await
                    .is_err()
                {
                    failures.push(format!(
                        "container did not exit within {}s",
                        STOP_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        if let Err(err) = self.runtime.delete(&self.container_id).await {
            failures.push(format!("delete: {err:#}"));
        }
        if let Some(path) = self.guest_netns.take() {
            if let Err(err) = netns::remove_netns(&path) {
                failures.push(format!("{err:#}"));
            }
        }
        if let Some(slot) = self.slot.take() {
            // The slot's tap0 is now a veth; never pool it.
            match tokio::task::spawn_blocking(move || slot.destroy(false)).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => failures.push(format!("destroy network slot: {err:#}")),
                Err(err) => failures.push(format!("join slot teardown: {err}")),
            }
        }
        while let Some(path) = self.mounts.pop() {
            if let Err(err) = unmount(&path) {
                failures.push(format!("{err:#}"));
            }
        }
        if let Some(device) = self.rootfs.take() {
            if let Err(err) = UblkDeviceManager::global().delete_device(&device).await {
                failures.push(format!("delete rootfs device: {err:#}"));
            }
        }
        if let Some(tools) = self.tools.take() {
            if let Err(err) = tools.release().await {
                failures.push(format!("release tools drive: {err:#}"));
            }
        }
        if failures.is_empty() {
            if let Err(err) = std::fs::remove_dir_all(&self.work_dir) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    failures.push(format!("remove work directory: {err}"));
                }
            }
        }
        if failures.is_empty() {
            debug!(container = %self.container_id, "container stopped");
            Ok(())
        } else {
            Err(anyhow!(
                "stop container {}: {}",
                self.container_id,
                failures.join("; ")
            ))
        }
    }

    fn unsupported<T>(&self, operation: &str) -> Result<T> {
        bail!("container sandbox {} does not support {operation}", self.id)
    }
}

#[async_trait]
impl SandboxBackend for ContainerSandbox {
    fn envd(&self) -> Option<Arc<dyn EnvdApi>> {
        let envd = self.envd.clone()?;
        Some(Arc::new(envd))
    }

    async fn start(&mut self) -> Result<()> {
        self.start_nowait().await?;
        self.wait_for_ready().await
    }

    async fn start_nowait(&mut self) -> Result<()> {
        self.start_inner().await
    }

    async fn wait_for_ready(&self) -> Result<()> {
        self.ready_inner().await
    }

    async fn pause(
        &mut self,
        _artifact_root: Option<&Path>,
    ) -> SandboxCaptureResult<Arc<dyn PausedSandboxState>> {
        Err(SandboxCaptureError::recoverable(anyhow!(
            "container sandboxes cannot be paused"
        )))
    }

    async fn resume(&mut self) -> Result<()> {
        self.unsupported("resume")
    }

    async fn snapshot(&mut self) -> SandboxCaptureResult<CapturedSandboxSnapshot> {
        Err(SandboxCaptureError::recoverable(anyhow!(
            "container sandboxes cannot be snapshotted"
        )))
    }

    async fn snapshot_volumes(&mut self) -> SandboxCaptureResult<()> {
        // Container sandboxes have no managed volumes.
        Ok(())
    }

    async fn fork(
        &mut self,
        _spec: &[SandboxForkSpec],
    ) -> SandboxCaptureResult<Vec<SandboxForkResult>> {
        Err(SandboxCaptureError::recoverable(anyhow!(
            "container sandboxes cannot be forked"
        )))
    }

    async fn capture_to_dir(
        &mut self,
        _at: &Path,
    ) -> SandboxCaptureResult<(SandboxSnapshotManifest, Option<Box<dyn Any + Send>>)> {
        Err(SandboxCaptureError::recoverable(anyhow!(
            "container sandboxes cannot be captured"
        )))
    }

    async fn stop(&mut self) -> Result<()> {
        self.stop_inner().await
    }

    async fn freeze_and_snapshot_volumes(&mut self) -> SandboxCaptureResult<()> {
        // Container sandboxes have no managed volumes.
        Ok(())
    }

    async fn thaw_volumes(&mut self) -> Result<()> {
        Ok(())
    }

    fn host_interaction_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.slot.as_ref().map(|slot| slot.host_interaction_ip)
    }

    fn runtime_info(&self) -> SandboxRuntimeInfo {
        let paths = [
            self.tools
                .as_ref()
                .map(|tools| tools.image_config_path().to_path_buf()),
            self.rootfs_image_config.clone(),
        ]
        .into_iter()
        .flatten()
        .collect();
        SandboxRuntimeInfo {
            rootfs_virtual_size: self.rootfs_virtual_size,
            runtime_artifacts: RuntimeArtifactSet::from_overlaybd_image_configs(paths),
        }
    }

    fn startup_artifacts(&self) -> RuntimeArtifactSet {
        RuntimeArtifactSet::from_overlaybd_image_configs(vec![self
            .build_spec
            .image_config_path
            .clone()])
    }

    async fn update_network_policy(&mut self, _policy: Option<SandboxNetworkPolicy>) -> Result<()> {
        self.unsupported("network policy updates")
    }

    fn update_custom_extension_params(&mut self, params: Option<CustomExtensionParams>) {
        self.custom_extension_params = params;
    }
}

#[async_trait(?Send)]
impl SandboxExecutor for ContainerSandbox {
    fn executor(&self) -> Result<Executor> {
        let envd = self.envd.as_ref().context("Sandbox is not running")?;
        Ok(Executor::new(envd.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_points_decode_escapes() {
        let mountinfo = "36 35 98:0 /mnt1 /mnt/a\\040b rw,noatime master:1 - ext3 /dev/root rw\n\
                         37 35 98:0 / /work/x/rootfs rw - ext4 /dev/ublkb3 rw\n";
        let points: Vec<_> = mount_points(mountinfo).collect();
        assert_eq!(
            points,
            vec!["/mnt/a b".to_string(), "/work/x/rootfs".to_string()]
        );
    }

    #[tokio::test]
    async fn reconcile_without_state_is_a_no_op() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let factory = ContainerSandboxFactory {
            runtime: OciRuntime::new("runc", temp.path().join("missing-root")),
            paths: ContainerPaths {
                work_base: temp.path().join("missing-work"),
                runtime_root: temp.path().join("missing-root"),
            },
        };
        factory.reconcile().await
    }

    #[tokio::test]
    async fn reconcile_removes_leftover_work_directories() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let work_base = temp.path().join("sandboxes");
        let leftover = work_base.join("01a20000-0000-7000-8000-000000000000");
        std::fs::create_dir_all(leftover.join("rootfs"))?;
        std::fs::write(leftover.join("config.json"), "{}")?;
        let factory = ContainerSandboxFactory {
            runtime: OciRuntime::new("runc", temp.path().join("missing-root")),
            paths: ContainerPaths {
                work_base: work_base.clone(),
                runtime_root: temp.path().join("missing-root"),
            },
        };
        factory.reconcile().await?;
        assert!(!leftover.exists());
        Ok(())
    }
}
