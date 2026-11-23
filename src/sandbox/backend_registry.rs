//! Dispatches sandbox construction to the backend each sandbox runs on.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::backend::{PausedSandboxState, SandboxBackend, SandboxBackendFactory};
use super::{EnvdAccessToken, FreshSandboxBuildSpec, SandboxLaunchConfig};
use crate::snapshot::RunnableSnapshot;
use crate::types::{SandboxBackendKind, SandboxId};

/// The factories of the backends this node runs.
///
/// The orchestrator holds a single factory; the registry is that factory and
/// forwards each call by backend: fresh builds by
/// [`FreshSandboxBuildSpec::backend`], snapshot launches by the manifest's
/// `backend`, and paused sandboxes to Firecracker, the only backend that
/// pauses.
#[derive(Default)]
pub struct BackendRegistry {
    firecracker: Option<Box<dyn SandboxBackendFactory>>,
    container: Option<Box<dyn SandboxBackendFactory>>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry with only `factory` as the Firecracker backend.
    pub fn firecracker(factory: impl SandboxBackendFactory) -> Self {
        Self::new().with(SandboxBackendKind::Firecracker, factory)
    }

    /// Registers `factory` for `backend`, replacing any earlier one.
    pub fn with(
        mut self,
        backend: SandboxBackendKind,
        factory: impl SandboxBackendFactory,
    ) -> Self {
        *self.slot(backend) = Some(Box::new(factory));
        self
    }

    pub fn is_registered(&self, backend: SandboxBackendKind) -> bool {
        self.get(backend).is_some()
    }

    fn slot(&mut self, backend: SandboxBackendKind) -> &mut Option<Box<dyn SandboxBackendFactory>> {
        match backend {
            SandboxBackendKind::Firecracker => &mut self.firecracker,
            SandboxBackendKind::Container => &mut self.container,
        }
    }

    fn get(&self, backend: SandboxBackendKind) -> Option<&dyn SandboxBackendFactory> {
        match backend {
            SandboxBackendKind::Firecracker => self.firecracker.as_deref(),
            SandboxBackendKind::Container => self.container.as_deref(),
        }
    }

    fn factory(&self, backend: SandboxBackendKind) -> Result<&dyn SandboxBackendFactory> {
        self.get(backend)
            .ok_or_else(|| anyhow!("sandbox backend '{backend}' is not enabled on this node"))
    }
}

impl SandboxBackendFactory for BackendRegistry {
    fn build(
        &self,
        build_spec: FreshSandboxBuildSpec,
        launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        self.factory(build_spec.backend)?
            .build(build_spec, launch_config)
    }

    fn build_from_snapshot(
        &self,
        snapshot: &RunnableSnapshot,
        launch_config: SandboxLaunchConfig,
    ) -> Result<Box<dyn SandboxBackend>> {
        let backend = snapshot
            .manifest()
            .backend
            .parse::<SandboxBackendKind>()
            .map_err(|err| anyhow!("snapshot {}: {err}", snapshot.record().id))?;
        self.factory(backend)?
            .build_from_snapshot(snapshot, launch_config)
    }

    fn decode_paused_state(
        &self,
        artifact_root: PathBuf,
        state: Value,
    ) -> Result<Arc<dyn PausedSandboxState>> {
        self.factory(SandboxBackendKind::Firecracker)?
            .decode_paused_state(artifact_root, state)
    }

    fn restores_paused(&self, backend: SandboxBackendKind) -> bool {
        backend.supports(crate::types::BackendCapability::Pause) && self.is_registered(backend)
    }

    fn build_from_paused_state(
        &self,
        sandbox_id: SandboxId,
        state: &dyn PausedSandboxState,
        envd_access_token: Option<EnvdAccessToken>,
    ) -> Result<Box<dyn SandboxBackend>> {
        self.factory(SandboxBackendKind::Firecracker)?
            .build_from_paused_state(sandbox_id, state, envd_access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::mock::{MockAction, MockBackendFactory, MockBehavior, MockOperation};

    fn spec(backend: SandboxBackendKind) -> FreshSandboxBuildSpec {
        FreshSandboxBuildSpec {
            backend,
            image_config_path: PathBuf::from("/nonexistent/image.json"),
            context: Default::default(),
            resources: Default::default(),
            extra_drives: Vec::new(),
            extra_boot_args: None,
        }
    }

    /// A mock factory whose next build fails with `name`, so a build's error
    /// tells which factory handled it.
    fn named(name: &str) -> MockBackendFactory {
        let behavior = Arc::new(MockBehavior::new());
        behavior.push_action(
            MockOperation::Build,
            MockAction::Fail {
                message: name.to_owned(),
            },
        );
        MockBackendFactory::with_behavior(behavior)
    }

    fn handled_by(registry: &BackendRegistry, backend: SandboxBackendKind) -> String {
        registry
            .build(spec(backend), Default::default())
            .err()
            .expect("named factories fail their build")
            .to_string()
    }

    #[test]
    fn routes_each_build_to_its_backend() {
        let registry = BackendRegistry::firecracker(named("fc"))
            .with(SandboxBackendKind::Container, named("ct"));
        assert_eq!(handled_by(&registry, SandboxBackendKind::Container), "ct");
        assert_eq!(handled_by(&registry, SandboxBackendKind::Firecracker), "fc");
    }

    #[test]
    fn restores_paused_sandboxes_only_of_registered_pausing_backends() {
        let firecracker_only = BackendRegistry::firecracker(named("fc"));
        assert!(firecracker_only.restores_paused(SandboxBackendKind::Firecracker));
        assert!(!firecracker_only.restores_paused(SandboxBackendKind::Container));
        let container_only =
            BackendRegistry::new().with(SandboxBackendKind::Container, named("ct"));
        assert!(!container_only.restores_paused(SandboxBackendKind::Firecracker));
        assert!(!container_only.restores_paused(SandboxBackendKind::Container));
    }

    #[test]
    fn rejects_backends_that_are_not_registered() {
        let registry = BackendRegistry::firecracker(named("fc"));
        assert!(registry.is_registered(SandboxBackendKind::Firecracker));
        assert!(!registry.is_registered(SandboxBackendKind::Container));
        let err = handled_by(&registry, SandboxBackendKind::Container);
        assert!(err.contains("'container' is not enabled"), "{err}");
    }
}
