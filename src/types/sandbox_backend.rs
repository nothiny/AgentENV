use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The runtime that executes a sandbox.
///
/// A sandbox keeps its backend for its whole lifecycle. Records written
/// before backends existed deserialize as [`SandboxBackendKind::Firecracker`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxBackendKind {
    #[default]
    Firecracker,
    Container,
}

/// Optional sandbox capabilities. Every backend supports creating, running,
/// executing commands in and deleting a sandbox; anything else is listed
/// here and checked before it is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendCapability {
    /// Durable pause/resume, including `autoPause` and `autoResume`.
    Pause,
    /// Capture a snapshot of a running sandbox.
    Snapshot,
    /// Launch a sandbox from a committed snapshot or template.
    SnapshotRestore,
    /// Fork a running sandbox.
    Fork,
    /// Managed `volumeMounts`.
    ManagedVolumes,
    /// Cold-start `attachedDrives`.
    AttachedDrives,
    /// Guest kernel `extraBootArgs`.
    ExtraBootArgs,
    /// Per-sandbox egress rules (`allowOut`/`denyOut`/`maskRequestHost`).
    EgressRules,
    /// Replacing the network policy of a running sandbox.
    UpdateNetwork,
    /// Non-empty custom extension params and their hooks.
    CustomExtension,
}

impl SandboxBackendKind {
    pub const ALL: [Self; 2] = [Self::Firecracker, Self::Container];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Container => "container",
        }
    }

    /// What this backend implements today. Grows as container phases land.
    pub fn supports(self, capability: BackendCapability) -> bool {
        match self {
            Self::Firecracker => true,
            Self::Container => match capability {
                BackendCapability::Pause
                | BackendCapability::Snapshot
                | BackendCapability::SnapshotRestore
                | BackendCapability::Fork
                | BackendCapability::ManagedVolumes
                | BackendCapability::AttachedDrives
                | BackendCapability::ExtraBootArgs
                | BackendCapability::EgressRules
                | BackendCapability::UpdateNetwork
                | BackendCapability::CustomExtension => false,
            },
        }
    }
}

impl fmt::Display for SandboxBackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SandboxBackendKind {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "firecracker" => Ok(Self::Firecracker),
            "container" => Ok(Self::Container),
            other => Err(format!(
                "unknown sandbox backend {other:?}; expected \"firecracker\" or \"container\""
            )),
        }
    }
}

impl fmt::Display for BackendCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pause => "pause/resume (autoPause, autoResume)",
            Self::Snapshot => "snapshot capture",
            Self::SnapshotRestore => "launch from a snapshot or template",
            Self::Fork => "fork",
            Self::ManagedVolumes => "volumeMounts",
            Self::AttachedDrives => "attachedDrives",
            Self::ExtraBootArgs => "extraBootArgs",
            Self::EgressRules => "network egress rules",
            Self::UpdateNetwork => "network policy updates",
            Self::CustomExtension => "custom extension params",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_backend_names() {
        for kind in SandboxBackendKind::ALL {
            assert_eq!(kind.as_str().parse::<SandboxBackendKind>().unwrap(), kind);
            assert_eq!(kind.to_string(), kind.as_str());
        }
        assert_eq!(
            " Container ".parse::<SandboxBackendKind>().unwrap(),
            SandboxBackendKind::Container
        );
        assert!("docker".parse::<SandboxBackendKind>().is_err());
    }

    #[test]
    fn records_without_a_backend_are_firecracker() {
        #[derive(Deserialize)]
        struct Record {
            #[serde(default)]
            backend: SandboxBackendKind,
        }
        let record: Record = serde_json::from_str("{}").unwrap();
        assert_eq!(record.backend, SandboxBackendKind::Firecracker);
        let record: Record = serde_json::from_str(r#"{"backend":"container"}"#).unwrap();
        assert_eq!(record.backend, SandboxBackendKind::Container);
    }

    #[test]
    fn firecracker_supports_everything_and_container_starts_minimal() {
        use BackendCapability::*;
        let all = [
            Pause,
            Snapshot,
            SnapshotRestore,
            Fork,
            ManagedVolumes,
            AttachedDrives,
            ExtraBootArgs,
            EgressRules,
            UpdateNetwork,
            CustomExtension,
        ];
        for capability in all {
            assert!(SandboxBackendKind::Firecracker.supports(capability));
            assert!(!SandboxBackendKind::Container.supports(capability));
        }
    }
}
