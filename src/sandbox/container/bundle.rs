//! OCI bundle for a container sandbox: `config.json` plus the files it binds
//! into the container.
//!
//! Layout under the sandbox work directory:
//!
//! ```text
//! rootfs/            the OverlayBD rootfs device, mounted read-write
//! tools/             the tools drive, mounted read-only; tools/agentenv -> /agentenv
//! init.sh            one-time guest setup, bound at /.aenv-init
//! inittab            busybox init's table, bound at /etc/inittab
//! etc/{resolv.conf,hosts,hostname}
//! netns              the container's network namespace
//! config.json
//! ```

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::types::SandboxResources;

/// Container counterpart of the tools drive's `pivot-init`, run once by
/// busybox init before envd: no pivot_root and no kernel `ip=` arguments, as
/// the bundle provides rootfs, mounts, network and /etc files.
pub(super) const INIT_SCRIPT: &str = r#"#!/agentenv/bin/busybox sh
BB=/agentenv/bin/busybox
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
$BB mkdir -p /usr/local/bin /usr/bin /bin /run/lock /tmp /var/log/agentenv/envd
$BB ln -sf /agentenv/envd /usr/local/bin/envd
[ -x /usr/bin/nice ] || $BB ln -sf /agentenv/bin/busybox /usr/bin/nice
[ -x /usr/bin/ionice ] || $BB ln -sf /agentenv/bin/busybox /usr/bin/ionice
[ -x /bin/sh ] || $BB ln -sf /agentenv/bin/busybox /bin/sh
if [ ! -e /etc/passwd ]; then
    shell=/bin/sh
    [ -x /bin/bash ] && shell=/bin/bash
    $BB mkdir -p /etc /root
    $BB printf 'root:x:0:0:root:/root:%s\n' "$shell" > /etc/passwd
fi
"#;

/// busybox init is PID 1: it reaps orphaned processes, which envd does not,
/// and restarts envd if it dies, as runsv does in the VM.
fn inittab(envd_port: u16) -> String {
    format!(
        "::sysinit:/agentenv/bin/busybox sh /.aenv-init\n\
         ::respawn:/agentenv/bin/busybox env GODEBUG=multipathtcp=0 /agentenv/envd -isnotfc -port {envd_port}\n"
    )
}

/// Docker's default capability set, without `CAP_NET_RAW`.
const CAPABILITIES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

const CPU_PERIOD_US: u64 = 100_000;

/// Syscalls that reach kernel surface a sandbox has no use for, refused with
/// EPERM. Docker's default profile refuses the same ones; everything else is
/// allowed. Most of these already fail without `CAP_SYS_ADMIN` and friends,
/// and the filter keeps it that way whatever the capability set becomes.
const DENIED_SYSCALLS: &[&str] = &[
    "acct",
    "add_key",
    "bpf",
    "clock_adjtime",
    "clock_settime",
    "create_module",
    "delete_module",
    "finit_module",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "get_kernel_syms",
    "init_module",
    "ioperm",
    "iopl",
    "kcmp",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "lookup_dcookie",
    "mount",
    "mount_setattr",
    "move_mount",
    "name_to_handle_at",
    "nfsservctl",
    "open_by_handle_at",
    "open_tree",
    "perf_event_open",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "query_module",
    "quotactl",
    "quotactl_fd",
    "reboot",
    "request_key",
    "setns",
    "settimeofday",
    "stime",
    "swapoff",
    "swapon",
    "sysfs",
    "_sysctl",
    "umount",
    "umount2",
    "unshare",
    "uselib",
    "userfaultfd",
    "ustat",
    "vm86",
    "vm86old",
];

/// `clone` flags that create namespaces, refused with EPERM.
const NAMESPACE_CLONE_FLAGS: &[u64] = &[
    0x0002_0000, // CLONE_NEWNS
    0x0200_0000, // CLONE_NEWCGROUP
    0x0400_0000, // CLONE_NEWUTS
    0x0800_0000, // CLONE_NEWIPC
    0x1000_0000, // CLONE_NEWUSER
    0x2000_0000, // CLONE_NEWPID
    0x4000_0000, // CLONE_NEWNET
];

const EPERM: u32 = 1;
const ENOSYS: u32 = 38;

fn seccomp_architectures() -> &'static [&'static str] {
    if cfg!(target_arch = "aarch64") {
        &["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"]
    } else {
        &["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"]
    }
}

/// The sandbox's seccomp filter, for `linux.seccomp`.
pub(super) fn seccomp_profile() -> Value {
    let mut syscalls = vec![
        json!({"names": DENIED_SYSCALLS, "action": "SCMP_ACT_ERRNO", "errnoRet": EPERM}),
        // clone3 passes flags in memory, beyond a filter's reach. Report it
        // missing so libc falls back to clone, whose flags are checked below.
        json!({"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": ENOSYS}),
    ];
    syscalls.extend(NAMESPACE_CLONE_FLAGS.iter().map(|flag| {
        json!({
            "names": ["clone"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": EPERM,
            "args": [{"index": 0, "value": flag, "valueTwo": flag, "op": "SCMP_CMP_MASKED_EQ"}]
        })
    }));
    json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": seccomp_architectures(),
        "syscalls": syscalls,
    })
}

/// A drive mounted on the host and bound into the container.
pub(super) struct DriveBind {
    pub source: std::path::PathBuf,
    pub destination: std::path::PathBuf,
    pub read_only: bool,
}

pub(super) struct BundleSpec<'a> {
    pub work_dir: &'a Path,
    pub hostname: &'a str,
    pub guest_ip: Ipv4Addr,
    pub nameservers: &'a [Ipv4Addr],
    pub resources: SandboxResources,
    pub pids_limit: u32,
    pub envd_port: u16,
    pub cgroups_path: &'a str,
    pub drives: &'a [DriveBind],
    /// Whether the bundle is for restoring a CRIU dump rather than a start.
    pub restore: bool,
    /// Whether to bind [`AUTH_DIR`] read-only at [`AUTH_MOUNT`]. Every new
    /// container has it; a restore has it when the dumped container did,
    /// since CRIU restores exactly the mounts it dumped.
    pub auth: bool,
}

/// Host directory, in the work directory, that the container sees at
/// [`AUTH_MOUNT`]: control files only the server writes.
pub(super) const AUTH_DIR: &str = "auth";
/// Where the container sees [`AUTH_DIR`].
pub(super) const AUTH_MOUNT: &str = "/run/agentenv";
/// The SHA-512 (hex) of the access token envd must accept from its next
/// `/init` even though it holds another one: a fork child's restored envd
/// still holds its parent's token. envd built with the tools image's
/// access-token-file patch reads it, as Firecracker's envd reads the hash
/// from MMDS.
pub(super) const ACCESS_TOKEN_HASH: &str = "access-token-hash";

/// CRIU options file a restore bundle names through the `org.criu.config`
/// annotation. Connections saved by the dump come back closed, and the
/// processes go into this container's cgroup rather than the one recorded
/// in the dump.
pub(super) const CRIU_CONFIG: &str = "criu.conf";

fn criu_config(cgroups_path: &str) -> String {
    format!("tcp-close\ncgroup-root {cgroups_path}\n")
}

/// Writes `init.sh`, the /etc files and `config.json` into the work directory.
pub(super) fn write_bundle(spec: &BundleSpec<'_>) -> Result<()> {
    let dir = spec.work_dir;
    fs::create_dir_all(dir.join("etc")).context("create bundle etc directory")?;
    fs::write(dir.join("init.sh"), INIT_SCRIPT).context("write container init")?;
    fs::write(dir.join("inittab"), inittab(spec.envd_port)).context("write inittab")?;
    let resolv: String = spec
        .nameservers
        .iter()
        .map(|server| format!("nameserver {server}\n"))
        .collect();
    fs::write(dir.join("etc/resolv.conf"), resolv).context("write resolv.conf")?;
    fs::write(
        dir.join("etc/hosts"),
        format!(
            "127.0.0.1 localhost\n::1 localhost\n{} {}\n",
            spec.guest_ip, spec.hostname
        ),
    )
    .context("write hosts")?;
    fs::write(dir.join("etc/hostname"), format!("{}\n", spec.hostname))
        .context("write hostname")?;
    if spec.restore {
        fs::write(dir.join(CRIU_CONFIG), criu_config(spec.cgroups_path))
            .context("write CRIU config")?;
    }
    if spec.auth {
        fs::create_dir_all(dir.join(AUTH_DIR)).context("create auth directory")?;
    }
    let config = serde_json::to_vec_pretty(&oci_config(spec)).context("encode config.json")?;
    fs::write(dir.join("config.json"), config).context("write config.json")
}

fn bind(destination: &str, source: &Path, read_only: bool) -> Value {
    let mut options = vec!["rbind", "nosuid", "nodev"];
    if read_only {
        options.push("ro");
    }
    json!({"destination": destination, "type": "bind", "source": source, "options": options})
}

pub(super) fn oci_config(spec: &BundleSpec<'_>) -> Value {
    let dir = spec.work_dir;
    let drive_mounts: Vec<Value> = spec
        .drives
        .iter()
        .map(|drive| {
            bind(
                drive.destination.to_str().unwrap_or_default(),
                &drive.source,
                drive.read_only,
            )
        })
        .collect();
    let memory_bytes = u64::from(spec.resources.memory_mib) * 1024 * 1024;
    let cpu_quota = u64::from(spec.resources.cpu_count.max(1)) * CPU_PERIOD_US;
    let mut config = json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/agentenv/bin/busybox", "init"],
            "env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME=/root",
            ],
            "cwd": "/",
            "capabilities": {
                "bounding": CAPABILITIES,
                "effective": CAPABILITIES,
                "permitted": CAPABILITIES,
            },
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1_048_576u64, "soft": 1_048_576u64}],
            "noNewPrivileges": true
        },
        "root": {"path": dir.join("rootfs"), "readonly": false},
        "hostname": spec.hostname,
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/dev/pts", "type": "devpts", "source": "devpts",
             "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]},
            {"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
             "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]},
            {"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue",
             "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs",
             "options": ["nosuid", "noexec", "nodev", "ro"]},
            {"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
             "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]},
            {"destination": "/run", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "nodev", "mode=755"]},
            bind("/agentenv", &dir.join("tools/agentenv"), true),
            bind("/.aenv-init", &dir.join("init.sh"), true),
            bind("/etc/inittab", &dir.join("inittab"), true),
            bind("/etc/resolv.conf", &dir.join("etc/resolv.conf"), true),
            bind("/etc/hosts", &dir.join("etc/hosts"), true),
            bind("/etc/hostname", &dir.join("etc/hostname"), true)
        ],
        "linux": {
            "cgroupsPath": spec.cgroups_path,
            "seccomp": seccomp_profile(),
            "resources": {
                "memory": {"limit": memory_bytes, "swap": memory_bytes},
                "cpu": {"quota": cpu_quota, "period": CPU_PERIOD_US},
                "pids": {"limit": spec.pids_limit}
            },
            "namespaces": [
                {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
                {"type": "cgroup"},
                {"type": "network", "path": dir.join("netns")}
            ],
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
                "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
                "/proc/sched_debug", "/sys/firmware", "/proc/scsi"
            ],
            "readonlyPaths": [
                "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"
            ]
        }
    });
    let mounts = config["mounts"].as_array_mut().expect("mounts is an array");
    if spec.auth {
        mounts.push(bind(AUTH_MOUNT, &dir.join(AUTH_DIR), true));
    }
    mounts.extend(drive_mounts);
    if spec.restore {
        config["annotations"] = json!({"org.criu.config": dir.join(CRIU_CONFIG)});
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMESERVERS: &[Ipv4Addr] = &[Ipv4Addr::new(10, 0, 0, 53)];

    fn spec(dir: &Path) -> BundleSpec<'_> {
        BundleSpec {
            work_dir: dir,
            hostname: "instance",
            guest_ip: Ipv4Addr::new(169, 254, 0, 21),
            nameservers: NAMESERVERS,
            resources: SandboxResources {
                cpu_count: 2,
                memory_mib: 512,
                disk_size_mib: 0,
            },
            pids_limit: 4096,
            envd_port: 49983,
            cgroups_path: "/aenv-container/aenv-x",
            drives: DRIVES,
            restore: false,
            auth: true,
        }
    }

    static DRIVES: &[DriveBind] = &[];

    #[test]
    fn auth_directory_is_bound_read_only_only_when_asked() {
        let find = |config: &Value| {
            config["mounts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["destination"] == AUTH_MOUNT)
                .cloned()
        };
        let mut spec = spec(Path::new("/work/sb"));
        let auth = find(&oci_config(&spec)).unwrap();
        assert_eq!(auth["source"], "/work/sb/auth");
        assert!(auth["options"].as_array().unwrap().contains(&json!("ro")));
        // A restore of a container dumped without it must not add it.
        spec.restore = true;
        spec.auth = false;
        assert!(find(&oci_config(&spec)).is_none());
    }

    #[test]
    fn drives_are_bound_after_the_base_mounts() {
        let drives = [DriveBind {
            source: "/work/sb/drives/data/sub".into(),
            destination: "/data".into(),
            read_only: true,
        }];
        let mut spec = spec(Path::new("/work/sb"));
        spec.drives = &drives;
        let config = oci_config(&spec);
        let mounts = config["mounts"].as_array().unwrap();
        let last = mounts.last().unwrap();
        assert_eq!(last["destination"], "/data");
        assert_eq!(last["source"], "/work/sb/drives/data/sub");
        assert!(last["options"].as_array().unwrap().contains(&json!("ro")));
    }

    #[test]
    fn config_maps_resources_namespaces_and_tools() {
        let dir = Path::new("/work/sb");
        let config = oci_config(&spec(dir));
        assert_eq!(config["root"]["path"], "/work/sb/rootfs");
        let resources = &config["linux"]["resources"];
        assert_eq!(resources["memory"]["limit"], 512u64 * 1024 * 1024);
        assert_eq!(resources["cpu"]["quota"], 200_000u64);
        assert_eq!(resources["pids"]["limit"], 4096);
        let netns = config["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|ns| ns["type"] == "network")
            .unwrap();
        assert_eq!(netns["path"], "/work/sb/netns");
        let tools = config["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/agentenv")
            .unwrap();
        assert_eq!(tools["source"], "/work/sb/tools/agentenv");
        assert!(tools["options"].as_array().unwrap().contains(&json!("ro")));
        let caps = config["process"]["capabilities"]["bounding"]
            .as_array()
            .unwrap();
        assert!(!caps.contains(&json!("CAP_NET_RAW")));
        assert!(!caps.contains(&json!("CAP_SYS_ADMIN")));
        let seccomp = &config["linux"]["seccomp"];
        assert_eq!(seccomp["defaultAction"], "SCMP_ACT_ALLOW");
        let rules = seccomp["syscalls"].as_array().unwrap();
        let denied = |name: &str| {
            rules.iter().any(|rule| {
                rule["names"].as_array().unwrap().contains(&json!(name)) && rule["args"].is_null()
            })
        };
        for name in ["unshare", "mount", "bpf", "keyctl", "setns", "userfaultfd"] {
            assert!(denied(name), "{name} must be refused");
        }
        let clone3 = rules
            .iter()
            .find(|rule| rule["names"] == json!(["clone3"]))
            .unwrap();
        assert_eq!(clone3["errnoRet"], 38);
        let clone_rules: Vec<_> = rules
            .iter()
            .filter(|rule| rule["names"] == json!(["clone"]))
            .collect();
        assert_eq!(clone_rules.len(), 7);
        assert!(clone_rules
            .iter()
            .all(|rule| rule["args"][0]["op"] == "SCMP_CMP_MASKED_EQ"));
        assert_eq!(
            config["process"]["args"],
            json!(["/agentenv/bin/busybox", "init"])
        );
    }

    #[test]
    fn writes_bundle_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_bundle(&spec(temp.path()))?;
        assert!(fs::read_to_string(temp.path().join("init.sh"))?.contains("/etc/passwd"));
        let inittab = fs::read_to_string(temp.path().join("inittab"))?;
        assert!(inittab.contains("::sysinit:/agentenv/bin/busybox sh /.aenv-init"));
        assert!(inittab.contains("/agentenv/envd -isnotfc -port 49983"));
        assert_eq!(
            fs::read_to_string(temp.path().join("etc/resolv.conf"))?,
            "nameserver 10.0.0.53\n"
        );
        assert!(
            fs::read_to_string(temp.path().join("etc/hosts"))?.contains("169.254.0.21 instance")
        );
        let config: Value = serde_json::from_slice(&fs::read(temp.path().join("config.json"))?)?;
        assert_eq!(config["hostname"], "instance");
        assert!(config.get("annotations").is_none());
        assert!(!temp.path().join(CRIU_CONFIG).exists());
        assert!(temp.path().join(AUTH_DIR).is_dir());
        Ok(())
    }

    #[test]
    fn a_restore_bundle_names_its_criu_options() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_bundle(&BundleSpec {
            restore: true,
            ..spec(temp.path())
        })?;
        assert_eq!(
            fs::read_to_string(temp.path().join(CRIU_CONFIG))?,
            "tcp-close\ncgroup-root /aenv-container/aenv-x\n"
        );
        let config: Value = serde_json::from_slice(&fs::read(temp.path().join("config.json"))?)?;
        assert_eq!(
            config["annotations"]["org.criu.config"],
            temp.path().join(CRIU_CONFIG).display().to_string()
        );
        Ok(())
    }
}
