//! Metrics and logs of a container sandbox, read on the host.
//!
//! envd's own `/metrics` reads `/proc` and the root filesystem, which inside a
//! container describe the host, not the sandbox's limits; and with `-isnotfc`
//! envd logs to stdout rather than to files in the guest. So the container
//! answers both from the host side: its cgroup, its mounted rootfs and its
//! runtime log.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use nix::sys::statvfs::statvfs;

use crate::logging::LogLevel;
use crate::sandbox::logs::{LogDecoder, LogPage, MAX_LOG_BYTES};
use crate::sandbox::{EnvdApi, SandboxLogEntry, SandboxMetric};

/// CPU usage is averaged since the previous sample. The first sample, or one
/// taken right after another, measures over this short window instead; it
/// must fit in the collector's 200 ms per-sandbox budget.
const MIN_CPU_WINDOW: Duration = Duration::from_millis(50);

/// The cgroup CPU counter at the last sample, shared by all handles of one
/// sandbox.
pub(super) type CpuSample = Arc<Mutex<Option<(Instant, u64)>>>;

pub(super) struct ContainerGuest {
    /// The container's cgroup directory, e.g. `/sys/fs/cgroup/aenv-container/aenv-<id>`.
    pub cgroup: PathBuf,
    /// Host mount point of the container rootfs.
    pub rootfs: PathBuf,
    /// The runtime's stdout/stderr, where envd writes its JSON log lines.
    pub log: PathBuf,
    pub cpu_count: u32,
    pub last_cpu: CpuSample,
}

fn read_trimmed(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?
        .trim()
        .to_owned())
}

/// `usage_usec` from a cgroup v2 `cpu.stat`.
fn cpu_usage_usec(cpu_stat: &str) -> Result<u64> {
    cpu_stat
        .lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .context("cpu.stat has no usage_usec")?
        .trim()
        .parse()
        .context("parse usage_usec")
}

/// The `file` (page cache) bytes from a cgroup v2 `memory.stat`.
fn page_cache_bytes(memory_stat: &str) -> Result<i64> {
    memory_stat
        .lines()
        .find_map(|line| line.strip_prefix("file "))
        .context("memory.stat has no file entry")?
        .trim()
        .parse()
        .context("parse memory.stat file")
}

/// Percentage of `cpu_count` cores used during `window`.
fn cpu_percent(before_usec: u64, after_usec: u64, window: Duration, cpu_count: u32) -> f32 {
    let capacity = window.as_micros() as f64 * f64::from(cpu_count.max(1));
    let used = after_usec.saturating_sub(before_usec) as f64;
    ((used / capacity) * 100.0).clamp(0.0, 100.0) as f32
}

impl ContainerGuest {
    fn read_cpu(&self) -> Result<u64> {
        cpu_usage_usec(&read_trimmed(&self.cgroup.join("cpu.stat"))?)
    }

    fn memory(&self) -> Result<(i64, i64, i64)> {
        let used: i64 = read_trimmed(&self.cgroup.join("memory.current"))?
            .parse()
            .context("parse memory.current")?;
        let total = match read_trimmed(&self.cgroup.join("memory.max"))?.as_str() {
            "max" => bail!("container cgroup has no memory limit"),
            limit => limit.parse().context("parse memory.max")?,
        };
        let cache = page_cache_bytes(&read_trimmed(&self.cgroup.join("memory.stat"))?)?;
        Ok((used, total, cache))
    }

    fn disk(&self) -> Result<(i64, i64)> {
        let stats =
            statvfs(&self.rootfs).with_context(|| format!("statvfs {}", self.rootfs.display()))?;
        let fragment = stats.fragment_size() as i64;
        let total = stats.blocks() as i64 * fragment;
        let used = total - stats.blocks_free() as i64 * fragment;
        Ok((used, total))
    }
}

#[async_trait]
impl EnvdApi for ContainerGuest {
    async fn metrics(&self) -> Result<SandboxMetric> {
        let previous = *self.last_cpu.lock().unwrap();
        let (start, before) = match previous {
            Some((at, usage)) if at.elapsed() >= MIN_CPU_WINDOW => (at, usage),
            _ => {
                let usage = self.read_cpu()?;
                let at = Instant::now();
                tokio::time::sleep(MIN_CPU_WINDOW).await;
                (at, usage)
            }
        };
        let after = self.read_cpu()?;
        let now = Instant::now();
        *self.last_cpu.lock().unwrap() = Some((now, after));
        let (mem_used, mem_total, mem_cache) = self.memory()?;
        let (disk_used, disk_total) = self.disk()?;
        Ok(SandboxMetric {
            timestamp: chrono::Utc::now(),
            cpu_count: i32::try_from(self.cpu_count.max(1)).context("cpu count overflow")?,
            cpu_used_pct: cpu_percent(before, after, now - start, self.cpu_count),
            mem_used,
            mem_total,
            mem_cache,
            disk_used,
            disk_total,
        })
    }

    async fn logs(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        limit: usize,
        backward: bool,
        level: Option<LogLevel>,
        search: Option<String>,
    ) -> Result<Vec<SandboxLogEntry>> {
        let mut page = LogPage::new(start, end, limit, backward, level, search);
        // The rotated generation first, then the live file; the writer keeps
        // both well under the query limit.
        let paths = [super::logfile::rotated(&self.log), self.log.clone()];
        let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            for path in paths {
                let mut file = match std::fs::File::open(&path) {
                    Ok(file) => file,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => {
                        return Err(err).with_context(|| format!("open {}", path.display()))
                    }
                };
                let budget = (MAX_LOG_BYTES as u64 + 1).saturating_sub(bytes.len() as u64);
                file.by_ref()
                    .take(budget)
                    .read_to_end(&mut bytes)
                    .with_context(|| format!("read {}", path.display()))?;
            }
            Ok(bytes)
        })
        .await
        .context("join log read")??;
        ensure!(
            bytes.len() <= MAX_LOG_BYTES,
            "sandbox logs exceed query size limit"
        );
        let mut decoder = LogDecoder::default();
        for chunk in bytes.chunks(8192) {
            for entry in decoder.feed(chunk)? {
                page.push(entry);
            }
        }
        Ok(page.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup_counters() {
        assert_eq!(
            cpu_usage_usec("usage_usec 1234\nuser_usec 1000\nsystem_usec 234\n").unwrap(),
            1234
        );
        assert!(cpu_usage_usec("user_usec 1\n").is_err());
        assert_eq!(
            page_cache_bytes("anon 4096\nfile 8192\nkernel 0\n").unwrap(),
            8192
        );
    }

    #[test]
    fn cpu_percent_is_relative_to_the_cpu_quota() {
        let window = Duration::from_millis(100);
        // One full core busy for the window on a 2-core sandbox is 50%.
        assert_eq!(cpu_percent(0, 100_000, window, 2), 50.0);
        assert_eq!(cpu_percent(500, 500, window, 2), 0.0);
        // Counter resets and overshoot stay within 0..=100.
        assert_eq!(cpu_percent(10, 5, window, 1), 0.0);
        assert_eq!(cpu_percent(0, 1_000_000, window, 1), 100.0);
    }
}
