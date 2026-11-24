//! The container's stdout and stderr, kept in a bounded, rotated file.
//!
//! envd logs to stdout for the sandbox's whole life. The runtime's output is
//! piped through the server into `container.log`, which rotates to
//! `container.log.1` at [`MAX_FILE_BYTES`], so the node keeps at most two
//! files per sandbox and the newest entries stay queryable.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::warn;

/// Size at which the live file rotates. Two files stay below the 32 MiB a
/// log query reads.
pub(super) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Longer lines are cut, so one line cannot exceed a file.
const MAX_LINE_BYTES: usize = 256 * 1024;

/// The previous generation of `path`.
pub(super) fn rotated(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_owned();
    rotated.push(".1");
    PathBuf::from(rotated)
}

pub(super) struct LogFile {
    path: PathBuf,
    file: Option<tokio::fs::File>,
    size: u64,
    max: u64,
}

impl LogFile {
    pub(super) fn new(path: PathBuf) -> Arc<Mutex<Self>> {
        Self::with_limit(path, MAX_FILE_BYTES)
    }

    fn with_limit(path: PathBuf, max: u64) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            path,
            file: None,
            size: 0,
            max,
        }))
    }

    async fn write_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        if self.file.is_none() || self.size + line.len() as u64 > self.max {
            if self.file.take().is_some() {
                tokio::fs::rename(&self.path, rotated(&self.path)).await?;
            }
            let file = tokio::fs::File::options()
                .create(true)
                .append(true)
                .open(&self.path)
                .await?;
            self.size = file.metadata().await?.len();
            self.file = Some(file);
        }
        let file = self.file.as_mut().expect("opened above");
        file.write_all(line).await?;
        self.size += line.len() as u64;
        Ok(())
    }
}

/// Copies `stream` into `log` line by line until the stream closes.
pub(super) fn spawn_pump(
    stream: impl AsyncRead + Unpin + Send + 'static,
    log: Arc<Mutex<LogFile>>,
) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        loop {
            line.clear();
            match (&mut reader)
                .take(MAX_LINE_BYTES as u64)
                .read_until(b'\n', &mut line)
                .await
            {
                Ok(0) => break,
                Ok(_) => {
                    if line.last() != Some(&b'\n') {
                        line.push(b'\n');
                    }
                    if let Err(err) = log.lock().await.write_line(&line).await {
                        warn!(error = %err, "failed to write container log");
                    }
                }
                Err(err) => {
                    warn!(error = %err, "failed to read container output");
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rotates_and_keeps_one_previous_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("container.log");
        let log = LogFile::with_limit(path.clone(), 100);
        for i in 0..30 {
            log.lock()
                .await
                .write_line(format!("line {i:02}\n").as_bytes())
                .await
                .unwrap();
        }
        let current = std::fs::read_to_string(&path).unwrap();
        let previous = std::fs::read_to_string(rotated(&path)).unwrap();
        assert!(current.len() <= 100 && previous.len() <= 100);
        assert!(current.ends_with("line 29\n"), "{current}");
        assert!(!previous.contains("line 00"), "only one generation is kept");
        assert!(!temp.path().join("container.log.2").exists());
    }

    #[tokio::test]
    async fn pump_cuts_overlong_lines() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("container.log");
        let log = LogFile::new(path.clone());
        let mut input = vec![b'x'; MAX_LINE_BYTES * 2];
        input.extend_from_slice(b"\nshort\n");
        spawn_pump(std::io::Cursor::new(input), Arc::clone(&log));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let written = std::fs::read(&path).unwrap();
        assert!(written
            .split(|b| *b == b'\n')
            .all(|l| l.len() <= MAX_LINE_BYTES));
        assert!(written.ends_with(b"short\n"));
    }
}
