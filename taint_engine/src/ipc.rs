// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Pipe/IPC taint propagation (v0.8).
//!
//! Tracks taint through inter-process communication channels:
//! - Named pipes (FIFOs) on Unix
//! - Unix domain sockets
//! - Windows named pipes (\\.\pipe\)
//!
//! When a tainted process writes to a pipe/socket, any process reading
//! from the same pipe/socket inherits taint — closing the IPC relay
//! exfiltration vector.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Tracks IPC channels and propagates taint through them.
pub struct IpcTracker {
    /// Named pipe/socket path → set of writer PIDs.
    writers: HashMap<PathBuf, HashSet<i32>>,
    /// Named pipe/socket path → set of reader PIDs.
    readers: HashMap<PathBuf, HashSet<i32>>,
    /// Paths with tainted writers (taint should propagate to readers).
    tainted_channels: HashSet<PathBuf>,
    /// Audit trail.
    events: Vec<IpcTaintEvent>,
    /// Anonymous pipe tracking: pipe FD pair → (writer_pid, reader_pid).
    anon_pipes: Vec<AnonPipe>,
}

/// An anonymous pipe (from pipe(2) syscall).
#[derive(Debug, Clone)]
pub struct AnonPipe {
    /// The PID that created the pipe.
    pub creator_pid: i32,
    /// Read end file descriptor.
    pub read_fd: i32,
    /// Write end file descriptor.
    pub write_fd: i32,
    /// PID holding the read end (after fork).
    pub reader_pid: Option<i32>,
    /// PID holding the write end (after fork).
    pub writer_pid: Option<i32>,
    /// Whether the write end is tainted.
    pub tainted: bool,
}

/// Record of taint propagation via IPC.
#[derive(Debug, Clone)]
pub struct IpcTaintEvent {
    pub source_pid: i32,
    pub target_pid: i32,
    pub channel: IpcChannel,
}

/// The type of IPC channel.
#[derive(Debug, Clone)]
pub enum IpcChannel {
    /// Named pipe (FIFO).
    NamedPipe(PathBuf),
    /// Unix domain socket.
    UnixSocket(PathBuf),
    /// Anonymous pipe.
    AnonPipe { read_fd: i32, write_fd: i32 },
    /// Windows named pipe.
    WindowsPipe(String),
}

impl IpcTracker {
    pub fn new() -> Self {
        Self {
            writers: HashMap::with_capacity(32),
            readers: HashMap::with_capacity(32),
            tainted_channels: HashSet::new(),
            events: Vec::new(),
            anon_pipes: Vec::new(),
        }
    }

    /// A process opened a named pipe or Unix socket for writing.
    /// Returns PIDs that should inherit taint (if writer is tainted).
    pub fn on_ipc_write(&mut self, pid: i32, path: &Path, is_tainted: bool) -> Vec<i32> {
        self.writers
            .entry(path.to_path_buf())
            .or_default()
            .insert(pid);

        if is_tainted {
            self.tainted_channels.insert(path.to_path_buf());
            // Propagate taint to all current readers
            let targets: Vec<i32> = self
                .readers
                .get(path)
                .map(|pids| pids.iter().copied().filter(|&p| p != pid).collect())
                .unwrap_or_default();

            for &target in &targets {
                self.events.push(IpcTaintEvent {
                    source_pid: pid,
                    target_pid: target,
                    channel: if is_unix_socket(path) {
                        IpcChannel::UnixSocket(path.to_path_buf())
                    } else {
                        IpcChannel::NamedPipe(path.to_path_buf())
                    },
                });
            }

            targets
        } else {
            Vec::new()
        }
    }

    /// A process opened a named pipe or Unix socket for reading.
    /// Returns true if the channel is already tainted (reader should be tainted).
    pub fn on_ipc_read(&mut self, pid: i32, path: &Path) -> bool {
        self.readers
            .entry(path.to_path_buf())
            .or_default()
            .insert(pid);

        if self.tainted_channels.contains(path) {
            // Find who tainted it
            let source_pid = self
                .writers
                .get(path)
                .and_then(|pids| pids.iter().next().copied())
                .unwrap_or(0);

            self.events.push(IpcTaintEvent {
                source_pid,
                target_pid: pid,
                channel: if is_unix_socket(path) {
                    IpcChannel::UnixSocket(path.to_path_buf())
                } else {
                    IpcChannel::NamedPipe(path.to_path_buf())
                },
            });

            true
        } else {
            false
        }
    }

    /// Register an anonymous pipe created by pipe(2).
    pub fn on_pipe_create(&mut self, creator_pid: i32, read_fd: i32, write_fd: i32) {
        self.anon_pipes.push(AnonPipe {
            creator_pid,
            read_fd,
            write_fd,
            reader_pid: Some(creator_pid),
            writer_pid: Some(creator_pid),
            tainted: false,
        });
    }

    /// After fork, reassign pipe ends (child inherits FDs).
    pub fn on_pipe_fork(&mut self, parent_pid: i32, child_pid: i32) {
        // After fork, both parent and child have both ends.
        // The typical pattern is: parent closes one end, child closes the other.
        // We track the potential for taint through any pipe shared between parent/child.
        for pipe in &mut self.anon_pipes {
            if pipe.creator_pid == parent_pid {
                // Child inherits — we don't know who closes what yet,
                // so mark both as potential holders.
                if pipe.reader_pid == Some(parent_pid) {
                    pipe.reader_pid = Some(child_pid);
                }
                if pipe.writer_pid == Some(parent_pid) {
                    pipe.writer_pid = Some(child_pid);
                }
            }
        }
    }

    /// Mark an anonymous pipe's write end as tainted.
    /// Returns the reader PID if known (should be tainted).
    pub fn on_anon_pipe_taint(&mut self, writer_pid: i32, write_fd: i32) -> Option<i32> {
        for pipe in &mut self.anon_pipes {
            if pipe.write_fd == write_fd
                && (pipe.writer_pid == Some(writer_pid) || pipe.creator_pid == writer_pid)
            {
                pipe.tainted = true;
                if let Some(reader) = pipe.reader_pid {
                    if reader != writer_pid {
                        self.events.push(IpcTaintEvent {
                            source_pid: writer_pid,
                            target_pid: reader,
                            channel: IpcChannel::AnonPipe {
                                read_fd: pipe.read_fd,
                                write_fd: pipe.write_fd,
                            },
                        });
                        return Some(reader);
                    }
                }
            }
        }
        None
    }

    /// Check if a path is a known IPC channel (named pipe or Unix socket).
    pub fn is_ipc_path(path: &Path) -> bool {
        let s = path.to_string_lossy();
        // Unix domain sockets
        s.ends_with(".sock")
            || s.ends_with(".socket")
            || s.contains("/tmp/")
                && (s.contains(".sock") || s.contains("socket") || s.contains("pipe"))
            // Common Unix socket locations
            || s.starts_with("/var/run/")
            || s.starts_with("/run/")
            // Windows named pipes
            || s.starts_with("\\\\.\\pipe\\")
            || s.starts_with("//./pipe/")
    }

    /// Check if a path is a Windows named pipe.
    pub fn is_windows_pipe(path: &str) -> bool {
        path.starts_with("\\\\.\\pipe\\") || path.starts_with("//./pipe/")
    }

    /// Clean up when a process exits.
    pub fn on_exit(&mut self, pid: i32) {
        for (_, pids) in self.writers.iter_mut() {
            pids.remove(&pid);
        }
        for (_, pids) in self.readers.iter_mut() {
            pids.remove(&pid);
        }
        // Clean up empty entries
        self.writers.retain(|_, pids| !pids.is_empty());
        self.readers.retain(|_, pids| !pids.is_empty());
        // Clean channels where no writers remain
        self.tainted_channels
            .retain(|path| self.writers.get(path).is_some_and(|pids| !pids.is_empty()));
        // Clean anonymous pipes
        self.anon_pipes
            .retain(|p| p.reader_pid != Some(pid) || p.writer_pid != Some(pid));
    }

    /// Drain IPC taint events for logging.
    pub fn drain_events(&mut self) -> Vec<IpcTaintEvent> {
        std::mem::take(&mut self.events)
    }
}

/// Heuristic: check if a path looks like a Unix domain socket.
fn is_unix_socket(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.ends_with(".sock") || s.ends_with(".socket") || s.contains("socket")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_pipe_taint_propagation() {
        let mut t = IpcTracker::new();
        let pipe = Path::new("/tmp/myfifo");

        // PID 200 opens the pipe for reading
        assert!(!t.on_ipc_read(200, pipe));

        // PID 100 (tainted) writes to the pipe
        let targets = t.on_ipc_write(100, pipe, true);
        assert_eq!(targets, vec![200]);
    }

    #[test]
    fn reader_joins_tainted_channel() {
        let mut t = IpcTracker::new();
        let pipe = Path::new("/tmp/myfifo");

        // PID 100 (tainted) writes first
        t.on_ipc_write(100, pipe, true);

        // PID 200 opens for reading — channel already tainted
        assert!(t.on_ipc_read(200, pipe));
    }

    #[test]
    fn clean_writer_no_propagation() {
        let mut t = IpcTracker::new();
        let pipe = Path::new("/tmp/myfifo");

        t.on_ipc_read(200, pipe);
        let targets = t.on_ipc_write(100, pipe, false);
        assert!(targets.is_empty());
    }

    #[test]
    fn unix_socket_detected() {
        assert!(IpcTracker::is_ipc_path(Path::new("/tmp/docker.sock")));
        assert!(IpcTracker::is_ipc_path(Path::new("/var/run/docker.sock")));
        assert!(IpcTracker::is_ipc_path(Path::new(
            "\\\\.\\pipe\\docker_engine"
        )));
        assert!(!IpcTracker::is_ipc_path(Path::new("/tmp/normal.txt")));
    }

    #[test]
    fn exit_cleanup() {
        let mut t = IpcTracker::new();
        let pipe = Path::new("/tmp/myfifo");

        t.on_ipc_write(100, pipe, true);
        t.on_ipc_read(200, pipe);
        t.on_exit(100);
        t.on_exit(200);

        // Channels should be cleaned up
        assert!(t.writers.is_empty() || t.writers.values().all(|v| v.is_empty()));
    }

    #[test]
    fn anon_pipe_taint() {
        let mut t = IpcTracker::new();

        // Process creates a pipe
        t.on_pipe_create(100, 3, 4);
        // Fork: child gets read end
        t.on_pipe_fork(100, 200);

        // Writer (parent) becomes tainted
        let reader = t.on_anon_pipe_taint(100, 4);
        assert_eq!(reader, Some(200));
    }

    #[test]
    fn events_tracked() {
        let mut t = IpcTracker::new();
        let pipe = Path::new("/tmp/myfifo");

        t.on_ipc_read(200, pipe);
        t.on_ipc_write(100, pipe, true);

        let events = t.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_pid, 100);
        assert_eq!(events[0].target_pid, 200);
    }
}
