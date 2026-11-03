// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Localhost relay detection (v0.3).
//!
//! Tracks which processes listen on which local ports. When a tainted process
//! connects to localhost, the listening process inherits taint — closing the
//! "localhost relay" exfiltration vector.
//!
//! Also tracks existing socket file descriptors at the moment of taint,
//! so pre-existing connections to non-allowlisted hosts can be flagged.

use std::collections::{HashMap, HashSet};

/// A snapshot of a process's open sockets at the time it became tainted.
#[derive(Debug, Clone)]
pub struct FdSnapshot {
    pub pid: i32,
    /// Remote addresses of open sockets at time of taint.
    /// The Swift host reads these from /proc or lsof and reports them.
    pub open_sockets: Vec<SocketInfo>,
}

/// Information about an open socket.
#[derive(Debug, Clone)]
pub struct SocketInfo {
    pub fd: i32,
    pub remote_addr: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub socket_type: SocketType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Tcp,
    Udp,
    Unix,
}

/// Tracks localhost listeners and enables taint propagation through local relays.
pub struct LocalhostTracker {
    /// port → set of PIDs listening on that port
    listeners: HashMap<u16, HashSet<i32>>,
    /// PID → set of ports it's listening on
    pid_ports: HashMap<i32, HashSet<u16>>,
    /// FD snapshots for tainted processes (reported by Swift host)
    fd_snapshots: HashMap<i32, FdSnapshot>,
    /// PIDs that received taint via localhost relay (for audit trail)
    relay_taints: Vec<RelayTaintEvent>,
}

/// Record of taint propagation via localhost relay.
#[derive(Debug, Clone)]
pub struct RelayTaintEvent {
    pub source_pid: i32,
    pub target_pid: i32,
    pub port: u16,
}

impl LocalhostTracker {
    pub fn new() -> Self {
        Self {
            listeners: HashMap::with_capacity(64),
            pid_ports: HashMap::with_capacity(64),
            fd_snapshots: HashMap::new(),
            relay_taints: Vec::new(),
        }
    }

    /// Record that a process is listening on a port.
    /// Called from ESF ES_EVENT_TYPE_NOTIFY_LISTEN.
    pub fn on_listen(&mut self, pid: i32, port: u16) {
        self.listeners.entry(port).or_default().insert(pid);
        self.pid_ports.entry(pid).or_default().insert(port);
    }

    /// Record that a process stopped listening (closed socket or exited).
    pub fn on_unlisten(&mut self, pid: i32, port: u16) {
        if let Some(pids) = self.listeners.get_mut(&port) {
            pids.remove(&pid);
            if pids.is_empty() {
                self.listeners.remove(&port);
            }
        }
        if let Some(ports) = self.pid_ports.get_mut(&pid) {
            ports.remove(&port);
            if ports.is_empty() {
                self.pid_ports.remove(&pid);
            }
        }
    }

    /// A tainted process connected to localhost:port.
    /// Returns the PIDs of processes listening on that port (they should be tainted).
    pub fn on_localhost_connect(&mut self, source_pid: i32, port: u16) -> Vec<i32> {
        let listener_pids: Vec<i32> = self
            .listeners
            .get(&port)
            .map(|pids| {
                pids.iter()
                    .filter(|&&pid| pid != source_pid) // don't taint yourself
                    .copied()
                    .collect()
            })
            .unwrap_or_default();

        for &target_pid in &listener_pids {
            self.relay_taints.push(RelayTaintEvent {
                source_pid,
                target_pid,
                port,
            });
        }

        listener_pids
    }

    /// Clean up when a process exits.
    pub fn on_exit(&mut self, pid: i32) {
        if let Some(ports) = self.pid_ports.remove(&pid) {
            for port in ports {
                if let Some(pids) = self.listeners.get_mut(&port) {
                    pids.remove(&pid);
                    if pids.is_empty() {
                        self.listeners.remove(&port);
                    }
                }
            }
        }
        self.fd_snapshots.remove(&pid);
    }

    /// Store a file descriptor snapshot for a newly tainted process.
    /// The Swift host calls this after reading the process's open FDs.
    pub fn store_fd_snapshot(&mut self, snapshot: FdSnapshot) {
        self.fd_snapshots.insert(snapshot.pid, snapshot);
    }

    /// Get the FD snapshot for a tainted process.
    pub fn get_fd_snapshot(&self, pid: i32) -> Option<&FdSnapshot> {
        self.fd_snapshots.get(&pid)
    }

    /// Get all PIDs listening on a specific port.
    pub fn listeners_on(&self, port: u16) -> Option<&HashSet<i32>> {
        self.listeners.get(&port)
    }

    /// Get all ports a process is listening on.
    pub fn ports_for(&self, pid: i32) -> Option<&HashSet<u16>> {
        self.pid_ports.get(&pid)
    }

    /// Get relay taint events (for audit logging).
    pub fn drain_relay_events(&mut self) -> Vec<RelayTaintEvent> {
        std::mem::take(&mut self.relay_taints)
    }

    // ─── T-09: Enhanced FD enumeration ───

    /// Enumerate open file descriptors for a process.
    /// Returns a snapshot of all open sockets. Platform-specific.
    #[cfg(target_os = "macos")]
    pub fn enumerate_fds(pid: i32) -> Vec<SocketInfo> {
        // On macOS, use lsof -nP -p <pid> -i to list network connections.
        // This is called by the Swift host or CLI when a process becomes tainted.
        let output = std::process::Command::new("lsof")
            .args(["-nP", "-p", &pid.to_string(), "-i"])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                parse_lsof_output(&stdout)
            }
            Err(_) => Vec::new(),
        }
    }

    /// Enumerate open file descriptors for a process (Linux).
    #[cfg(target_os = "linux")]
    pub fn enumerate_fds(pid: i32) -> Vec<SocketInfo> {
        // On Linux, read /proc/<pid>/net/tcp and /proc/<pid>/fd
        let mut sockets = Vec::new();

        // Read /proc/net/tcp for this process's connections
        let tcp_path = format!("/proc/{}/net/tcp", pid);
        if let Ok(contents) = std::fs::read_to_string(&tcp_path) {
            for line in contents.lines().skip(1) {
                if let Some(sock) = parse_proc_tcp_line(line, pid) {
                    sockets.push(sock);
                }
            }
        }

        // Also check /proc/net/tcp6
        let tcp6_path = format!("/proc/{}/net/tcp6", pid);
        if let Ok(contents) = std::fs::read_to_string(&tcp6_path) {
            for line in contents.lines().skip(1) {
                if let Some(sock) = parse_proc_tcp_line(line, pid) {
                    sockets.push(sock);
                }
            }
        }

        sockets
    }

    /// Enumerate open file descriptors for a process (Windows stub).
    #[cfg(windows)]
    pub fn enumerate_fds(pid: i32) -> Vec<SocketInfo> {
        // On Windows, use netstat or GetExtendedTcpTable API.
        // Stub: the Windows daemon handles this via ETW events.
        let _ = pid;
        Vec::new()
    }

    /// Enumerate open file descriptors (unsupported platform fallback).
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    pub fn enumerate_fds(pid: i32) -> Vec<SocketInfo> {
        let _ = pid;
        Vec::new()
    }
}

/// Parse lsof -nP -i output into SocketInfo entries.
#[cfg(target_os = "macos")]
fn parse_lsof_output(output: &str) -> Vec<SocketInfo> {
    let mut sockets = Vec::new();
    for line in output.lines().skip(1) {
        // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let fd_str = parts[3].trim_end_matches(|c: char| !c.is_ascii_digit());
        let fd = fd_str.parse::<i32>().unwrap_or(-1);
        let name = parts[8]; // e.g., "192.168.1.1:443->10.0.0.1:54321"

        if let Some((remote, local_port)) = parse_lsof_connection(name) {
            sockets.push(SocketInfo {
                fd,
                remote_addr: remote.0,
                remote_port: remote.1,
                local_port,
                socket_type: if parts[4] == "IPv6" {
                    SocketType::Tcp
                } else {
                    SocketType::Tcp
                },
            });
        }
    }
    sockets
}

/// Parse a lsof connection string like "host:port->remote:port".
#[cfg(target_os = "macos")]
fn parse_lsof_connection(name: &str) -> Option<((String, u16), u16)> {
    let arrow = name.find("->")?;
    let local = &name[..arrow];
    let remote = &name[arrow + 2..];

    let local_port = local.rsplit(':').next()?.parse::<u16>().ok()?;
    let last_colon = remote.rfind(':')?;
    let remote_addr = remote[..last_colon].to_string();
    let remote_port = remote[last_colon + 1..].parse::<u16>().ok()?;

    Some(((remote_addr, remote_port), local_port))
}

/// Parse a /proc/net/tcp line into a SocketInfo.
#[cfg(target_os = "linux")]
fn parse_proc_tcp_line(line: &str, pid: i32) -> Option<SocketInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    // Format: sl local_address rem_address st ...
    // Addresses are hex: AABBCCDD:PORT
    let local = parse_hex_addr(parts[1])?;
    let remote = parse_hex_addr(parts[2])?;

    // Skip connections with remote 0.0.0.0:0 (listening)
    if remote.1 == 0 {
        return None;
    }

    Some(SocketInfo {
        fd: -1, // /proc/net/tcp doesn't give us the FD directly
        remote_addr: remote.0,
        remote_port: remote.1,
        local_port: local.1,
        socket_type: SocketType::Tcp,
    })
}

/// Parse a hex address like "0100007F:1F90" into ("127.0.0.1", 8080).
#[cfg(target_os = "linux")]
fn parse_hex_addr(s: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr_int = u32::from_str_radix(addr_hex, 16).ok()?;
    // /proc/net/tcp stores addresses in little-endian
    let addr = format!(
        "{}.{}.{}.{}",
        addr_int & 0xFF,
        (addr_int >> 8) & 0xFF,
        (addr_int >> 16) & 0xFF,
        (addr_int >> 24) & 0xFF
    );
    Some((addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_and_query() {
        let mut t = LocalhostTracker::new();
        t.on_listen(100, 8080);
        t.on_listen(101, 3000);
        t.on_listen(102, 8080); // two processes on same port

        assert!(t.listeners_on(8080).unwrap().contains(&100));
        assert!(t.listeners_on(8080).unwrap().contains(&102));
        assert!(t.listeners_on(3000).unwrap().contains(&101));
        assert!(t.listeners_on(9999).is_none());

        assert!(t.ports_for(100).unwrap().contains(&8080));
    }

    #[test]
    fn localhost_connect_propagates() {
        let mut t = LocalhostTracker::new();
        t.on_listen(200, 9999); // proxy listening

        // Tainted process connects to localhost:9999
        let targets = t.on_localhost_connect(100, 9999);
        assert_eq!(targets, vec![200]);

        // Audit trail
        let events = t.drain_relay_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_pid, 100);
        assert_eq!(events[0].target_pid, 200);
        assert_eq!(events[0].port, 9999);
    }

    #[test]
    fn no_self_taint() {
        let mut t = LocalhostTracker::new();
        t.on_listen(100, 8080);
        // Process connects to its own listener
        let targets = t.on_localhost_connect(100, 8080);
        assert!(targets.is_empty());
    }

    #[test]
    fn no_listener_returns_empty() {
        let mut t = LocalhostTracker::new();
        let targets = t.on_localhost_connect(100, 9999);
        assert!(targets.is_empty());
    }

    #[test]
    fn unlisten_removes() {
        let mut t = LocalhostTracker::new();
        t.on_listen(100, 8080);
        t.on_unlisten(100, 8080);
        assert!(t.listeners_on(8080).is_none());
        assert!(t.ports_for(100).is_none());
    }

    #[test]
    fn exit_cleans_up() {
        let mut t = LocalhostTracker::new();
        t.on_listen(100, 8080);
        t.on_listen(100, 3000);
        t.on_exit(100);
        assert!(t.listeners_on(8080).is_none());
        assert!(t.listeners_on(3000).is_none());
        assert!(t.ports_for(100).is_none());
    }

    #[test]
    fn fd_snapshot_storage() {
        let mut t = LocalhostTracker::new();
        t.store_fd_snapshot(FdSnapshot {
            pid: 100,
            open_sockets: vec![SocketInfo {
                fd: 5,
                remote_addr: "evil.com".to_string(),
                remote_port: 443,
                local_port: 54321,
                socket_type: SocketType::Tcp,
            }],
        });

        let snap = t.get_fd_snapshot(100).unwrap();
        assert_eq!(snap.open_sockets.len(), 1);
        assert_eq!(snap.open_sockets[0].remote_addr, "evil.com");
    }

    #[test]
    fn multiple_listeners_same_port() {
        let mut t = LocalhostTracker::new();
        t.on_listen(200, 8080);
        t.on_listen(201, 8080);

        let mut targets = t.on_localhost_connect(100, 8080);
        targets.sort();
        assert_eq!(targets, vec![200, 201]);
    }
}
