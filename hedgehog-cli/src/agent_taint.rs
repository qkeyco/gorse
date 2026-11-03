// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Agent-to-agent taint propagation (W-09).
//!
//! When multiple AI agents are running (e.g., Claude Code + Copilot),
//! taint from one agent should propagate to others that read the same
//! files. This module tracks agent sessions and propagates taint
//! between them.
//!
//! Architecture:
//! - Each agent session is identified by (tool_name, session_id, pid)
//! - When one agent reads a tainted file, its PID becomes tainted
//! - If another agent's subprocess reads output from the first agent,
//!   taint propagates through the file system
//! - The taint engine handles file-level propagation; this module
//!   adds agent-session-level tracking for dashboard display

use std::collections::{HashMap, HashSet};

/// Tracks taint across AI agent sessions.
pub struct AgentTaintTracker {
    /// session_id → AgentSession
    sessions: HashMap<String, AgentSession>,
    /// PID → session_id mapping
    pid_sessions: HashMap<i32, String>,
    /// Taint propagation events between agents
    propagation_events: Vec<AgentPropagation>,
}

/// An active AI agent session.
#[derive(Debug, Clone)]
pub struct AgentSession {
    pub tool_name: String,
    pub session_id: String,
    pub pids: HashSet<i32>,
    pub tainted: bool,
    pub taint_source: Option<String>,
}

/// Record of taint propagating between agent sessions.
#[derive(Debug, Clone)]
pub struct AgentPropagation {
    pub source_agent: String,
    pub source_session: String,
    pub target_agent: String,
    pub target_session: String,
    pub via: String, // file path or mechanism
}

impl AgentTaintTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            pid_sessions: HashMap::new(),
            propagation_events: Vec::new(),
        }
    }

    /// Register an agent session (called when a hook check arrives).
    pub fn register_session(&mut self, tool_name: &str, session_id: &str, pid: i32) {
        let session = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| AgentSession {
                tool_name: tool_name.to_string(),
                session_id: session_id.to_string(),
                pids: HashSet::new(),
                tainted: false,
                taint_source: None,
            });
        session.pids.insert(pid);
        self.pid_sessions.insert(pid, session_id.to_string());
    }

    /// Mark a session as tainted (called when any of its PIDs becomes tainted).
    pub fn taint_session(&mut self, session_id: &str, source: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if !session.tainted {
                session.tainted = true;
                session.taint_source = Some(source.to_string());
            }
        }
    }

    /// Check if a PID belongs to a tainted session.
    pub fn is_pid_in_tainted_session(&self, pid: i32) -> bool {
        if let Some(session_id) = self.pid_sessions.get(&pid) {
            if let Some(session) = self.sessions.get(session_id) {
                return session.tainted;
            }
        }
        false
    }

    /// When a PID becomes tainted, check if it belongs to an agent session
    /// and propagate the taint to all PIDs in that session.
    /// Returns the list of other PIDs that should be tainted.
    pub fn on_pid_tainted(&mut self, pid: i32, source: &str) -> Vec<i32> {
        let session_id = match self.pid_sessions.get(&pid) {
            Some(id) => id.clone(),
            None => return Vec::new(),
        };

        self.taint_session(&session_id, source);

        // Return all other PIDs in this session
        if let Some(session) = self.sessions.get(&session_id) {
            session.pids.iter().copied().filter(|&p| p != pid).collect()
        } else {
            Vec::new()
        }
    }

    /// Record taint propagation between two agent sessions.
    pub fn record_propagation(
        &mut self,
        source_session_id: &str,
        target_session_id: &str,
        via: &str,
    ) {
        let source = self.sessions.get(source_session_id);
        let target = self.sessions.get(target_session_id);

        if let (Some(src), Some(tgt)) = (source, target) {
            self.propagation_events.push(AgentPropagation {
                source_agent: src.tool_name.clone(),
                source_session: src.session_id.clone(),
                target_agent: tgt.tool_name.clone(),
                target_session: tgt.session_id.clone(),
                via: via.to_string(),
            });
        }
    }

    /// Look up which session a PID belongs to.
    pub fn session_for_pid(&self, pid: i32) -> Option<&AgentSession> {
        let session_id = self.pid_sessions.get(&pid)?;
        self.sessions.get(session_id)
    }

    /// Get all active sessions.
    pub fn sessions(&self) -> impl Iterator<Item = &AgentSession> {
        self.sessions.values()
    }

    /// Get tainted sessions.
    pub fn tainted_sessions(&self) -> Vec<&AgentSession> {
        self.sessions.values().filter(|s| s.tainted).collect()
    }

    /// Drain propagation events for logging.
    pub fn drain_events(&mut self) -> Vec<AgentPropagation> {
        std::mem::take(&mut self.propagation_events)
    }

    /// Clean up when a process exits.
    pub fn on_exit(&mut self, pid: i32) {
        if let Some(session_id) = self.pid_sessions.remove(&pid) {
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.pids.remove(&pid);
                if session.pids.is_empty() {
                    self.sessions.remove(&session_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_taint() {
        let mut t = AgentTaintTracker::new();
        t.register_session("claude", "sess-1", 100);
        t.register_session("claude", "sess-1", 101);

        assert!(!t.is_pid_in_tainted_session(100));

        let others = t.on_pid_tainted(100, "/Users/test/.env");
        assert_eq!(others, vec![101]);
        assert!(t.is_pid_in_tainted_session(100));
        assert!(t.is_pid_in_tainted_session(101));
    }

    #[test]
    fn separate_sessions_independent() {
        let mut t = AgentTaintTracker::new();
        t.register_session("claude", "sess-1", 100);
        t.register_session("copilot", "sess-2", 200);

        t.on_pid_tainted(100, "test");
        assert!(t.is_pid_in_tainted_session(100));
        assert!(!t.is_pid_in_tainted_session(200));
    }

    #[test]
    fn exit_cleanup() {
        let mut t = AgentTaintTracker::new();
        t.register_session("claude", "sess-1", 100);
        t.register_session("claude", "sess-1", 101);

        t.on_exit(100);
        t.on_exit(101);

        // Session should be cleaned up
        assert_eq!(t.sessions().count(), 0);
    }

    #[test]
    fn propagation_recorded() {
        let mut t = AgentTaintTracker::new();
        t.register_session("claude", "sess-1", 100);
        t.register_session("copilot", "sess-2", 200);

        t.taint_session("sess-1", "test");
        t.record_propagation("sess-1", "sess-2", "/tmp/shared.txt");

        let events = t.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_agent, "claude");
        assert_eq!(events[0].target_agent, "copilot");
    }

    #[test]
    fn session_lookup() {
        let mut t = AgentTaintTracker::new();
        t.register_session("claude", "sess-1", 100);

        let session = t.session_for_pid(100).unwrap();
        assert_eq!(session.tool_name, "claude");
        assert_eq!(session.session_id, "sess-1");
    }
}
