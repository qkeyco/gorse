// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Event logging for the taint engine.
//!
//! Collects events in memory. The Swift host drains them periodically
//! and writes to disk / sends notifications.

use std::collections::VecDeque;

const MAX_RECENT_EVENTS: usize = 4096;

/// Type of taint event.
#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    /// A process was tainted (read a secret file).
    Tainted,
    /// A network connection was blocked.
    Blocked,
    /// Taint was propagated to a child process.
    Propagated,
    /// Taint was cleaned up (process exit or TTL expiry).
    Cleaned,
}

/// A single log entry.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub event: EventType,
    pub pid: i32,
    pub detail: String,
}

/// Bounded recent diagnostics. Durable alarms have a separate host outbox.
pub struct EventLogger {
    entries: VecDeque<LogEntry>,
}

impl EventLogger {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(64),
        }
    }

    pub fn log(&mut self, entry: LogEntry) {
        if self.entries.len() == MAX_RECENT_EVENTS {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Drain all entries, returning them and clearing the buffer.
    pub fn drain(&mut self) -> Vec<LogEntry> {
        self.entries.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_events_keep_a_bounded_recent_window() {
        let mut logger = EventLogger::new();
        for pid in 0..10_000 {
            logger.log(LogEntry {
                event: EventType::Tainted,
                pid,
                detail: "synthetic".into(),
            });
        }
        assert_eq!(logger.len(), MAX_RECENT_EVENTS);
        let recent = logger.drain();
        assert_eq!(
            recent.first().unwrap().pid,
            10_000 - MAX_RECENT_EVENTS as i32
        );
        assert_eq!(recent.last().unwrap().pid, 9999);
        assert!(logger.is_empty());
    }

    #[test]
    fn log_and_drain() {
        let mut l = EventLogger::new();
        l.log(LogEntry {
            event: EventType::Tainted,
            pid: 100,
            detail: "test".to_string(),
        });
        l.log(LogEntry {
            event: EventType::Blocked,
            pid: 100,
            detail: "test2".to_string(),
        });
        assert_eq!(l.len(), 2);

        let entries = l.drain();
        assert_eq!(entries.len(), 2);
        assert!(l.is_empty());
    }
}
