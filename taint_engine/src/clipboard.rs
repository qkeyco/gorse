// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Clipboard monitoring (v0.7).
//!
//! Tracks clipboard access from tainted processes. When a tainted process
//! writes to the clipboard (pbcopy, xclip, SetClipboardData), the clipboard
//! content is considered tainted. If a non-tainted process subsequently
//! reads the clipboard, it may receive tainted data — but we don't taint
//! the reader automatically (too many false positives). Instead, we flag
//! clipboard writes from tainted processes for audit.

use std::time::Instant;

/// Clipboard state tracking.
pub struct ClipboardTracker {
    /// Current clipboard taint state: (writing PID, timestamp, content hash).
    tainted_clipboard: Option<ClipboardTaint>,
    /// Audit trail of clipboard events.
    events: Vec<ClipboardEvent>,
}

/// Represents tainted clipboard content.
#[derive(Debug, Clone)]
pub struct ClipboardTaint {
    /// PID that wrote to the clipboard.
    pub writer_pid: i32,
    /// When the clipboard was written.
    pub written_at: Instant,
    /// Hash of the content (we never store actual content).
    pub content_hash: u64,
}

/// A clipboard access event for audit logging.
#[derive(Debug, Clone)]
pub struct ClipboardEvent {
    pub pid: i32,
    pub action: ClipboardAction,
    pub was_tainted: bool,
    pub timestamp: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardAction {
    /// Process wrote to clipboard (pbcopy, xclip, SetClipboardData).
    Write,
    /// Process read from clipboard (pbpaste, xsel, GetClipboardData).
    Read,
}

impl ClipboardTracker {
    pub fn new() -> Self {
        Self {
            tainted_clipboard: None,
            events: Vec::new(),
        }
    }

    /// A process wrote to the clipboard.
    /// If the process is tainted, marks the clipboard as tainted.
    /// Returns true if the clipboard became tainted.
    pub fn on_clipboard_write(&mut self, pid: i32, is_tainted: bool, content_hash: u64) -> bool {
        self.events.push(ClipboardEvent {
            pid,
            action: ClipboardAction::Write,
            was_tainted: is_tainted,
            timestamp: Instant::now(),
        });

        if is_tainted {
            self.tainted_clipboard = Some(ClipboardTaint {
                writer_pid: pid,
                written_at: Instant::now(),
                content_hash,
            });
            true
        } else {
            // Non-tainted write clears any previous taint
            self.tainted_clipboard = None;
            false
        }
    }

    /// A process read from the clipboard.
    /// Returns true if the clipboard is currently tainted (for audit/warning).
    pub fn on_clipboard_read(&mut self, pid: i32) -> bool {
        let is_tainted = self.tainted_clipboard.is_some();
        self.events.push(ClipboardEvent {
            pid,
            action: ClipboardAction::Read,
            was_tainted: is_tainted,
            timestamp: Instant::now(),
        });
        is_tainted
    }

    /// Check if the clipboard is currently tainted.
    pub fn is_clipboard_tainted(&self) -> bool {
        self.tainted_clipboard.is_some()
    }

    /// Get the current clipboard taint info.
    pub fn clipboard_taint(&self) -> Option<&ClipboardTaint> {
        self.tainted_clipboard.as_ref()
    }

    /// Drain clipboard events for logging.
    pub fn drain_events(&mut self) -> Vec<ClipboardEvent> {
        std::mem::take(&mut self.events)
    }

    /// Clean up on process exit (if the writing process exits, taint remains
    /// until overwritten by a non-tainted process).
    pub fn on_exit(&mut self, _pid: i32) {
        // Clipboard taint persists even after the writer exits.
        // It's only cleared when a non-tainted process writes new content.
    }
}

/// Known clipboard command patterns (for detecting clipboard access via exec).
pub fn is_clipboard_write_command(command: &str) -> bool {
    let cmd = command.trim();
    // macOS
    if cmd.starts_with("pbcopy") || cmd.contains("| pbcopy") || cmd.contains("|pbcopy") {
        return true;
    }
    // Linux X11
    if cmd.starts_with("xclip") && (cmd.contains("-selection") || cmd.contains("-sel")) {
        return true;
    }
    if cmd.starts_with("xsel") && cmd.contains("--clipboard") {
        return true;
    }
    // Linux Wayland
    if cmd.starts_with("wl-copy") {
        return true;
    }
    false
}

/// Known clipboard read patterns.
pub fn is_clipboard_read_command(command: &str) -> bool {
    let cmd = command.trim();
    if cmd.starts_with("pbpaste") || cmd.contains("$(pbpaste)") {
        return true;
    }
    if cmd.starts_with("xclip") && cmd.contains("-o") {
        return true;
    }
    if cmd.starts_with("xsel") && cmd.contains("--output") {
        return true;
    }
    if cmd.starts_with("wl-paste") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tainted_write_marks_clipboard() {
        let mut t = ClipboardTracker::new();
        assert!(t.on_clipboard_write(100, true, 12345));
        assert!(t.is_clipboard_tainted());
        assert_eq!(t.clipboard_taint().unwrap().writer_pid, 100);
    }

    #[test]
    fn clean_write_clears_taint() {
        let mut t = ClipboardTracker::new();
        t.on_clipboard_write(100, true, 12345);
        assert!(t.is_clipboard_tainted());
        t.on_clipboard_write(200, false, 67890);
        assert!(!t.is_clipboard_tainted());
    }

    #[test]
    fn read_detects_tainted_clipboard() {
        let mut t = ClipboardTracker::new();
        t.on_clipboard_write(100, true, 12345);
        assert!(t.on_clipboard_read(200));
    }

    #[test]
    fn read_clean_clipboard() {
        let mut t = ClipboardTracker::new();
        assert!(!t.on_clipboard_read(200));
    }

    #[test]
    fn clipboard_commands_detected() {
        assert!(is_clipboard_write_command("pbcopy"));
        assert!(is_clipboard_write_command("cat file | pbcopy"));
        assert!(is_clipboard_write_command("xclip -selection clipboard"));
        assert!(is_clipboard_write_command("wl-copy"));
        assert!(!is_clipboard_write_command("echo hello"));

        assert!(is_clipboard_read_command("pbpaste"));
        assert!(is_clipboard_read_command("xclip -o"));
        assert!(is_clipboard_read_command("wl-paste"));
        assert!(!is_clipboard_read_command("echo hello"));
    }

    #[test]
    fn events_tracked() {
        let mut t = ClipboardTracker::new();
        t.on_clipboard_write(100, true, 1);
        t.on_clipboard_read(200);
        let events = t.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, ClipboardAction::Write);
        assert_eq!(events[1].action, ClipboardAction::Read);
    }
}
