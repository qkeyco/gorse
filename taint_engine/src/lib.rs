// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Gorse Taint Engine
//!
//! Core taint tracking library with C FFI for Swift interop.
//! Tracks which processes read secret files, propagates taint through
//! process trees, and blocks network connections from tainted processes
//! to non-allowlisted destinations.
//!
//! ## Version History
//! - v0.1: Core taint tracking (file open → taint → block connect)
//! - v0.2: DNS exfiltration mitigation (resolver restriction)
//! - v0.3: Localhost relay detection + FD enumeration on taint
//! - v0.4: Per-project allowlist scoping
//! - v0.5: Write taint propagation (derived secrets)
//! - v0.6: Secret provider endpoint taint (Vault, AWS, 1Password, etc.)
//! - v0.7: Container path resolution + mount mapping
//! - v0.8: Clipboard monitoring, IPC/pipe taint propagation
//!
//! Zero external dependencies. All std library.

pub mod allowlist;
pub mod authority;
pub mod clipboard;
pub mod container;
pub mod content_patterns;
pub mod derived;
mod ffi;
pub mod ipc;
pub mod localhost;
pub mod logger;
pub mod process_tree;
pub mod project;
pub mod secret_providers;
pub mod secrets;
pub mod taint;
pub mod tier;

pub use allowlist::Allowlist;
pub use clipboard::{ClipboardAction, ClipboardEvent, ClipboardTracker};
pub use container::{ContainerPathResolver, MountMapping};
pub use content_patterns::{Confidence, ContentFinding, ContentSecretType, LineContext, Severity};
pub use derived::{DerivedSecretInfo, DerivedSecretTracker};
pub use ipc::{IpcChannel, IpcTaintEvent, IpcTracker};
pub use localhost::{FdSnapshot, LocalhostTracker, SocketInfo, SocketType};
pub use logger::{EventLogger, EventType, LogEntry};
pub use process_tree::ProcessTree;
pub use project::{ProjectConfig, ProjectRegistry};
pub use secret_providers::{SecretProviderMatch, SecretProviderRegistry};
pub use secrets::SecretDetector;
pub use taint::{Decision, TaintEngine, TaintInfo};
pub use tier::{License, Tier, TierLimits};

// Re-export FFI functions
pub use ffi::*;
