// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Process tree tracking.
//!
//! Maintains parent-child relationships between processes
//! for taint propagation and debugging.

use std::collections::{HashMap, HashSet};

/// Tracks parent-child relationships in the process tree.
pub struct ProcessTree {
    /// PID → parent PID
    parents: HashMap<i32, i32>,
    /// PID → set of child PIDs
    children: HashMap<i32, HashSet<i32>>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            parents: HashMap::with_capacity(256),
            children: HashMap::with_capacity(256),
        }
    }

    /// Record a fork: parent spawned child.
    pub fn add_child(&mut self, parent: i32, child: i32) {
        self.parents.insert(child, parent);
        self.children.entry(parent).or_default().insert(child);
    }

    /// Remove a process from the tree (on exit).
    pub fn remove(&mut self, pid: i32) {
        // Remove from parent's children list
        if let Some(parent) = self.parents.remove(&pid) {
            if let Some(siblings) = self.children.get_mut(&parent) {
                siblings.remove(&pid);
                if siblings.is_empty() {
                    self.children.remove(&parent);
                }
            }
        }
        // Note: we don't remove children entries here —
        // orphaned children will clean up when they exit.
    }

    /// Get the parent of a process.
    pub fn parent_of(&self, pid: i32) -> Option<i32> {
        self.parents.get(&pid).copied()
    }

    /// Get all children of a process.
    pub fn children_of(&self, pid: i32) -> Option<&HashSet<i32>> {
        self.children.get(&pid)
    }

    /// Walk up the tree to find all ancestors.
    pub fn ancestors(&self, pid: i32) -> Vec<i32> {
        let mut result = Vec::new();
        let mut current = pid;
        // Safety: limit depth to prevent cycles
        for _ in 0..64 {
            match self.parents.get(&current) {
                Some(&parent) => {
                    result.push(parent);
                    current = parent;
                }
                None => break,
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_query() {
        let mut t = ProcessTree::new();
        t.add_child(1, 10);
        t.add_child(1, 11);
        t.add_child(10, 100);

        assert_eq!(t.parent_of(10), Some(1));
        assert_eq!(t.parent_of(100), Some(10));
        assert_eq!(t.parent_of(1), None);

        let kids = t.children_of(1).unwrap();
        assert!(kids.contains(&10));
        assert!(kids.contains(&11));
    }

    #[test]
    fn ancestors() {
        let mut t = ProcessTree::new();
        t.add_child(1, 10);
        t.add_child(10, 100);
        t.add_child(100, 1000);

        let anc = t.ancestors(1000);
        assert_eq!(anc, vec![100, 10, 1]);
    }

    #[test]
    fn remove_cleans_up() {
        let mut t = ProcessTree::new();
        t.add_child(1, 10);
        t.remove(10);
        assert_eq!(t.parent_of(10), None);
        assert!(t.children_of(1).is_none() || t.children_of(1).unwrap().is_empty());
    }
}
