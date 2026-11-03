// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Permission graph: who can reach what, through which credential, and
//! what authority each hop actually grants.
//!
//! Nodes are things (the laptop, identities, credentials, roles, systems,
//! signers, wallets, assets). Edges are capabilities with evidence, scope,
//! assurance and any approval condition that gates them. Path analysis
//! never assumes reachability equals authority: the outcome of a path is
//! decided by the weakest hop and by every approval gate along it.

use super::Assurance;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    Laptop,
    Identity,
    Credential,
    CloudRole,
    CiSystem,
    Repository,
    Registry,
    Cluster,
    Workload,
    ProductionService,
    SecretsManager,
    /// HSM, MPC, custody or other signing service.
    Signer,
    Wallet,
    FinancialAsset,
    Other,
}

impl NodeKind {
    pub fn label(&self) -> &'static str {
        match self {
            NodeKind::Laptop => "laptop",
            NodeKind::Identity => "identity",
            NodeKind::Credential => "credential",
            NodeKind::CloudRole => "cloud role",
            NodeKind::CiSystem => "CI/CD system",
            NodeKind::Repository => "repository",
            NodeKind::Registry => "container registry",
            NodeKind::Cluster => "Kubernetes cluster",
            NodeKind::Workload => "workload",
            NodeKind::ProductionService => "production service",
            NodeKind::SecretsManager => "secrets manager",
            NodeKind::Signer => "signing service",
            NodeKind::Wallet => "wallet",
            NodeKind::FinancialAsset => "financial asset",
            NodeKind::Other => "system",
        }
    }
    pub fn is_financial(&self) -> bool {
        matches!(
            self,
            NodeKind::Signer | NodeKind::Wallet | NodeKind::FinancialAsset
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub name: String,
    /// Whether this is production (as declared or inferred).
    pub production: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EdgeKind {
    /// Network reachability only; grants nothing by itself.
    CanReach,
    CanAuthenticate,
    CanAssumeRole,
    CanReadSecret,
    CanPushCode,
    CanDeploy,
    CanModifyConfiguration,
    CanCreateCredential,
    CanRequestSignature,
    CanApproveTransaction,
    CanChangeSigningPolicy,
    CanInstallDelegation,
    CanTransferAssets,
}

impl EdgeKind {
    pub fn label(&self) -> &'static str {
        match self {
            EdgeKind::CanReach => "CAN_REACH",
            EdgeKind::CanAuthenticate => "CAN_AUTHENTICATE",
            EdgeKind::CanAssumeRole => "CAN_ASSUME_ROLE",
            EdgeKind::CanReadSecret => "CAN_READ_SECRET",
            EdgeKind::CanPushCode => "CAN_PUSH_CODE",
            EdgeKind::CanDeploy => "CAN_DEPLOY",
            EdgeKind::CanModifyConfiguration => "CAN_MODIFY_CONFIGURATION",
            EdgeKind::CanCreateCredential => "CAN_CREATE_CREDENTIAL",
            EdgeKind::CanRequestSignature => "CAN_REQUEST_SIGNATURE",
            EdgeKind::CanApproveTransaction => "CAN_APPROVE_TRANSACTION",
            EdgeKind::CanChangeSigningPolicy => "CAN_CHANGE_SIGNING_POLICY",
            EdgeKind::CanInstallDelegation => "CAN_INSTALL_DELEGATION",
            EdgeKind::CanTransferAssets => "CAN_TRANSFER_ASSETS",
        }
    }
    pub fn plain(&self) -> &'static str {
        match self {
            EdgeKind::CanReach => "can reach",
            EdgeKind::CanAuthenticate => "can log in to",
            EdgeKind::CanAssumeRole => "can assume",
            EdgeKind::CanReadSecret => "can read secrets from",
            EdgeKind::CanPushCode => "can push code to",
            EdgeKind::CanDeploy => "can deploy to",
            EdgeKind::CanModifyConfiguration => "can change configuration of",
            EdgeKind::CanCreateCredential => "can create credentials in",
            EdgeKind::CanRequestSignature => "can request signatures from",
            EdgeKind::CanApproveTransaction => "can approve transactions on",
            EdgeKind::CanChangeSigningPolicy => "can change signing policy of",
            EdgeKind::CanInstallDelegation => "can install delegation on",
            EdgeKind::CanTransferAssets => "can transfer assets from",
        }
    }
    /// Edges that move or authorise money or change who may.
    pub fn is_financial_authority(&self) -> bool {
        matches!(
            self,
            EdgeKind::CanApproveTransaction
                | EdgeKind::CanChangeSigningPolicy
                | EdgeKind::CanInstallDelegation
                | EdgeKind::CanTransferAssets
        )
    }
    /// Edges that change infrastructure rather than observe it.
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            EdgeKind::CanReach | EdgeKind::CanAuthenticate | EdgeKind::CanReadSecret
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    pub assurance: Assurance,
    /// What the capability is limited to (namespace, repo, policy, chain).
    pub scope: Option<String>,
    /// Why we believe this edge exists. Never secret material.
    pub evidence: Vec<String>,
    /// An approval that must come from somewhere other than this path
    /// (second signer, MFA prompt, PR review, HSM policy). None = ungated.
    pub requires_approval: Option<String>,
}

/// The strongest thing a path lets an attacker do. The order matters:
/// later variants strictly imply more authority than earlier ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathOutcome {
    /// Holds a credential but no established use for it.
    Possession,
    /// Can connect to the system; nothing more shown.
    Reachability,
    /// Can read data or secrets.
    Read,
    /// Can change infrastructure, code or configuration.
    Modify,
    /// Can ask a signer to sign; approval still sits elsewhere.
    RequestSignature,
    /// Can approve a signature or transaction.
    ApproveSignature,
    /// Can move funds or install authority that moves funds.
    MoveFunds,
}

impl PathOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            PathOutcome::Possession => "possession of credential",
            PathOutcome::Reachability => "network reachability only",
            PathOutcome::Read => "read access",
            PathOutcome::Modify => "can modify infrastructure",
            PathOutcome::RequestSignature => "can request a signature (approval elsewhere)",
            PathOutcome::ApproveSignature => "can approve a signature",
            PathOutcome::MoveFunds => "can move funds",
        }
    }
    pub fn key(&self) -> &'static str {
        match self {
            PathOutcome::Possession => "possession",
            PathOutcome::Reachability => "reachability",
            PathOutcome::Read => "read",
            PathOutcome::Modify => "modify",
            PathOutcome::RequestSignature => "request_signature",
            PathOutcome::ApproveSignature => "approve_signature",
            PathOutcome::MoveFunds => "move_funds",
        }
    }
}

/// A concrete multi-hop path from a start node to a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackPath {
    pub nodes: Vec<NodeId>,
    /// Indices into `PermissionGraph::edges`, one per hop.
    pub edges: Vec<usize>,
    /// Weakest assurance along the path.
    pub assurance: Assurance,
    /// Every approval gate an attacker would still have to pass.
    pub approvals_required: Vec<String>,
    pub outcome: PathOutcome,
}

impl AttackPath {
    pub fn hops(&self) -> usize {
        self.edges.len()
    }
    pub fn is_gated(&self) -> bool {
        !self.approvals_required.is_empty()
    }
    pub fn target(&self) -> NodeId {
        *self.nodes.last().expect("path has at least the start node")
    }
}

/// Result of the compromised-laptop simulation.
#[derive(Debug, Clone, Default)]
pub struct Reachability {
    /// Best path to each reachable node (strongest outcome, then fewest
    /// gates, then strongest assurance, then shortest).
    pub best_paths: BTreeMap<NodeId, AttackPath>,
}

impl Reachability {
    pub fn reachable(&self) -> usize {
        self.best_paths.len()
    }
    pub fn with_outcome(&self, min: PathOutcome) -> Vec<&AttackPath> {
        self.best_paths
            .values()
            .filter(|p| p.outcome >= min)
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PermissionGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    by_name: BTreeMap<(String, String), NodeId>,
}

impl PermissionGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node, or return the existing node with the same kind and name.
    pub fn node(&mut self, kind: NodeKind, name: &str) -> NodeId {
        let key = (format!("{kind:?}"), name.to_string());
        if let Some(id) = self.by_name.get(&key) {
            return *id;
        }
        let id = NodeId(self.nodes.len());
        self.nodes.push(Node {
            id,
            kind,
            name: name.to_string(),
            production: false,
            notes: Vec::new(),
        });
        self.by_name.insert(key, id);
        id
    }

    pub fn mark_production(&mut self, id: NodeId) {
        if let Some(n) = self.nodes.get_mut(id.0) {
            n.production = true;
        }
    }

    pub fn note(&mut self, id: NodeId, note: &str) {
        if let Some(n) = self.nodes.get_mut(id.0) {
            n.notes.push(super::redact_text(note));
        }
    }

    pub fn get(&self, id: NodeId) -> &Node {
        &self.nodes[id.0]
    }

    pub fn find(&self, kind: NodeKind, name: &str) -> Option<NodeId> {
        self.by_name
            .get(&(format!("{kind:?}"), name.to_string()))
            .copied()
    }

    /// Add an edge. Evidence strings are redacted on the way in.
    pub fn edge(
        &mut self,
        from: NodeId,
        to: NodeId,
        kind: EdgeKind,
        assurance: Assurance,
    ) -> usize {
        self.edge_full(from, to, kind, assurance, None, Vec::new(), None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn edge_full(
        &mut self,
        from: NodeId,
        to: NodeId,
        kind: EdgeKind,
        assurance: Assurance,
        scope: Option<String>,
        evidence: Vec<String>,
        requires_approval: Option<String>,
    ) -> usize {
        // A blank approval string is "no gate", never a gate with no name:
        // an empty `change_approval = ""` must not soften a path.
        let requires_approval = requires_approval.filter(|a| !a.trim().is_empty());
        // Deduplicate identical (from, to, kind): keep the stronger assurance,
        // merge evidence, keep the approval requirement if both have one.
        if let Some((i, existing)) = self
            .edges
            .iter_mut()
            .enumerate()
            .find(|(_, e)| e.from == from && e.to == to && e.kind == kind)
        {
            if assurance < existing.assurance {
                existing.assurance = assurance;
            }
            for ev in evidence {
                let ev = super::redact_text(&ev);
                if !existing.evidence.contains(&ev) {
                    existing.evidence.push(ev);
                }
            }
            if existing.scope.is_none() {
                existing.scope = scope;
            }
            if requires_approval.is_none() {
                existing.requires_approval = None;
            }
            return i;
        }
        self.edges.push(Edge {
            from,
            to,
            kind,
            assurance,
            scope,
            evidence: evidence.iter().map(|e| super::redact_text(e)).collect(),
            requires_approval,
        });
        self.edges.len() - 1
    }

    pub fn edges_from(&self, id: NodeId) -> impl Iterator<Item = (usize, &Edge)> {
        self.edges
            .iter()
            .enumerate()
            .filter(move |(_, e)| e.from == id)
    }

    pub fn nodes_of_kind(&self, kind: NodeKind) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|n| n.kind == kind)
            .map(|n| n.id)
            .collect()
    }

    fn outcome_of(&self, edge_indices: &[usize]) -> PathOutcome {
        let mut strongest = PathOutcome::Possession;
        for &i in edge_indices {
            let edge = &self.edges[i];
            let o = match edge.kind {
                EdgeKind::CanReach => PathOutcome::Reachability,
                EdgeKind::CanAuthenticate | EdgeKind::CanAssumeRole => PathOutcome::Reachability,
                EdgeKind::CanReadSecret => PathOutcome::Read,
                EdgeKind::CanPushCode
                | EdgeKind::CanDeploy
                | EdgeKind::CanModifyConfiguration
                | EdgeKind::CanCreateCredential => PathOutcome::Modify,
                EdgeKind::CanRequestSignature => PathOutcome::RequestSignature,
                EdgeKind::CanApproveTransaction => PathOutcome::ApproveSignature,
                EdgeKind::CanChangeSigningPolicy
                | EdgeKind::CanInstallDelegation
                | EdgeKind::CanTransferAssets => PathOutcome::MoveFunds,
            };
            if o > strongest {
                strongest = o;
            }
        }
        // The final hop decides what you get at the target; but an earlier
        // hop may already have conferred more (e.g. a role that can deploy
        // before reaching a read-only service). Report the strongest, with
        // one exception: a path whose last hop is RequestSignature does not
        // become ApproveSignature merely because approval exists elsewhere.
        strongest
    }

    fn build_path(&self, nodes: Vec<NodeId>, edges: Vec<usize>) -> AttackPath {
        let mut assurance = Assurance::Confirmed;
        let mut approvals = Vec::new();
        for &i in &edges {
            let e = &self.edges[i];
            assurance = assurance.weakest(e.assurance);
            if let Some(a) = &e.requires_approval {
                if !approvals.contains(a) {
                    approvals.push(a.clone());
                }
            }
        }
        if edges.is_empty() {
            assurance = Assurance::Confirmed;
        }
        let outcome = self.outcome_of(&edges);
        AttackPath {
            nodes,
            edges,
            assurance,
            approvals_required: approvals,
            outcome,
        }
    }

    /// All simple paths (no repeated node, so cycles terminate) from `from`
    /// to `to` of at most `max_hops` hops.
    pub fn paths_between(&self, from: NodeId, to: NodeId, max_hops: usize) -> Vec<AttackPath> {
        let mut out = Vec::new();
        let mut stack_nodes = vec![from];
        let mut stack_edges: Vec<usize> = Vec::new();
        let mut visited: BTreeSet<NodeId> = BTreeSet::new();
        visited.insert(from);
        self.dfs(
            to,
            max_hops,
            &mut stack_nodes,
            &mut stack_edges,
            &mut visited,
            &mut out,
        );
        out
    }

    fn dfs(
        &self,
        target: NodeId,
        max_hops: usize,
        nodes: &mut Vec<NodeId>,
        edges: &mut Vec<usize>,
        visited: &mut BTreeSet<NodeId>,
        out: &mut Vec<AttackPath>,
    ) {
        if out.len() >= 10_000 {
            return; // Hard cap: a dense graph should not hang the scanner.
        }
        let current = *nodes.last().unwrap();
        if current == target && !edges.is_empty() {
            out.push(self.build_path(nodes.clone(), edges.clone()));
            return;
        }
        if edges.len() >= max_hops {
            return;
        }
        for (i, e) in self.edges_from(current) {
            if visited.contains(&e.to) {
                continue;
            }
            visited.insert(e.to);
            nodes.push(e.to);
            edges.push(i);
            self.dfs(target, max_hops, nodes, edges, visited, out);
            edges.pop();
            nodes.pop();
            visited.remove(&e.to);
        }
    }

    /// Every simple path from `from` that ends on a node of `kind`.
    pub fn paths_to_kind(&self, from: NodeId, kind: NodeKind, max_hops: usize) -> Vec<AttackPath> {
        let mut all = Vec::new();
        for target in self.nodes_of_kind(kind) {
            if target != from {
                all.extend(self.paths_between(from, target, max_hops));
            }
        }
        all.sort_by(|a, b| Self::rank(b).cmp(&Self::rank(a)));
        all
    }

    /// Ranking key: stronger outcome, fewer gates, stronger assurance,
    /// shorter path. Higher is "worse for the defender".
    fn rank(
        p: &AttackPath,
    ) -> (
        PathOutcome,
        std::cmp::Reverse<usize>,
        std::cmp::Reverse<u8>,
        std::cmp::Reverse<usize>,
    ) {
        let assurance_rank = match p.assurance {
            Assurance::Confirmed => 0,
            Assurance::Inferred => 1,
            Assurance::Unknown => 2,
        };
        (
            p.outcome,
            std::cmp::Reverse(p.approvals_required.len()),
            std::cmp::Reverse(assurance_rank),
            std::cmp::Reverse(p.hops()),
        )
    }

    /// Compromised-laptop simulation: starting from `start`, compute the
    /// best path to every reachable node using only edges that exist in the
    /// graph. Nothing is exercised; this is pure graph traversal.
    ///
    /// Breadth-first over all simple paths up to `max_hops`, keeping the
    /// highest-ranked path per node.
    pub fn reachability(&self, start: NodeId, max_hops: usize) -> Reachability {
        let mut result = Reachability::default();
        let mut queue: VecDeque<(Vec<NodeId>, Vec<usize>)> = VecDeque::new();
        queue.push_back((vec![start], Vec::new()));
        let mut expansions = 0usize;
        while let Some((nodes, edges)) = queue.pop_front() {
            expansions += 1;
            if expansions > 200_000 {
                break;
            }
            let current = *nodes.last().unwrap();
            if !edges.is_empty() {
                let path = self.build_path(nodes.clone(), edges.clone());
                let better = match result.best_paths.get(&current) {
                    None => true,
                    Some(existing) => Self::rank(&path) > Self::rank(existing),
                };
                if better {
                    result.best_paths.insert(current, path);
                }
            }
            if edges.len() >= max_hops {
                continue;
            }
            for (i, e) in self.edges_from(current) {
                if nodes.contains(&e.to) {
                    continue; // cycle
                }
                let mut n = nodes.clone();
                n.push(e.to);
                let mut es = edges.clone();
                es.push(i);
                queue.push_back((n, es));
            }
        }
        result
    }

    /// Human-readable rendering of a path: "laptop → AWS key → role → signer".
    pub fn describe(&self, path: &AttackPath) -> String {
        let mut s = String::new();
        for (i, node) in path.nodes.iter().enumerate() {
            let n = self.get(*node);
            if i > 0 {
                let e = &self.edges[path.edges[i - 1]];
                let verb = if self.get(e.from).kind == NodeKind::Laptop
                    && e.kind == EdgeKind::CanAuthenticate
                {
                    "holds"
                } else {
                    e.kind.plain()
                };
                s.push_str(&format!(" —{verb}→ "));
            }
            s.push_str(&n.name);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laptop_to_signer() -> (PermissionGraph, NodeId, NodeId) {
        let mut g = PermissionGraph::new();
        let laptop = g.node(NodeKind::Laptop, "laptop");
        let kube = g.node(NodeKind::Credential, "kubeconfig prod");
        let cluster = g.node(NodeKind::Cluster, "prod-eks");
        let deploy = g.node(NodeKind::ProductionService, "payments-api");
        let signer = g.node(NodeKind::Signer, "treasury-signer");
        let wallet = g.node(NodeKind::Wallet, "treasury-wallet");
        g.mark_production(cluster);
        g.edge(
            laptop,
            kube,
            EdgeKind::CanAuthenticate,
            Assurance::Confirmed,
        );
        g.edge_full(
            kube,
            cluster,
            EdgeKind::CanDeploy,
            Assurance::Confirmed,
            Some("namespace payments".into()),
            vec!["kubectl auth can-i create deployments: yes".into()],
            None,
        );
        g.edge(
            cluster,
            deploy,
            EdgeKind::CanModifyConfiguration,
            Assurance::Inferred,
        );
        g.edge(
            deploy,
            signer,
            EdgeKind::CanRequestSignature,
            Assurance::Inferred,
        );
        g.edge_full(
            signer,
            wallet,
            EdgeKind::CanTransferAssets,
            Assurance::Inferred,
            None,
            vec![],
            Some("HSM policy: second approver".into()),
        );
        (g, laptop, wallet)
    }

    #[test]
    fn multi_hop_path_found_with_weakest_assurance_and_gates() {
        let (g, laptop, wallet) = laptop_to_signer();
        let paths = g.paths_between(laptop, wallet, 8);
        assert_eq!(paths.len(), 1);
        let p = &paths[0];
        assert_eq!(p.hops(), 5);
        assert_eq!(p.assurance, Assurance::Inferred);
        assert_eq!(
            p.approvals_required,
            vec!["HSM policy: second approver".to_string()]
        );
        assert_eq!(p.outcome, PathOutcome::MoveFunds);
        assert!(p.is_gated());
        let text = g.describe(p);
        assert!(text.starts_with("laptop —holds→ kubeconfig prod"));
        assert!(text.ends_with("treasury-wallet"));
    }

    #[test]
    fn cyclic_role_relationships_terminate() {
        let mut g = PermissionGraph::new();
        let laptop = g.node(NodeKind::Laptop, "laptop");
        let a = g.node(NodeKind::CloudRole, "role-a");
        let b = g.node(NodeKind::CloudRole, "role-b");
        let c = g.node(NodeKind::CloudRole, "role-c");
        let secret = g.node(NodeKind::SecretsManager, "vault");
        g.edge(laptop, a, EdgeKind::CanAssumeRole, Assurance::Inferred);
        g.edge(a, b, EdgeKind::CanAssumeRole, Assurance::Inferred);
        g.edge(b, c, EdgeKind::CanAssumeRole, Assurance::Inferred);
        g.edge(c, a, EdgeKind::CanAssumeRole, Assurance::Inferred);
        g.edge(c, secret, EdgeKind::CanReadSecret, Assurance::Confirmed);
        let paths = g.paths_between(laptop, secret, 10);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].hops(), 4);
        let reach = g.reachability(laptop, 10);
        assert_eq!(reach.reachable(), 4);
        assert_eq!(reach.best_paths[&secret].outcome, PathOutcome::Read);
    }

    #[test]
    fn reachability_prefers_ungated_confirmed_paths() {
        let mut g = PermissionGraph::new();
        let laptop = g.node(NodeKind::Laptop, "laptop");
        let key = g.node(NodeKind::Credential, "key");
        let session = g.node(NodeKind::Credential, "session");
        let signer = g.node(NodeKind::Signer, "signer");
        g.edge(laptop, key, EdgeKind::CanAuthenticate, Assurance::Confirmed);
        g.edge(
            laptop,
            session,
            EdgeKind::CanAuthenticate,
            Assurance::Confirmed,
        );
        g.edge_full(
            key,
            signer,
            EdgeKind::CanRequestSignature,
            Assurance::Confirmed,
            None,
            vec![],
            Some("MFA".into()),
        );
        g.edge(
            session,
            signer,
            EdgeKind::CanRequestSignature,
            Assurance::Inferred,
        );
        let reach = g.reachability(laptop, 5);
        let best = &reach.best_paths[&signer];
        assert!(!best.is_gated());
        assert_eq!(best.nodes[1], session);
    }

    #[test]
    fn reachability_does_not_equal_authority() {
        let mut g = PermissionGraph::new();
        let laptop = g.node(NodeKind::Laptop, "laptop");
        let rpc = g.node(NodeKind::Credential, "rpc key");
        let signer = g.node(NodeKind::Signer, "signer");
        g.edge(laptop, rpc, EdgeKind::CanAuthenticate, Assurance::Confirmed);
        g.edge(rpc, signer, EdgeKind::CanReach, Assurance::Confirmed);
        let reach = g.reachability(laptop, 5);
        assert_eq!(reach.best_paths[&signer].outcome, PathOutcome::Reachability);
        assert!(reach.with_outcome(PathOutcome::RequestSignature).is_empty());
    }

    #[test]
    fn duplicate_edges_merge_and_keep_stronger_assurance() {
        let mut g = PermissionGraph::new();
        let a = g.node(NodeKind::Laptop, "a");
        let b = g.node(NodeKind::Cluster, "b");
        let i = g.edge_full(
            a,
            b,
            EdgeKind::CanDeploy,
            Assurance::Inferred,
            None,
            vec!["name".into()],
            Some("review".into()),
        );
        let j = g.edge_full(
            a,
            b,
            EdgeKind::CanDeploy,
            Assurance::Confirmed,
            None,
            vec!["can-i".into()],
            None,
        );
        assert_eq!(i, j);
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].assurance, Assurance::Confirmed);
        assert_eq!(g.edges[0].evidence.len(), 2);
        assert!(g.edges[0].requires_approval.is_none());
    }

    #[test]
    fn evidence_is_redacted_on_insert() {
        let mut g = PermissionGraph::new();
        let a = g.node(NodeKind::Laptop, "a");
        let b = g.node(NodeKind::Credential, "b");
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        g.edge_full(
            a,
            b,
            EdgeKind::CanAuthenticate,
            Assurance::Inferred,
            None,
            vec![format!("token {secret}")],
            None,
        );
        assert!(!g.edges[0].evidence[0].contains(secret));
        g.note(b, &format!("value {secret}"));
        assert!(!g.get(b).notes[0].contains(secret));
    }

    #[test]
    fn node_dedup_by_kind_and_name() {
        let mut g = PermissionGraph::new();
        let a = g.node(NodeKind::Wallet, "0x1111");
        let b = g.node(NodeKind::Wallet, "0x1111");
        let c = g.node(NodeKind::Signer, "0x1111");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(g.find(NodeKind::Wallet, "0x1111"), Some(a));
    }

    #[test]
    fn blank_approval_is_not_a_gate() {
        let mut g = PermissionGraph::new();
        let a = g.node(NodeKind::Credential, "kube");
        let b = g.node(NodeKind::Workload, "withdrawal-service");
        g.edge_full(
            a,
            b,
            EdgeKind::CanDeploy,
            Assurance::Inferred,
            None,
            vec!["declared".into()],
            Some("   ".into()),
        );
        assert!(g.edges[0].requires_approval.is_none());
        let paths = g.paths_between(a, b, 2);
        assert!(paths[0].approvals_required.is_empty());
    }

    #[test]
    fn paths_to_kind_sorted_worst_first() {
        let (g, laptop, _) = laptop_to_signer();
        let paths = g.paths_to_kind(laptop, NodeKind::Signer, 8);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].outcome, PathOutcome::RequestSignature);
        let financial = g.paths_to_kind(laptop, NodeKind::Wallet, 8);
        assert_eq!(financial[0].outcome, PathOutcome::MoveFunds);
    }
}
