# Exposure Check — `hedgehog exposure`

**Question it answers:** if this laptop were compromised, what could an
attacker access, authorize, modify, sign, deploy or steal with the
credentials and sessions on it?

`hedgehog scan` tells you *which* credential files exist. `hedgehog exposure`
tells you what they can *do*, how sure we are, which of them need rotating or
revoking at their service because wiping the laptop would not remove the
access, and what to fix first. It is an extension of the
credentials check, not a separate product.

```
hedgehog exposure                 # local, read-only, offline
hedgehog exposure --verify        # Pro: also confirm with read-only provider queries
hedgehog exposure --json          # machine-readable
hedgehog exposure --html out.html # report with the permission graph
hedgehog exposure --init          # write ~/.hedgehog/authority.toml to describe your infrastructure
hedgehog exposure --mark-production NAME   # record a host or system as production in the map (the apps' "Mark as production" button)
```

The deep scan (`hedgehog scan --deep`) runs TruffleHog as a second engine
when it is installed (`hedgehog engines install trufflehog` downloads the
pinned release, verifies it against a checksum in `hedgehog-cli/src/engines.rs`,
and keeps it under `~/.hedgehog/engines`; the apps offer this as one click), always with `--no-verification`, so the promise that
the scan sends nothing anywhere holds; its findings carry the detector name
as the category and never the raw secret. `--no-trufflehog` or
`HEDGEHOG_NO_TRUFFLEHOG=1` turns it off.

The Fast Scan (`hedgehog exposure`) uses the same engine when it is
installed: one run, verification off, over the known credential locations
that exist on the machine (encrypted stores such as the macOS keychains,
GnuPG keyrings, the Windows Credential Manager blobs, Bitwarden data and
Chrome's Login Data are left out, since pattern detectors over ciphertext
report junk, and so are the large browser-profile and wallet trees, which
are watched for presence only). The list of locations and the published
source for each one is `hedgehog-cli/data/credential-locations.toml`; see
`docs/CREDENTIAL_LOCATIONS.md` for how it is kept current. A detection in a file
Hedgehog already read and assessed is dropped: Hedgehog's own finding
carries the reach. Anything else becomes a Low finding with confidence
"unknown" whose evidence says the vendor is recognised and the reach has not
been assessed, which the report says is not the same as safe. The JSON
report lists the run under `engines` (locations handed over, detections,
findings added, never a secret); `--no-trufflehog` skips it, and without the
engine the notes say how to add it. The MCP `exposure_check` tool runs it
too.

An SSH key is scored as a shell on the hosts that accept it, not as mere
reachability: Medium for a host nobody has identified (Low when the key has a
passphrase and the login is only inferred), High for a declared production
host, and one step higher again when the key file has no passphrase. A
declaration in the map beats the name heuristic: `james-devbox-02` is
production if you say so, however it is spelled.

Exit codes: `0` nothing at High or above, `1` High or Critical findings, `2` could not run. `--fail-on medium` (or `critical`, `low`) moves the bar.

## What it distinguishes

Every finding is placed on this ladder, and the report never skips a rung:

| Rung | Meaning |
|---|---|
| possession | a credential is on the laptop |
| reachability | the credential can connect to a system; nothing more shown |
| read | it can read data or secrets |
| modify | it can change code, configuration or deployments |
| request signature | it can ask a signer to sign; approval lives elsewhere |
| approve signature | it can approve a transaction |
| move funds | it can transfer assets, or install authority that can |

Every claim also carries an **assurance**: `confirmed` (the provider
answered), `inferred` (from local configuration, naming or credential type) or
`unknown`. A path is only as confirmed as its weakest hop, and an inferred
claim is scored one step lower than the same claim confirmed, with one
exception: an ungated path that ends in moving funds or approving a
transaction is never scored below Critical. Such a path can only come from a
key in hand or from the topology you declared, never from a name heuristic,
and the cost of under-reporting it is the whole treasury. The confidence label
still says `inferred` and the finding says what `--verify` would confirm.
Presence of a credential never scores as administrative authority on its own.

Separately from assurance, every finding records what a `--verify` check
actually established, as `verification.status`: `not_attempted` (no
`--verify`), `unsupported` (no adapter for this credential yet),
`local_config` (the tool ran but only read local configuration, such as
`gcloud auth list` or `az account show`; the provider was not asked),
`identity_confirmed` (the provider authenticated the credential and returned
who it belongs to, such as `aws sts get-caller-identity`, `gh auth status`,
`vault token lookup`, `doctl account get`), `permission_confirmed` (the
provider confirmed a specific permission, such as `kubectl auth can-i`,
`az role assignment list`, an assumed AWS role, or repository access through
`gh api`), or `failed` (the check ran and errored or timed out). Running a
tool successfully never by itself counts as confirmation. Listing attached
AWS policies is identity only: permission boundaries, SCPs and explicit denies
are not evaluated, so effective permission is not confirmed. Repository write
access does not establish permission to push to a protected branch. A finding's
assurance rises to `confirmed` only on identity or permission confirmation,
and a multi-hop path stays `inferred` unless every hop was permission
confirmed. The summary counts each status in `verification_counts`.

A blank `change_approval = ""` or `approval = ""` in the map means "no gate".
It is never treated as an unnamed approval step.

## How it works

1. **Discovery** (`hedgehog-cli/src/exposure/discover.rs`). Reads the files
   and environment the user already owns and keeps only metadata: a
   fingerprint, the identity, expiry, scope hints, and where it was found.
   Sources: AWS profiles, SSO and STS caches; Google Cloud ADC, service account
   keys, gcloud config; Azure CLI profile and service principals; Vault,
   1Password, Doppler, Infisical; GitHub CLI, `GITHUB_TOKEN`, `.git-credentials`,
   GitHub App keys; GitLab, CircleCI, Fly, Vercel, Netlify, Railway, npm, PyPI,
   `.netrc`; Docker registries; every kubeconfig context (token, client cert,
   exec plugin, auth provider); Terraform Cloud, `TF_TOKEN_*`, Pulumi;
   DigitalOcean (every doctl context in `config.yaml` on any platform's
   path, `DIGITALOCEAN_ACCESS_TOKEN`, `DIGITALOCEAN_TOKEN`); SSH
   private keys (passphrase or not), SSH certificates (principals, validity,
   extensions), `~/.ssh/config` hosts with agent forwarding, identities unlocked
   in `ssh-agent`; Ethereum keystores, Solana keypairs, Bitcoin Core, Electrum,
   Sparrow, Ledger Live, Frame, browser wallet extensions, WalletConnect stores;
   declared signing services; RPC provider keys, raw private keys and seed
   phrases in the environment and in `.env` files of the current project.
2. **Verification** (`--verify`, `verify.rs`). Opt-in and read-only. Uses the
   user's own installed CLIs with query subcommands only: `aws sts
   get-caller-identity` and `iam list-attached-*-policies`, `gh auth status`
   and `gh api repos/{owner}/{repo}` for repositories named in the map,
   `kubectl config view --minify`, `kubectl get namespaces`, `kubectl auth
   can-i --list -n <namespace>` and `kubectl auth can-i <verb> <resource>
   --all-namespaces`, `vault token
   lookup`, `gcloud auth list`, `az account show` and `az role assignment
   list`, `doctl account get` plus the `projects`, `compute droplet`,
   `kubernetes cluster`, `databases`, `registry` and `apps` listings (the
   last three as text columns, since their JSON carries connection
   passwords and app environment values), and JSON-RPC `eth_getCode` for
   declared wallets. Each call has a
   timeout; a failure leaves the permission `inferred` and is listed in the
   notes. `authority.toml` can forbid it with `allow_remote_verification =
   false`.

   A DigitalOcean token's scope (read-only, full access or fine-grained)
   is reported by no endpoint and no write is attempted, so after
   verification its identity is confirmed and every resource edge stays
   inferred: a droplet it lists (matched to a `~/.ssh/config` Host by public
   address), a Kubernetes cluster (named `do-<region>-<name>` so a saved
   kubeconfig joins the same node; the admin kubeconfig comes from a read
   endpoint, which the evidence says), a database (its password is in the
   read response Hedgehog did not request), the registry and each app.

   A provider answer only confirms what it actually says. GitHub classic
   scopes confirm what a token *has*; a missing scope confirms nothing,
   because fine-grained tokens carry per-repository permissions that `gh`
   does not list. Their write access stays `inferred` unless the map names
   the repository (`hosts = ["acme/payments"]` on a `repository` or `ci`
   system), in which case the read-only `permissions` object of that
   repository settles it. Each repository gets its own confirmed edge to the
   system, scoped `repository owner/repo`, so a writable repository and a
   read-only one are both reported and the order they appear in the map does
   not matter; a repository the token cannot read is named as unchecked and
   leaves the system's write access inferred. Kubernetes `can-i --list` is
   always about one namespace: the context's own, or `default` when it sets
   none, plus any `namespaces = [...]` the map declares for systems on that
   cluster, plus every namespace `kubectl get namespaces` lists when the
   context may list them (up to 50 beyond the declared ones). Results are
   labelled "in namespace X"; only the `--all-namespaces` probes are called
   cluster-wide. A capability is reported as "no" only when the cluster scope
   denied it and every namespace in the cluster's list and in the map was
   checked and denied it; if the list is not readable or any namespace went
   unchecked, it stays unknown and the evidence names the namespaces that
   were checked and those that were not. No graph edge ever carries more
   assurance than the credential it belongs to.

   `--verify` is the one part of the exposure check that needs **Hedgehog
   Pro** ($89 per computer per year) or a Team licence. Everything else,
   including the full report in text, JSON and HTML and the MCP tool, is free.
   Without a licence, `--verify` stops before any provider query, prints how
   to get a key, and exits `2`; the report without `--verify` is unchanged.
   Activate with `hedgehog activate <key>`.

   **Lease lifetime and renewal.** The key is a signed, machine-bound lease of
   at most 24 hours. Before `--verify` runs, the CLI quietly tries to renew a
   lease that is past half its life (ten-second timeout, nothing printed, the
   command never waits on failure). After the signed expiry a 14-day renewal
   grace begins (`RENEWAL_GRACE_SECONDS` in `credential_store.rs`): the tier
   stays effective, `hedgehog license status` reports state `grace` with the
   days remaining, and `hedgehog license refresh` is still accepted by the
   server for an active subscription. A cancelled subscription is refused
   (403) at the first renewal attempt and the lease is removed, so the grace is
   the only window in which a stale lease counts. When the grace ends the tier
   is Free until the customer signs in and activates again.

   **Verified report stamp (an integrity checksum).** A `--verify` run adds an `attestation` block to
   the report: the licence holder (the email on the lease), Hedgehog's machine
   fingerprint for the laptop, the UTC time the run finished, and a checksum.
   The checksum covers the report and its stamp. It detects accidental or
   careless edits; it is not a cryptographic signature and does not prove who
   produced the report. It is `sha256:` followed by the lowercase hex SHA-256
   of the JSON report serialised compactly with keys sorted, with the
   top-level `generated_at` member and the `attestation.digest` member
   removed and `attestation.holder`, `attestation.machine` and
   `attestation.verified_at` left in, so editing a finding or any of those
   three fields changes it and anyone holding the JSON can recompute it.
   History files written by older versions may also carry a top-level
   `accepted_by_user` member (an earlier `gorse schedule accept-baseline`
   wrote it into the run); it is not part of the check result and is removed
   too. Current versions never modify a recorded run: accepting a baseline
   writes `~/.hedgehog/exposure/baseline.json`
   (`{"file": "<run file name>", "accepted_at": "<RFC 3339 time>",
   "accepted_by_user": true}`) instead, and the accepted run stays the
   baseline, even if incomplete, until a newer complete run exists. The checksum is computed last,
   over the report exactly as emitted: when the run is recorded into history
   (`--record`, which the apps always use) it covers the `changes`,
   `recorded_at` and `trigger` members as well, and the copy kept in history
   is byte-for-byte the emitted one. The text report shows it as a
   closing "Verified report" block, the HTML report as a footer box, and the
   JSON as `"attestation": {holder, machine, verified_at, digest}` (`null`
   when the report was not verified). The stamp never contains secret
   material.
3. **Infrastructure map** (`~/.hedgehog/authority.toml`, `config.rs`). The
   laptop cannot see that the cluster its kubeconfig reaches hosts the service
   that talks to the treasury signer. Teams declare that once: production
   systems and what they reach, signers and their approval policy, wallets and
   their addresses, what role names mean. Metadata only; the file is refused if
   it contains key material.
4. **Permission graph** (`taint_engine/src/authority/graph.rs`). Nodes are the
   laptop, credentials, roles, systems, signers, wallets and assets. Edges are
   capabilities (`CAN_AUTHENTICATE`, `CAN_ASSUME_ROLE`, `CAN_READ_SECRET`,
   `CAN_DEPLOY`, `CAN_MODIFY_CONFIGURATION`, `CAN_CREATE_CREDENTIAL`,
   `CAN_REQUEST_SIGNATURE`, `CAN_APPROVE_TRANSACTION`,
   `CAN_CHANGE_SIGNING_POLICY`, `CAN_INSTALL_DELEGATION`,
   `CAN_TRANSFER_ASSETS`) each with evidence, scope, assurance and any approval
   gate. Path search is cycle-safe and bounded; the **compromised-laptop
   simulation** (`reachability`) computes the best path from the laptop to
   every reachable node without exercising anything.
5. **Scoring** (`scoring.rs`). Severity reflects effective authority:
   Critical for confirmed ungated paths to moving funds, approving
   transactions, changing signing policy or installing delegations; High for
   production deployment authority over signing infrastructure, admin cloud
   access, long-lived credentials that modify production, credential creation,
   or inferred versions of the Critical cases; Medium for restricted production
   access and expiring privileged sessions; Low for read-only, RPC and scoped
   development credentials. Expired or revoked credentials are Low.
6. **Persistence.** Each finding says whether it still works after the laptop
   is cleaned: requires endpoint, independently valid credential, server-side
   persistence (can mint new credentials), blockchain authorization, or unknown.
7. **Blockchain checks** (`eip7702.rs`, `psbt.rs`). EIP-7702 authorization
   tuples are parsed from RLP, type-4 transactions or JSON; a wallet's *current*
   delegation is read from `eth_getCode` and recognised by the `0xef0100`
   prefix, so a historical authorization is never treated as an active
   delegation; delegates are classified approved / known-malicious / unknown.
   Bitcoin PSBTs are parsed (v0, witness and non-witness UTXOs, change
   detection via derivation paths) and checked against a signing policy:
   destination allowlist, change validation, fee and fee-rate limits,
   withdrawal limit, independent output verification. Signer declarations
   capture whether an HSM enforces policy or merely signs payloads, whether a
   multisig quorum lives on one laptop, and shared dependencies between
   "independent" signers.

## Safety properties

- Read-only. Never signs, submits, assumes, authenticates on its own, revokes
  or modifies IAM.
- No type in the analysis layer can hold a secret; evidence strings are
  redacted on insertion and tests assert that fixture secrets never appear in
  text, JSON or HTML output.
- Remote verification is opt-in per run and can be disabled in the map.
- Fails safe: unreadable files, missing CLIs and denied API calls become notes,
  not crashes, and leave assurance at `inferred` or `unknown`.
- No endpoint monitoring, no browser cookie reading, no keylogging.

## Example

`docs/examples/` holds a synthetic laptop: a long-lived AWS key, an expired
SSO session, a kubeconfig with a static token for a production cluster, a
GitHub login, an ECR login, a passphrase-less SSH key with agent forwarding to
a production bastion, a deployer private key in a project `.env`, and an MPC
signing-service API key. With the example `authority.toml` declaring that the
cluster hosts `payments-api`, which reaches `treasury-signer`, which controls
the `treasury` wallet, the check reports:

```
prod (Kubernetes context) —can deploy to→ payments-api —can request signatures from→ treasury-signer —can transfer assets from→ treasury → can move funds (inferred) [gated by: PR review + CI]
```

scored Medium (inferred, gated), while the signer API key with no independent
approval scores Critical even though it is only inferred, because nothing
gates the path to funds. See
`exposure-report.txt`, `.json` and `.html`.

## Automation

The check is built to be driven by scripts, agents and catalogs.

- **CLI contract.** `hedgehog exposure --json` prints one JSON document whose
  shape is described by `docs/schema/exposure-report.v1.schema.json`
  (published at https://gorse.is/schema/exposure-report.v1.json). Every
  document carries `schema_version`; it is bumped only for breaking changes,
  and new optional fields may appear without a bump. `attestation` is one such
  field: `null` for a free run, the verified-report stamp for a Pro `--verify`
  run.
- **Exit codes.** `0` nothing at the threshold, `1` at or above it, `2` could
  not run. The default threshold is High; `--fail-on critical|high|medium|low`
  chooses another, so an integrator picks the bar rather than inheriting ours.
- **MCP tool.** `hedgehog mcp` exposes `exposure_check` alongside
  `check_command`, `scan_content` and `explain_command`. It takes optional
  `verify` (default false), `map` and `max_hops` and returns the same JSON as
  the CLI in the tool result text, with the summary repeated in `_meta`.
  `verify: true` needs a Pro or Team licence on the computer running the
  server; without one the tool returns an error result with the upgrade
  message and runs nothing.
- **Map as input.** `--map FILE` (or the `map` argument) lets the caller supply
  the infrastructure topology instead of relying on `~/.hedgehog/authority.toml`.
- **Safe to ship.** The JSON contains fingerprints and metadata only. The map
  is the sensitive artefact: it names signers, wallets and approvers, and
  deserves the same handling as a secret.

## Scheduled checks (Pro)

Pro re-runs the check on a schedule and reports what changed. This is the
Mac app (`Gorse.app`, the direct download) and the command-line tool only;
the Mac App Store Scanner does not have it yet.

- **Cadence.** Daily by default, at 9:30 each morning or the next time the
  Mac wakes if it was asleep; hourly is optional. `gorse schedule set
  daily|hourly|off`, `gorse schedule status`, `gorse schedule history`.
- **Alerts.** Each run is diffed against the previous one. A notification is
  shown only when a finding is new or an existing one got worse. It carries
  counts only: no names, locations or fingerprints.
- **History.** What changed and when lives in `~/.hedgehog/exposure/history`.
- **Nothing leaves the computer.** Scheduled runs send nothing to Gorse and
  never download anything; TruffleHog is used only if already installed.

## Known limitations

- Without `--verify`, everything is inferred. Role and context names are
  heuristics; `prod-deploy` is production because of its name, not because we
  looked.
- Verification covers identity and coarse policy names. It does not evaluate
  IAM policy documents, GCP IAM bindings, resource policies, SCPs, permission
  boundaries or Kubernetes admission controls.
- The indirect graph beyond the first hop depends on `authority.toml`.
  Hedgehog does not crawl cloud accounts, CI configuration or cluster
  workloads to discover topology.
- GitHub fine-grained tokens do not expose scopes to `gh`; their write access
  stays inferred except on repositories the map names, which are checked
  individually and reported one by one. Repositories the map does not name
  are not checked.
- Kubernetes RBAC is checked in the context's namespace, any namespaces the
  map declares, every namespace the context can list (up to 50 extra), and
  cluster-wide via `--all-namespaces`. A denial counts as a confirmed "no"
  only when that coverage is complete; when the namespace list cannot be read
  or a namespace went unchecked, the capability stays unknown and the report
  says which namespaces were checked.
- The verified-report checksum is not a signature. It catches edits to the
  findings or the stamp made by mistake; it does not stop someone from
  editing and recomputing it.
- Browser wallet and WalletConnect findings are presence-based; vault contents
  and connected sites are not read.
- Browser cookies and OAuth sessions inside browsers are deliberately out of
  scope.
- HSM, MPC and custody policy is taken from the declaration; the tools do not
  query Fireblocks, Turnkey, BitGo or similar APIs.
- PSBT v2 is not parsed. Taproot script-path and miniscript policies are not
  interpreted beyond address derivation.
- EIP-7702 delegate reputation lists ship empty; populate `approved_delegates`
  and `malicious_delegates` per wallet.
- Windows credential manager, macOS keychain items and Linux keyrings are
  counted by the secret scanner but their contents are not enumerated here.
- `ssh-agent` is queried on Unix only.

## Future improvements, in priority order

1. Cloud policy evaluation: `iam simulate-principal-policy`, GCP
   `testIamPermissions`, Azure `permissions list`, to turn admin and
   credential-creation claims into confirmed ones.
2. Topology discovery: read GitHub Actions and GitLab CI definitions for
   deploy targets and secrets, EKS/GKE/AKS cluster lists from cloud creds,
   Kubernetes workloads for signer endpoints, so fewer declarations are needed.
3. Custody and signing-service integrations behind explicit consent:
   Fireblocks TAP policy, Turnkey policies, Safe owners/threshold/modules via
   the transaction service, Bitcoin Core `getwalletinfo`.
4. Live EIP-7702 nonce check (`eth_getTransactionCount`) to mark which pending
   authorizations are executable now; parse pending authorizations from
   wallet/tooling logs.
5. Team dashboard upload of the JSON summary (metadata only) through the
   existing `hedgehog report` path.
6. MCP tool exposing the summary to AI agents, and a panel in `hedgehog web`.
7. Windows: Credential Manager enumeration, Pageant/OpenSSH agent, `%APPDATA%`
   locations for the sources above.
8. Continuous mode: shipped on the Mac as scheduled checks (above). Still to
   do: Windows and Linux scheduling, and routing change alerts through the
   existing alert channels.
