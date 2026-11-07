# Credential locations: how the Fast Scan's list is assembled

The Fast Scan (`hedgehog exposure`) checks a fixed list of places where
credentials live on a laptop. This document is the procedure for deciding
what is on that list. The list itself is the register at
`hedgehog-cli/data/credential-locations.toml`, and a unit test
(`hedgehog-cli/src/exposure/register.rs`) fails whenever the register and the
code disagree, so the register cannot silently go stale.

The rule: **no location is on the list without a recorded source.** Before
2026-11-01 the list was written from memory of vendor documentation. Those
entries cite the provisional source `hedgehog-engineering` and are replaced
with real citations as the review below reaches them.

## The four states a location can be in

"Covered" used to mean one of three register fields was set, which mixed
watching a path with understanding what is in it. Each location now has four
distinct states, and a coverage statement names which of them apply. They
build on each other: a location can be present without being detected, and
detected without being verified.

| State | Register field | Where in the code | What it means |
|---|---|---|---|
| **present** | `watched` | `SecretDetector::add_user_home` in `taint_engine/src/secrets.rs` | The location is on the list. `hedgehog status` and `scan --all` report whether it exists on this computer. Nothing has interpreted the file. `["all"]` or a list of platforms |
| **detected** | `discovered` | `hedgehog-cli/src/exposure/discover.rs` | A Fast Scan adapter opens and parses the file into a credential: what it is, which account or host it belongs to, and what it is inferred to reach |
| **verified** | (none yet; see below) | `hedgehog-cli/src/exposure/verify.rs` | A read-only provider query exists for the credential, so with Pro Verify the inferred reach can be confirmed by the provider. Some queries only confirm identity, and the reach stays inferred; the verify step's note says which |
| **protected** | `guarded` | filename rules in `taint_engine/src/secrets.rs`; system paths in `hedgehog-linux/src/secrets.rs` | Agent guard rules exist: a read of it taints the process. Used for name patterns (`.kdbx`, `.ovpn`, `.pfx`, `credentials.xml`) that cannot be reported present without a walk, and for Linux system files such as `/etc/shadow`. A list of platforms |

The register does not yet carry a `verified` field. The table in
`verify.rs` (module comment) is the record of which providers have a query
and what each query confirms; adding the field to the register and checking
it against that table is the next step for the register test.

`status` is `covered` when the location is at least present (or protected,
for the name patterns that cannot be listed), `gap` when a source cites the
location and nothing checks it yet, and `excluded` when we decided not to
check it; an excluded entry must say why in `note`. A coverage statement
for a location, in a report or on the website, should say which of the four
states apply rather than "covered".

### What is out of scope

Browser sessions and cookies are not read. Operating-system credential
stores (macOS keychains, Windows Credential Manager, GNOME Keyring) and
browser password stores are not read either: they are encrypted at rest, so
reading them would mean decrypting the user's passwords, which is not what a
read-only exposure check should do. These stores may be `present` on the
watch list so that access to them is noticed by the agent guard, but the
Fast Scan never opens them and no pattern detector is run over them. Browser
profiles are read only for the presence of wallet extensions.

The distinction between `watched` and `guarded` matters. On 2026-11-01 the
register showed that every path the Linux and Windows platform crates add
was guarded only, and the shipped Windows binary does not even compile the
Windows crate. On 2026-11-02 every home-directory location moved into the
taint engine's own tables (`HOME_LOCATIONS` for all platforms,
`MACOS_HOME_LOCATIONS`, `LINUX_HOME_LOCATIONS` and `WINDOWS_HOME_LOCATIONS`
for the rest), each with a priority and a description, so the three
platforms report the same way. The platform crates now only matter for the
Linux system paths; their home-directory entries are duplicates of the
engine's and can be removed.

## Where entries come from

Every entry cites at least one source of one of these kinds:

| Kind | Examples | What it tells us |
|---|---|---|
| `vendor-docs` | AWS CLI, gcloud, kubectl, Docker, doctl, Vercel, npm documentation | The default path the tool writes, per platform |
| `framework` | MITRE ATT&CK T1552 (Unsecured Credentials) and sub-techniques | Paths defenders are expected to monitor |
| `infostealer-analysis` | Published analyses of macOS and Windows stealers (AMOS, Banshee, Poseidon, RedLine, Lumma, Vidar and others) | What attackers actually collect from a compromised laptop |
| `incident` | Supply-chain compromises that harvested developer credentials (npm, PyPI and CI worms) | What developer-targeted malware went for in practice |
| `scanner` | Gitleaks, Nosey Parker, detect-secrets and other public scanner docs | Patterns and locations scanners expect |
| `audit-guidance` | CIS, NIST, Elastic and Microsoft detection rules naming credential files | Paths an audit would expect us to cover |

Infostealer analyses are the most important of these. A location that
several stealer families collect is on the list even if no vendor document
names it, because the question the Check answers is what a stolen laptop
reaches, and the stealers are the ground truth for that.

## What qualifies

A location goes in the register when it is a file, directory or environment
variable that holds, or points at, a credential a developer laptop is likely
to carry: cloud and infrastructure CLIs, source control, CI and deployment
tools, package registries, secrets managers, databases, SSH and signing keys,
wallets, and AI-agent configuration that embeds API keys.

Consumer material (browser password stores, messaging apps, saved game
logins) is recorded when a source cites it but marked `excluded` with the
reason, unless it bears on what an attacker can reach from the laptop. Browser
profiles are read only for the presence of wallet extensions.

Encrypted operating-system stores and browser password stores are listed as
`present` only, never `detected` (see "What is out of scope" above); apart
from the privacy reason, detectors over ciphertext produce junk.

## Adding a location

1. Add a `[[source]]` for where you learned of it, if not already present:
   `id`, `kind`, `title`, `url`, `date` (publication) and `reviewed`.
2. Add a `[[location]]` with the paths per platform (`~` for home,
   `%USERPROFILE%`, `%APPDATA%` or `%LOCALAPPDATA%` on Windows), `vendor`,
   `what`, `status = "gap"` and `sources`.
3. Decide the layer. Presence alone is enough for the watch list: add it to
   the matching table in `taint_engine/src/secrets.rs` (`HOME_LOCATIONS`
   when the path is the same under every home directory, otherwise the
   platform table) with a priority and a one-line description, since the
   description is what the report shows. A directory entry guards everything
   beneath it. Large binary trees (browser profiles, wallets) are watched for
   presence only and never read by a pattern detector. If the Fast Scan should understand the
   credential, write or extend a discovery adapter in `discover.rs` and, for
   Pro verification, a verify step in `verify.rs`.
4. Set `watched` (present), `guarded` (protected) or `discovered` (detected)
   to match, change `status` to `covered`, and run
   `cargo test -p hedgehog-cli exposure::register`. The test checks that
   every covered path really is on the watch list for this platform, that
   every watch-list path has a register entry, that every watched or guarded
   path is one the agent guard treats as secret (when the platform crate is
   compiled in), and that every discovered entry's path literal (or its
   `code` override) appears in `discover.rs`. CI runs the same tests on
   macOS, Linux and Windows, but the Linux and Windows runs happen only on
   tags, so before tagging check the other two platforms by hand: the
   Windows list is `HOME_LOCATIONS` rendered under `%USERPROFILE%` plus
   `WINDOWS_HOME_LOCATIONS`, and every one of those paths must appear in an
   entry whose `watched` names `windows` or `all`.
5. Mention the vendor in `docs/EXPOSURE_CHECK.md` and, if user-facing, the
   Resources page.

## Monthly review

The Monthly Upstream Review issue (`.github/workflows/upstream-review.yml`)
carries a checklist item for this. Each month:

1. Search for infostealer analyses published since the last `meta.reviewed`
   date (vendor research blogs: SentinelOne, Kandji, Jamf, Elastic, Unit 42,
   Malwarebytes, Microsoft, CrowdStrike, Sekoia, Recorded Future). For any
   new family or new target list, add the source and any path we do not have
   as a `gap`.
2. Check for new developer-tool compromises (npm, PyPI, VS Code extensions,
   CI actions) and record what they harvested.
3. Re-read MITRE ATT&CK T1552 and sub-techniques for changes.
4. Check the vendor documentation of any CLI tool added to the Resources
   page or requested by a user since last month.
5. For each `gap`, decide: implement now, schedule, or mark `excluded` with a
   reason.
6. The first fill on 2026-11-01 took its infostealer citations from a
   research sweep rather than a hand read of every article. Spot-check two
   or three of those sources at the first review and correct any path that
   was summarised rather than quoted.
7. Update `meta.reviewed` and commit. The test will not pass with a
   malformed date.

## Known limits

- The register covers paths. The environment-variable list lives in the
  `environment` adapter in `discover.rs` and is recorded in the register as
  one pattern entry; its contents are not individually sourced yet.
- The reverse check (every adapter literal has a register entry) runs only
  for the watch list. A path read by an adapter but missing from the register
  is caught in review, not by the test.
- Watch-list membership is checked for the platform the test runs on. Each
  platform's list is verified only on that platform's CI runner.
