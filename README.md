# Gorse

Gorse answers one question about the computer it runs on: **if this laptop were
compromised, what could an attacker reach?**

It finds the credentials stored on the machine (cloud, CI, Kubernetes, SSH,
package registries, wallets, signing keys, AI coding agents and their MCP
settings, and more), then reports what each one gives access to, including
multi-step paths to production systems and money, and which credentials need
rotating at their service because wiping the laptop would not remove the
access.

The check is read-only, runs locally and never prints a secret.

This repository holds the source of the `gorse` command-line tool, its
detection engine and rule packs, the Mac app and the Windows and Linux app.
It is **source-available, not open source**: see [Licence](#licence).

## Download the signed apps

Most people should download the signed apps rather than build from source:

- **[gorse.is/download](https://www.gorse.is/download)**: Mac app, Windows app
  and the command-line tool for macOS, Windows and Linux.
- **[github.com/jamestagg/hedgehog-releases](https://github.com/jamestagg/hedgehog-releases)**:
  the same files, published with every release.

The downloads are free for everyone, companies included. Pro and Team
features, such as Verify, are sold separately at gorse.is.

## Check a download

Every release carries `SHA256SUMS.all`, the SHA-256 of every file in the
release, and `SHA256SUMS.all.sig`, its Ed25519 signature with QKey's release
key (key id `Dntss+6z`). To check a file you downloaded:

    gorse verify-download <file>

The Mac app and the macOS command-line tool are also signed with QKey's
Developer ID (Apple Team ID `4H5SCV7U38`) and notarized by Apple. To check
the Mac app:

    codesign --verify --deep --strict --verbose=2 /Applications/Gorse.app
    spctl --assess --type execute --verbose /Applications/Gorse.app

`spctl` should report `source=Notarized Developer ID` and
`codesign -dv` should show `TeamIdentifier=4H5SCV7U38`.

## Build from source (non-commercial use)

Builds from source are **not signed by QKey Co.** and are not the official
Gorse release. You may build and use them for non-commercial purposes under
the [PolyForm Noncommercial License 1.0.0](LICENSE).

You need Rust (the version in `.github/workflows/ci.yml`).

**Command-line tool** (macOS, Windows, Linux):

    cargo build --locked --release -p hedgehog-cli
    ./target/release/gorse exposure

**Tests:**

    cargo test --locked -p hedgehog-cli -p hedgehog_taint

Each release has a tag here (`v0.4.10` and later); check out the tag of the
release you want to compare with the published files. The
`dependency-inventory.json` on each release page is produced from QKey's
build tree, whose `Cargo.lock` also lists the crates of an experimental
kernel component that is not shipped. This repository's `Cargo.lock` is the
same lock with only those packages removed; no package is added and no
version differs.

**Mac app** (needs Xcode 15 or later). Without `--sign` the app is ad-hoc
signed and runs only on the Mac that built it:

    cd esf_client
    ./bundle-desktop.sh

**Windows and Linux app** (a separate Cargo project):

    cargo build --locked --release --manifest-path hedgehog-desktop/Cargo.toml

The directories and crates keep their earlier name, Hedgehog, on purpose; the
product is Gorse.

## Licence

In short (the full position is in [NOTICE.md](NOTICE.md)):

- The **source in this repository** is licensed under the
  [PolyForm Noncommercial License 1.0.0](LICENSE). You may read, audit, build
  and use it for non-commercial purposes. Commercial use of the source needs a
  licence from QKey Co.: contact support@gorse.is.
- The **official apps and command-line tool** downloaded from gorse.is or the
  releases repository are licensed under the end-user licence in
  [EULA.txt](EULA.txt) and are free for everyone.
- **Third-party components** keep their own licences
  ([LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY)).

## Contributing

Issues are welcome. Pull requests can be merged only after the contributor has
agreed to the Gorse Contributor Licence Agreement in [CLA.md](CLA.md). See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report security problems privately to support@gorse.is, not in a
public issue.
