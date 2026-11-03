# Release signing and provenance

`scripts/release/README.md` beside this file is the customer README that goes
inside every download; this file is for whoever cuts a release.

## What a release carries

- `SHA256SUMS.all`: one line per release asset, `<sha256>  <file name>`, sorted
  by name, built by `node scripts/release/sign-release.ts vX.Y.Z` over every
  asset of the private release (CI's Linux and Windows files, the locally
  notarized Mac zips and DMG, and the per-platform `SHA256SUMS`).
- `SHA256SUMS.all.sig`: an Ed25519 signature that binds the manifest to the
  release tag (signature format v2, below). `gorse verify-download <file>`
  fetches both from
  `https://github.com/jamestagg/hedgehog-releases/releases/download/<tag>/`
  and checks the download against the public key compiled into the CLI and
  the tag it asked for.
- Build provenance attestations are not possible yet: GitHub does not store
  them for user-owned private repositories (the first attempt, on v0.4.1,
  failed with "Feature not available for user-owned private repositories").
  The signed manifest covers every asset, CI-built and local alike. Revisit
  once releases are built in a public or organisation-owned repository.

`mirror-public.sh` copies every asset, the two manifest files included, and
refuses to mirror a release that has not been signed.

## Signature format v2

`SHA256SUMS.all.sig` is two ASCII lines, each ending in LF, nothing else:

1. `gorse-release-signature v2 key=<key id> tag=<tag>`, where `<key id>` is the
   first 8 characters of the base64 public key (`Dntss+6z`) and `<tag>` is the
   exact git tag of the release, `vX.Y.Z` and nothing more (pre-release tags
   are never signed).
2. The raw 64-byte Ed25519 signature in standard padded base64 (88 characters).

The signed bytes are `<tag>`, one LF, then the exact bytes of
`SHA256SUMS.all`. For `v0.4.2` that is `v0.4.2\n` followed by the manifest. A
verifier recomputes those bytes from the tag it is checking, so it never
trusts the tag in the header on its own: the header tag is compared with the
expected tag first, and the signature is then checked over the expected tag.
Re-labelling the header does not help an attacker because the tag is inside
the signed bytes.

Why v2 exists: an audit found that under format v1 (signature over the
manifest alone) a stale, genuinely signed manifest copied from an old release
and served under an invented newer tag still verified. Everything in it was
real: the key, the signature, the hashes. The only thing wrong was the tag it
was being served under, and v1 did not cover the tag. An attacker who could
influence what a client downloaded could keep every customer on an old,
vulnerable build while `gorse verify-download` reported success. Binding the
tag closes that: a manifest signed for `v0.4.1` verifies only as `v0.4.1`.

Checks a verifier must make, in order: the header parses as v2; the key id is
the compiled-in key; the header tag equals the tag being verified; the
signature verifies over `<expected tag>\n` + manifest; the manifest parses
canonically; the file's hash matches its line. `sign-release.ts --verify-only`
does all of these, as does `gorse verify-download`.

### Older releases and format v1

Format v1 was `gorse-release-signature v1 key=<key id>` on line 1 and the
signature over the bare manifest on line 2. `v0.4.1` was signed with v1 and is
not re-signed: its signature is still valid for what it was, a statement that
these files belong to `v0.4.1`, so `gorse verify-download --tag v0.4.1`
still verifies it. That is the only tag for which a v1 signature is accepted,
and the acceptance is pinned to tags older than `v0.4.2` (`FIRST_V2_TAG` in
`sign-release.ts`, mirrored in the CLI). No v1 signature can ever verify as a
newer tag, so `v0.4.1` can never be presented as an update: the update path
only recommends tags carrying a v2 signature bound to that tag.

`sign-release.ts` always writes v2 and refuses to sign a tag that is not plain
`vX.Y.Z`. Its `--verify-only` passes `allowV1` only when the tag it was given
sorts before `v0.4.2`; its `verifyManifest` rejects v1 otherwise and reports
which format it found.

## The key

- Private key: `~/.config/gorse-release/signing.key`, PKCS#8 PEM, mode 600, on
  the release Mac only. Override the path with
  `GORSE_RELEASE_SIGNING_KEY_FILE`. It never goes in the repository, in CI, in
  a GitHub secret, or in a chat.
- Public key (raw 32 bytes, base64): `Dntss+6znmHXEgrCkvZy6GENQOA+bScwD5jtCYdraG0=`,
  key id `Dntss+6z`. It is the constant in `scripts/release/sign-release.ts`,
  in `hedgehog-cli/src/release_signature.rs` and on the website security page.
- `sign-release.ts` derives the public key from the private key and refuses to
  sign if it differs from the constant, so a wrong key file cannot publish a
  manifest that installed copies of gorse would reject.
- Make a key with `openssl genpkey -algorithm ed25519 -out signing.key` and
  `chmod 600`; the public half is
  `openssl pkey -in signing.key -pubout -outform DER | tail -c 32 | base64`.

## Rotating the key

1. Generate the new key as above, on the release Mac, into a new file.
2. Update the constant in `scripts/release/sign-release.ts`,
   `hedgehog-cli/src/release_signature.rs` (and its tests) and the website
   security page. Mention the rotation in the release notes.
3. Ship a release containing the new CLI; sign it with the new key (point
   `GORSE_RELEASE_SIGNING_KEY_FILE` at it, then move it into place).
4. Older installed copies of gorse will reject manifests signed with the new
   key until they update, which is the intended behaviour.
5. Destroy the old private key.

If the private key is ever exposed, rotate immediately and re-sign the
current release; do not sign anything further with the old key.

## Dependency checks

`cargo audit --deny warnings` runs on every push and pull request (the
`advisories` job in `.github/workflows/ci.yml`) against both lock files.
`cargo deny` (licence and source policy on top of advisories) is the next step
once a `deny.toml` has been tuned for the workspace; it is not in CI yet.
