# Hedgehog Scanner — the Mac App Store build

Hedgehog Scanner is the scan-only product: a sandboxed window app that checks
folders the user chooses for exposed secrets and sensitive content. It has no
system extension, no network filter, no agent hooks and no network
entitlement. Detection runs in the bundled `hedgehog-cli`, launched as a child
that inherits the app's sandbox and therefore only the folder access the user
granted in the open panel.

| Piece | Where |
|---|---|
| App source | `Sources/HedgehogScanner/` (SwiftPM target `HedgehogScanner`) |
| App entitlements | `Resources/HedgehogScanner.entitlements` |
| Helper entitlements | `Resources/HedgehogScannerCLI.entitlements` (CLI and OCR helper) |
| Privacy manifest | `Resources/ScannerPrivacyInfo.xcprivacy` |
| Bundle id | `is.hedgehog.scanner` (helpers: `is.hedgehog.scanner.cli`, `is.hedgehog.scanner.ocr`) |
| CLI mode | `hedgehog scan --deep --json --path DIR [--path DIR…]` |
| Build script | `bundle-scanner.sh` |
| Icon source | `Resources/ScannerIcon.png` (placeholder, 1024 px or larger) |

## What the sandbox removes

- **Apple Notes** are not scanned. The Notes database lives in another app's
  container, which a sandboxed app may not read.
- **Images** are read. The bundled `gorse-ocr` helper (Apple Vision,
  `Sources/GorseOCR/`) runs inside the same sandbox and folder grant; the CLI
  finds it beside itself and reads pictures in the chosen folders. It never
  falls back to the `swift` toolchain inside an app.
- The home-directory defaults (`~/.ssh`, `~/.aws`, Desktop, …) are not scanned
  automatically. The user adds folders explicitly; grants persist across
  launches through app-scoped bookmarks.

With `--path`, the CLI skips Notes itself, so the sandboxed child never
attempts an access that would be denied, and reads pictures only when
`gorse-ocr` sits beside it.

## Build and local test

```sh
cd esf_client
./bundle-scanner.sh            # ad-hoc signed release build in build-scanner/
./bundle-scanner.sh --debug    # debug build with the --smoke-test flag
```

The script builds a universal Rust CLI (`aarch64` + `x86_64`), a universal
Swift app, renders `AppIcon.icns`, assembles the bundle, signs inside-out with
the two entitlement files and verifies the signature. Ad-hoc builds run on the
building Mac only.

The debug build accepts `--smoke-test`: inside its sandbox it draws a
picture of a made-up GitHub token into the container's own Documents folder,
scans that folder (the CLI and `gorse-ocr` both run as sandboxed children),
prints the result as JSON on stdout, deletes the picture and quits. Run it in
its own process group with a timeout. A pass shows a "GitHub PAT" finding in
`gorse-smoke.png` and `"images_not_checked": 0`. The flag is compiled out of
release builds (`#if DEBUG`).

## App Store submission

1. In App Store Connect, register the app id `is.hedgehog.scanner` and create
   a **Mac App Store** provisioning profile for it (no special capabilities).
2. Install the **Apple Distribution** and **3rd Party Mac Developer Installer**
   certificates for team `4H5SCV7U38` in the login keychain.
3. Build:

   ```sh
   ./bundle-scanner.sh \
     --sign "Apple Distribution: James Tagg (4H5SCV7U38)" \
     --installer-sign "3rd Party Mac Developer Installer: James Tagg (4H5SCV7U38)" \
     --profile ~/Downloads/HedgehogScanner_MacAppStore.provisionprofile
   ```

4. Upload `build-scanner/Hedgehog-Scanner.pkg` with the Transporter app.
5. Complete the listing: screenshots, description, privacy labels (no data
   collected, nothing leaves the Mac), category Utilities, free. The app
   shows no prices, plans or upgrade links: App Store rules forbid steering
   to purchases outside in-app purchase.

Bump `CFBundleShortVersionString` and `CFBundleVersion` in
`Sources/HedgehogScanner/Resources/Info.plist` for every upload.

For direct download instead, pass the Developer ID identity to `--sign`,
notarize the zip with `notarytool`, staple and repackage, as `bundle.sh`
documents for the full app.
