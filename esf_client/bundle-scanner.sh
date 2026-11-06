#!/bin/bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
# bundle-scanner.sh — Build and assemble "Gorse Scanner.app", the sandboxed
# scan-only product for the Mac App Store.
#
# Usage:
#   ./bundle-scanner.sh [--sign IDENTITY] [--installer-sign IDENTITY]
#                       [--profile PATH] [--debug] [--skip-build] [--output DIR]
#
#   --sign            "Apple Distribution: ..." (App Store) or a Developer ID
#                     Application identity (direct download). Without it the
#                     bundle is ad-hoc signed: fine for local testing on this
#                     Mac, rejected by Gatekeeper everywhere else.
#   --installer-sign  "3rd Party Mac Developer Installer: ..." identity. When
#                     given, also writes the .pkg that Transporter uploads to
#                     App Store Connect.
#   --profile         Mac App Store provisioning profile for is.hedgehog.scanner,
#                     embedded as Contents/embedded.provisionprofile.
#   --debug           Bundle the debug Swift build (enables --smoke-test).
#   --skip-build      Reuse existing build products.
#
# The result:
#   Gorse Scanner.app/Contents/
#     Info.plist                      (Sources/HedgehogScanner/Resources/Info.plist)
#     Resources/AppIcon.icns
#     MacOS/HedgehogScanner           (universal SwiftUI app)
#     MacOS/gorse-cli              (universal Rust CLI, sandbox-inheriting)
#     MacOS/gorse-ocr              (universal Vision text reader, sandbox-inheriting)
#
# The app carries App Sandbox with user-selected read-only file access; the
# CLI carries App Sandbox plus inherit and nothing else. No network, no
# system extension, no restricted entitlements, so no profile is required for
# the app to launch; App Store Connect still expects one at upload.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/Resources"
INFO_PLIST="$SCRIPT_DIR/Sources/HedgehogScanner/Resources/Info.plist"
APP_ENTITLEMENTS="$RESOURCES_DIR/HedgehogScanner.entitlements"
CLI_ENTITLEMENTS="$RESOURCES_DIR/HedgehogScannerCLI.entitlements"
ICON_SOURCE="$RESOURCES_DIR/ScannerIcon.png"
SCRATCH="$SCRIPT_DIR/.build-scanner"

SIGN_IDENTITY=""
INSTALLER_IDENTITY=""
PROFILE=""
CONFIG=release
SKIP_BUILD=0
OUTPUT_DIR="$SCRIPT_DIR/build-scanner"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign) SIGN_IDENTITY="$2"; shift 2 ;;
        --installer-sign) INSTALLER_IDENTITY="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --debug) CONFIG=debug; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ -n "$PROFILE" && ! -f "$PROFILE" ]]; then
    echo "Provisioning profile not found: $PROFILE" >&2; exit 1
fi

# ---------------------------------------------------------------- build ----
if [[ "$SKIP_BUILD" == 0 ]]; then
    echo "Building universal Rust CLI..."
    (cd "$ROOT" && cargo build --release -p hedgehog-cli --target aarch64-apple-darwin --target x86_64-apple-darwin)
    mkdir -p "$ROOT/target/scanner"
    lipo -create -output "$ROOT/target/scanner/gorse-cli" \
        "$ROOT/target/aarch64-apple-darwin/release/gorse" \
        "$ROOT/target/x86_64-apple-darwin/release/gorse"

    echo "Building universal Swift app ($CONFIG)..."
    (cd "$SCRIPT_DIR" && HEDGEHOG_SKIP_ESF=1 swift build -c "$CONFIG" --product HedgehogScanner \
        --arch arm64 --arch x86_64 --scratch-path "$SCRATCH")
    echo "Building universal OCR helper..."
    (cd "$SCRIPT_DIR" && HEDGEHOG_SKIP_ESF=1 swift build -c release --product GorseOCR \
        --arch arm64 --arch x86_64 --scratch-path "$SCRATCH")
fi

CLI_BIN="$ROOT/target/scanner/gorse-cli"
SWIFT_BIN="$SCRATCH/apple/Products/$(tr '[:lower:]' '[:upper:]' <<< "${CONFIG:0:1}")${CONFIG:1}/HedgehogScanner"
OCR_BIN="$SCRATCH/apple/Products/Release/GorseOCR"
for bin in "$CLI_BIN" "$SWIFT_BIN" "$OCR_BIN"; do
    [[ -x "$bin" ]] || { echo "Missing build product: $bin" >&2; exit 1; }
    for arch in arm64 x86_64; do
        lipo "$bin" -verify_arch "$arch" || { echo "$bin lacks $arch" >&2; exit 1; }
    done
done

# ----------------------------------------------------------------- icon ----
ICNS="$OUTPUT_DIR/AppIcon.icns"
mkdir -p "$OUTPUT_DIR"
if [[ ! -f "$ICON_SOURCE" ]]; then
    echo "Missing icon source $ICON_SOURCE (1024x1024 PNG)" >&2; exit 1
fi
ICONSET="$OUTPUT_DIR/AppIcon.iconset"
rm -rf "$ICONSET"; mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$ICNS"
rm -rf "$ICONSET"

# ------------------------------------------------------------- assemble ----
APP="$OUTPUT_DIR/Gorse Scanner.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$INFO_PLIST" "$APP/Contents/Info.plist"
cp "$ICNS" "$APP/Contents/Resources/AppIcon.icns"
cp "$RESOURCES_DIR/ScannerPrivacyInfo.xcprivacy" "$APP/Contents/Resources/PrivacyInfo.xcprivacy"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/LICENSE"
cp "$ROOT/LICENSE-THIRD-PARTY" "$APP/Contents/Resources/LICENSE-THIRD-PARTY"
cp "$SWIFT_BIN" "$APP/Contents/MacOS/HedgehogScanner"
cp "$CLI_BIN" "$APP/Contents/MacOS/gorse-cli"
cp "$OCR_BIN" "$APP/Contents/MacOS/gorse-ocr"
chmod 755 "$APP/Contents/MacOS/"*
if [[ -n "$PROFILE" ]]; then
    cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
fi
/usr/bin/xattr -cr "$APP"

# ----------------------------------------------------------------- sign ----
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/gorse-scanner-sign.XXXXXXXX")"
trap 'rm -rf "$TEMP"' EXIT
APP_ENT="$TEMP/app.entitlements"
cp "$APP_ENTITLEMENTS" "$APP_ENT"
if [[ -z "$SIGN_IDENTITY" ]]; then
    # Ad-hoc builds have no team; the identifier entitlements would be lies.
    /usr/libexec/PlistBuddy -c "Delete :com.apple.application-identifier" "$APP_ENT"
    /usr/libexec/PlistBuddy -c "Delete :com.apple.developer.team-identifier" "$APP_ENT"
fi

sign() {  # sign PATH ENTITLEMENTS IDENTIFIER
    local ARGS=(--force --options runtime --entitlements "$2" --identifier "$3")
    if [[ -n "$SIGN_IDENTITY" ]]; then
        ARGS+=(--timestamp --sign "$SIGN_IDENTITY")
    else
        ARGS+=(--sign -)
    fi
    codesign "${ARGS[@]}" "$1"
}

if [[ -n "$SIGN_IDENTITY" ]]; then
    echo "Code signing with identity: $SIGN_IDENTITY"
else
    echo "Code signing ad-hoc (local testing only)..."
fi
# Inside-out: the helper first, then the app, which seals the helper's hash.
sign "$APP/Contents/MacOS/gorse-cli" "$CLI_ENTITLEMENTS" "is.hedgehog.scanner.cli"
sign "$APP/Contents/MacOS/gorse-ocr" "$CLI_ENTITLEMENTS" "is.hedgehog.scanner.ocr"
sign "$APP" "$APP_ENT" "is.hedgehog.scanner"

echo "Verifying signature..."
codesign --verify --strict --deep --verbose=2 "$APP"
echo ""
echo "App entitlements:"
codesign -d --entitlements - --xml "$APP/Contents/MacOS/HedgehogScanner" 2>/dev/null | plutil -p -
echo "Helper entitlements:"
codesign -d --entitlements - --xml "$APP/Contents/MacOS/gorse-cli" 2>/dev/null | plutil -p -

# -------------------------------------------------------------- package ----
ZIP_PATH="$OUTPUT_DIR/Gorse-Scanner-macOS.zip"
rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP" "$ZIP_PATH"
echo ""
echo "Created: $APP"
echo "         $ZIP_PATH"

if [[ -n "$INSTALLER_IDENTITY" ]]; then
    PKG_PATH="$OUTPUT_DIR/Gorse-Scanner.pkg"
    rm -f "$PKG_PATH"
    productbuild --component "$APP" /Applications --sign "$INSTALLER_IDENTITY" "$PKG_PATH"
    echo "         $PKG_PATH   (upload with the Transporter app)"
fi
