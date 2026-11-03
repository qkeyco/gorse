#!/bin/bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
# bundle-desktop.sh — Build and assemble "Gorse.app", the Developer ID
# download: the exposure check and the folder scan in one window, around the
# bundled Rust CLI. Not sandboxed (the check must read ~/.aws, ~/.kube, ~/.ssh
# and agent settings); hardened runtime; notarized when asked.
#
# Usage:
#   ./bundle-desktop.sh [--sign "Developer ID Application: ..."] [--notarize]
#                       [--debug] [--skip-build] [--output DIR]
#
#   --sign       Developer ID Application identity. Without it the bundle is
#                ad-hoc signed: runs on this Mac only.
#   --notarize   Submit the zip with `xcrun notarytool` using the keychain
#                profile in $HEDGEHOG_NOTARY_PROFILE, staple the app, re-zip.
#   --debug      Bundle the debug Swift build.
#   --skip-build Reuse existing build products.
#
# The result (build-desktop/):
#   Gorse.app/Contents/
#     Info.plist                      (Sources/HedgehogScanner/Resources/Info-Desktop.plist)
#     Resources/AppIcon.icns
#     MacOS/Gorse                     (universal SwiftUI app, HEDGEHOG_DESKTOP build)
#     MacOS/gorse-cli                 (universal Rust CLI)
#   Gorse-macOS.dmg                   (what /api/download?platform=macos-app serves:
#                                      the app plus an Applications shortcut to drag it onto)
#   Gorse-macOS.zip                   (the same app, for /api/download?platform=macos-zip)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/Resources"
INFO_PLIST="$SCRIPT_DIR/Sources/HedgehogScanner/Resources/Info-Desktop.plist"
APP_ENTITLEMENTS="$RESOURCES_DIR/HedgehogDesktop.entitlements"
ICON_SOURCE="$RESOURCES_DIR/ScannerIcon.png"
SCRATCH="$SCRIPT_DIR/.build-desktop"

SIGN_IDENTITY=""
NOTARIZE=0
CONFIG=release
SKIP_BUILD=0
OUTPUT_DIR="$SCRIPT_DIR/build-desktop"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign) SIGN_IDENTITY="$2"; shift 2 ;;
        --notarize) NOTARIZE=1; shift ;;
        --debug) CONFIG=debug; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
if [[ "$NOTARIZE" == 1 ]]; then
    [[ -n "$SIGN_IDENTITY" ]] || { echo "--notarize needs --sign" >&2; exit 2; }
    [[ -n "${HEDGEHOG_NOTARY_PROFILE:-}" ]] || { echo "--notarize needs HEDGEHOG_NOTARY_PROFILE" >&2; exit 2; }
fi

# ---------------------------------------------------------------- build ----
if [[ "$SKIP_BUILD" == 0 ]]; then
    echo "Building universal Rust CLI..."
    (cd "$ROOT" && cargo build --release -p hedgehog-cli --target aarch64-apple-darwin --target x86_64-apple-darwin)
    mkdir -p "$ROOT/target/desktop"
    lipo -create -output "$ROOT/target/desktop/gorse-cli" \
        "$ROOT/target/aarch64-apple-darwin/release/gorse" \
        "$ROOT/target/x86_64-apple-darwin/release/gorse"

    echo "Building universal Swift app ($CONFIG, HEDGEHOG_DESKTOP)..."
    (cd "$SCRIPT_DIR" && HEDGEHOG_SKIP_ESF=1 swift build -c "$CONFIG" --product HedgehogScanner \
        -Xswiftc -DHEDGEHOG_DESKTOP --arch arm64 --arch x86_64 --scratch-path "$SCRATCH")
fi

CLI_BIN="$ROOT/target/desktop/gorse-cli"
SWIFT_BIN="$SCRATCH/apple/Products/$(tr '[:lower:]' '[:upper:]' <<< "${CONFIG:0:1}")${CONFIG:1}/HedgehogScanner"
for bin in "$CLI_BIN" "$SWIFT_BIN"; do
    [[ -x "$bin" ]] || { echo "Missing build product: $bin" >&2; exit 1; }
    for arch in arm64 x86_64; do
        lipo "$bin" -verify_arch "$arch" || { echo "$bin lacks $arch" >&2; exit 1; }
    done
done

# ----------------------------------------------------------------- icon ----
mkdir -p "$OUTPUT_DIR"
ICNS="$OUTPUT_DIR/AppIcon.icns"
[[ -f "$ICON_SOURCE" ]] || { echo "Missing icon source $ICON_SOURCE" >&2; exit 1; }
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
APP="$OUTPUT_DIR/Gorse.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$INFO_PLIST" "$APP/Contents/Info.plist"
cp "$ICNS" "$APP/Contents/Resources/AppIcon.icns"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/LICENSE"
cp "$ROOT/LICENSE-THIRD-PARTY" "$APP/Contents/Resources/LICENSE-THIRD-PARTY"
cp "$SWIFT_BIN" "$APP/Contents/MacOS/Gorse"
cp "$CLI_BIN" "$APP/Contents/MacOS/gorse-cli"
chmod 755 "$APP/Contents/MacOS/"*
/usr/bin/xattr -cr "$APP"

# ----------------------------------------------------------------- sign ----
TEMP="$(mktemp -d "${TMPDIR:-/tmp}/gorse-desktop-sign.XXXXXXXX")"
trap 'rm -rf "$TEMP"' EXIT
APP_ENT="$TEMP/app.entitlements"
cp "$APP_ENTITLEMENTS" "$APP_ENT"
# The identifier entitlements belong to App Store builds, which carry a
# provisioning profile that grants them. A Developer ID app has no profile,
# and the kernel refuses to spawn a process whose entitlements it cannot
# vouch for ("Launchd job spawn failed"). So they go for every build here.
/usr/libexec/PlistBuddy -c "Delete :com.apple.application-identifier" "$APP_ENT"
/usr/libexec/PlistBuddy -c "Delete :com.apple.developer.team-identifier" "$APP_ENT"

sign() {  # sign PATH IDENTIFIER [ENTITLEMENTS]
    local ARGS=(--force --options runtime --identifier "$2")
    [[ -n "${3:-}" ]] && ARGS+=(--entitlements "$3")
    if [[ -n "$SIGN_IDENTITY" ]]; then
        ARGS+=(--timestamp --sign "$SIGN_IDENTITY")
    else
        ARGS+=(--sign -)
    fi
    codesign "${ARGS[@]}" "$1"
}

if [[ -n "$SIGN_IDENTITY" ]]; then echo "Code signing with identity: $SIGN_IDENTITY"; else echo "Code signing ad-hoc (local testing only)..."; fi
# Inside-out: the helper first, then the app, which seals the helper's hash.
sign "$APP/Contents/MacOS/gorse-cli" "is.hedgehog.app.cli"
sign "$APP" "is.hedgehog.app" "$APP_ENT"

echo "Verifying signature..."
codesign --verify --strict --deep --verbose=2 "$APP"

# -------------------------------------------------------------- package ----
ZIP_PATH="$OUTPUT_DIR/Gorse-macOS.zip"
zip_app() { rm -f "$ZIP_PATH"; ditto -c -k --keepParent "$APP" "$ZIP_PATH"; }
zip_app

if [[ "$NOTARIZE" == 1 ]]; then
    echo "Notarizing..."
    REPORT="$TEMP/notarization.json"
    xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$HEDGEHOG_NOTARY_PROFILE" --wait --output-format json > "$REPORT"
    if [[ "$(plutil -extract status raw -o - "$REPORT")" != "Accepted" ]]; then
        echo "Notarization was not accepted; the app cannot ship." >&2; cat "$REPORT" >&2; exit 1
    fi
    xcrun stapler staple "$APP"
    xcrun stapler validate "$APP"
    spctl --assess --type execute --verbose=2 "$APP"
    zip_app
fi

# ------------------------------------------------------------------ dmg ----
# A disk image with the app and a shortcut to /Applications is the install
# people recognise: open, drag, done. Built from the stapled app, then
# signed and notarized in its own right.
#
# The window is laid out the way installers conventionally look: a fixed
# 600x400 Finder window in icon view, the app on the left, the Applications
# shortcut on the right, an arrow between them on a background picture, the
# volume carrying the app icon. Finder is the only thing that can write that
# layout (.DS_Store), so the image is first created read-write, attached, laid
# out by Finder over AppleScript, detached, then compressed to UDZO. The
# Finder step needs Automation permission for the terminal; without it the
# image still ships, only plainer.
DMG_PATH="$OUTPUT_DIR/Gorse-macOS.dmg"
DMG_VOLNAME="Gorse"
DMG_STAGE="$TEMP/dmg"
DMG_RW="$TEMP/Gorse-rw.dmg"
DMG_DEV=""
detach_dmg() { [[ -n "$DMG_DEV" ]] && hdiutil detach "$DMG_DEV" -force >/dev/null 2>&1; DMG_DEV=""; }
trap 'detach_dmg; rm -rf "$TEMP"' EXIT

rm -rf "$DMG_STAGE"; mkdir -p "$DMG_STAGE/.background"
ditto "$APP" "$DMG_STAGE/Gorse.app"
ln -s /Applications "$DMG_STAGE/Applications"
cp "$ICNS" "$DMG_STAGE/.VolumeIcon.icns"

# Background picture: one PNG each for 1x and 2x, folded into a TIFF with both
# so Finder draws it sharp on Retina displays. Falls back to the 1x PNG.
DMG_BG_SRC="$TEMP/dmg-background"
swift "$SCRIPT_DIR/scripts/dmg-background.swift" "$DMG_BG_SRC"
DMG_BG_NAME="background.tiff"
if ! tiffutil -cathidpicheck "$DMG_BG_SRC/background.png" "$DMG_BG_SRC/background@2x.png" \
        -out "$DMG_STAGE/.background/$DMG_BG_NAME" >/dev/null 2>&1; then
    DMG_BG_NAME="background.png"
    cp "$DMG_BG_SRC/background.png" "$DMG_STAGE/.background/$DMG_BG_NAME"
fi

# A volume with this name from an earlier run (or an opened download) would
# push the new one to "Gorse 1" and confuse the Finder script.
hdiutil info | awk -F'\t' -v vol="/Volumes/$DMG_VOLNAME" \
        '$NF == vol || $NF ~ ("^" vol " [0-9]+$") { print $NF }' | while read -r stale; do
    echo "Detaching stale volume $stale"
    hdiutil detach "$stale" -force >/dev/null 2>&1 || true
done

rm -f "$DMG_RW" "$DMG_PATH"
DMG_SIZE_KB=$(( $(du -sk "$DMG_STAGE" | cut -f1) + 8192 ))
hdiutil create -volname "$DMG_VOLNAME" -srcfolder "$DMG_STAGE" -ov -format UDRW -fs HFS+ \
    -size "${DMG_SIZE_KB}k" "$DMG_RW" >/dev/null
ATTACH_PLIST="$TEMP/dmg-attach.plist"
hdiutil attach "$DMG_RW" -readwrite -noverify -noautoopen -plist > "$ATTACH_PLIST"
# The mounted filesystem is the one entity with a mount-point; take its device
# and path from hdiutil rather than assuming /Volumes/Gorse.
DMG_MOUNT=""
ENTITY_COUNT=$(plutil -extract system-entities raw -o - "$ATTACH_PLIST")
for ((i = 0; i < ENTITY_COUNT; i++)); do
    if mp=$(plutil -extract "system-entities.$i.mount-point" raw -o - "$ATTACH_PLIST" 2>/dev/null); then
        DMG_MOUNT="$mp"
        DMG_DEV=$(plutil -extract "system-entities.$i.dev-entry" raw -o - "$ATTACH_PLIST")
        break
    fi
done
[[ -n "$DMG_MOUNT" && -d "$DMG_MOUNT" ]] || { echo "Could not find the mount point of $DMG_RW" >&2; exit 1; }
echo "Laying out the disk image window at $DMG_MOUNT..."

DMG_FINDER_NAME="$(basename "$DMG_MOUNT")"
if ! osascript >/dev/null <<APPLESCRIPT
tell application "Finder"
    tell disk "$DMG_FINDER_NAME"
        open
        set theWindow to container window
        set current view of theWindow to icon view
        set toolbar visible of theWindow to false
        try
            set statusbar visible of theWindow to false
            set sidebar width of theWindow to 0
        end try
        set bounds of theWindow to {200, 160, 800, 560}
        set theOptions to icon view options of theWindow
        set arrangement of theOptions to not arranged
        set icon size of theOptions to 128
        set text size of theOptions to 13
        set background picture of theOptions to file ".background:$DMG_BG_NAME"
        -- Positions set while the toolbar is still being hidden land 45 points
        -- low once the window reopens, so reopen first, then place the icons.
        close
        open
        set theWindow to container window
        set position of item "Gorse.app" of theWindow to {150, 190}
        set position of item "Applications" of theWindow to {450, 190}
        -- Park the housekeeping files far outside the window so they stay out
        -- of sight for people whose Finder shows hidden files.
        repeat with dotName in {".background", ".fseventsd", ".VolumeIcon.icns", ".DS_Store", ".Trashes"}
            try
                set position of item dotName of theWindow to {1500, 1500}
            end try
        end repeat
        close
        open
        delay 1
        close
    end tell
end tell
APPLESCRIPT
then
    echo "WARNING: Finder could not lay out the disk image window (is this terminal allowed to" >&2
    echo "         control Finder under System Settings > Privacy & Security > Automation?)." >&2
    echo "         The image will open in a plain Finder window." >&2
fi
# The volume shows the app icon: Finder reads .VolumeIcon.icns when the root
# folder carries the custom-icon flag. (Not `update` in the Finder script:
# on macOS 26 that deletes .VolumeIcon.icns and clears the flag.)
if SETFILE="$(xcrun -f SetFile 2>/dev/null)"; then
    "$SETFILE" -a C "$DMG_MOUNT"
else
    xattr -wx com.apple.FinderInfo \
        "0000000000000000040000000000000000000000000000000000000000000000" "$DMG_MOUNT"
fi
sync
detach_dmg
hdiutil convert "$DMG_RW" -format UDZO -imagekey zlib-level=9 -ov -o "$DMG_PATH" >/dev/null
rm -f "$DMG_RW"
# The licence sheet (Agree / Disagree before the volume mounts) must go on
# before the image is signed, because it rewrites the file.
node "$ROOT/esf_client/scripts/dmg-licence.ts" "$DMG_PATH" "$ROOT/LICENSE"
if [[ -n "$SIGN_IDENTITY" ]]; then
    codesign --force --timestamp --sign "$SIGN_IDENTITY" "$DMG_PATH"
    if [[ "$NOTARIZE" == 1 ]]; then
        echo "Notarizing the disk image..."
        REPORT_DMG="$TEMP/notarization-dmg.json"
        xcrun notarytool submit "$DMG_PATH" --keychain-profile "$HEDGEHOG_NOTARY_PROFILE" --wait --output-format json > "$REPORT_DMG"
        if [[ "$(plutil -extract status raw -o - "$REPORT_DMG")" != "Accepted" ]]; then
            echo "Disk image notarization was not accepted; it cannot ship." >&2; cat "$REPORT_DMG" >&2; exit 1
        fi
        xcrun stapler staple "$DMG_PATH"
        spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG_PATH"
    fi
fi

(cd "$OUTPUT_DIR" && shasum -a 256 "$(basename "$ZIP_PATH")" "$(basename "$DMG_PATH")" > SHA256SUMS-app)
echo ""
echo "Created: $APP"
echo "         $DMG_PATH"
echo "         $ZIP_PATH"
