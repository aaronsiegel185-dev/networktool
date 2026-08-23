#!/bin/bash
# Build nettool.app - a double-clickable macOS application bundle.
#
#   ./gui/macos/build-app.sh                 # build for this Mac
#   ./gui/macos/build-app.sh --universal     # Intel + Apple Silicon in one binary
#   ./gui/macos/build-app.sh --dmg           # also produce nettool.dmg
#
# The bundle carries the Python CLI inside Contents/Resources, so the app is
# self-contained apart from the system Python that ships with macOS.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUI_DIR="$(cd "$HERE/.." && pwd)"
REPO_DIR="$(cd "$GUI_DIR/.." && pwd)"
APP_NAME="nettool"
BUILD_DIR="$GUI_DIR/target/macos"
APP="$BUILD_DIR/$APP_NAME.app"
UNIVERSAL=0
MAKE_DMG=0

for arg in "$@"; do
    case "$arg" in
        --universal) UNIVERSAL=1 ;;
        --dmg) MAKE_DMG=1 ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script builds a macOS bundle and must run on macOS." >&2
    exit 1
fi
command -v cargo >/dev/null || { echo "error: cargo not found - install Rust from https://rustup.rs" >&2; exit 1; }

VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$GUI_DIR/Cargo.toml" | head -1)"
VERSION="${VERSION:-0.1.0}"
echo "==> building nettool.app $VERSION"

cd "$GUI_DIR"
if [[ $UNIVERSAL -eq 1 ]]; then
    rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
    cargo build --release --target aarch64-apple-darwin
    cargo build --release --target x86_64-apple-darwin
    BINARY="$BUILD_DIR/nettool-gui-universal"
    mkdir -p "$BUILD_DIR"
    lipo -create -output "$BINARY" \
        "target/aarch64-apple-darwin/release/nettool-gui" \
        "target/x86_64-apple-darwin/release/nettool-gui"
else
    cargo build --release
    BINARY="$GUI_DIR/target/release/nettool-gui"
fi

echo "==> assembling bundle"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINARY" "$APP/Contents/MacOS/nettool-gui"
chmod +x "$APP/Contents/MacOS/nettool-gui"
sed "s/@VERSION@/$VERSION/g" "$HERE/Info.plist" > "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# The CLI that does the actual work.
cp -R "$REPO_DIR/nettool" "$APP/Contents/Resources/nettool"
find "$APP/Contents/Resources/nettool" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

echo "==> icon"
ICONSET="$BUILD_DIR/nettool.iconset"
rm -rf "$ICONSET"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
    sips -z $size $size "$HERE/icon.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z $double $double "$HERE/icon.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/nettool.icns"
rm -rf "$ICONSET"

echo "==> signing (ad-hoc)"
# Ad-hoc signature: enough for Gatekeeper to run it locally after the first
# right-click -> Open. Replace with your Developer ID to distribute it.
codesign --force --deep --sign - "$APP" 2>/dev/null || \
    echo "    warning: codesign failed; the app still runs via right-click -> Open"

echo "==> done: $APP"
echo
echo "Run it:            open '$APP'"
echo "Install it:        cp -R '$APP' /Applications/"
echo "Capture without sudo (once):  sudo '$HERE/install-bpf-access.sh'"

if [[ $MAKE_DMG -eq 1 ]]; then
    echo "==> building dmg"
    DMG_DIR="$BUILD_DIR/dmg"
    rm -rf "$DMG_DIR" "$BUILD_DIR/$APP_NAME.dmg"
    mkdir -p "$DMG_DIR"
    cp -R "$APP" "$DMG_DIR/"
    ln -s /Applications "$DMG_DIR/Applications"
    hdiutil create -volname "$APP_NAME" -srcfolder "$DMG_DIR" -ov -format UDZO \
        "$BUILD_DIR/$APP_NAME.dmg" >/dev/null
    rm -rf "$DMG_DIR"
    echo "==> done: $BUILD_DIR/$APP_NAME.dmg"
fi
