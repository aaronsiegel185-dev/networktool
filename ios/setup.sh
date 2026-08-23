#!/bin/bash
# Get the app ready to build for an iPad or iPhone.
#
# Everything that goes wrong here goes wrong before any code is compiled -
# Command Line Tools instead of full Xcode, no xcodegen, no device trusted - so
# this checks each one and says exactly what to do rather than letting Xcode
# fail obliquely later.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

say()  { printf '\033[36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m warning:\033[0m %s\n' "$1"; }
die()  { printf '\033[31m error:\033[0m %s\n' "$1" >&2; exit 1; }

# --- full Xcode, not just the command line tools ---------------------------
# The CLT are enough for the Mac GUI and the Python CLI, so it is entirely
# normal to have got this far without ever installing Xcode itself. Note that
# `xcodebuild` exists as a stub inside the CLT, so its presence proves nothing -
# what matters is where xcode-select points and whether Xcode.app is there.

find_xcode() {
    # The usual place first, then anywhere Spotlight knows about, since Xcode
    # is often kept on a second volume once it has eaten 15 GB.
    local candidate
    for candidate in /Applications/Xcode.app /Applications/Xcode-beta.app; do
        [ -d "$candidate" ] && { printf '%s' "$candidate"; return 0; }
    done
    if command -v mdfind >/dev/null 2>&1; then
        candidate="$(mdfind "kMDItemCFBundleIdentifier == 'com.apple.dt.Xcode'"                      2>/dev/null | head -1)"
        [ -n "$candidate" ] && [ -d "$candidate" ] && { printf '%s' "$candidate"; return 0; }
    fi
    return 1
}

DEVELOPER_DIR="$(xcode-select -p 2>/dev/null || true)"
case "$DEVELOPER_DIR" in
    *Xcode*) ;;                     # already pointed at a real Xcode
    *)
        if XCODE="$(find_xcode)"; then
            die "Xcode is installed at $XCODE, but the developer directory still
       points at the command line tools:
         ${DEVELOPER_DIR:-none}
       Point it at Xcode and run this again:
         sudo xcode-select -s \"$XCODE/Contents/Developer\""
        else
            die "Xcode is not installed. The Mac app and the CLI only need the
       command line tools, which is why everything so far has worked - but
       building for an iPad needs the full Xcode.
       Install it from the App Store (it is around 15 GB and takes a while):
         https://apps.apple.com/app/xcode/id497799835
       Open it once so it can finish setting up, then run this again."
        fi
        ;;
esac

if ! xcodebuild -version >/dev/null 2>&1; then
    die "xcodebuild will not run - open Xcode once to accept its licence,
       or run: sudo xcodebuild -license accept"
fi
say "$(xcodebuild -version | head -1)"

# --- an iOS SDK, which a Mac-only Xcode install can be missing --------------
if ! xcodebuild -showsdks 2>/dev/null | grep -q "iphoneos"; then
    die "no iOS SDK found. In Xcode: Settings > Components, install the iOS
       platform, then run this again."
fi

# --- xcodegen --------------------------------------------------------------
if ! command -v xcodegen >/dev/null 2>&1; then
    if command -v brew >/dev/null 2>&1; then
        say "Installing xcodegen"
        brew install xcodegen
    else
        die "xcodegen is missing and Homebrew is not installed.
       Install Homebrew from https://brew.sh, then: brew install xcodegen"
    fi
fi

say "Generating Nettool.xcodeproj"
xcodegen generate

# --- what is plugged in ----------------------------------------------------
say "Devices Xcode can see"
DEVICES="$(xcrun xctrace list devices 2>/dev/null | sed -n '/^== Devices ==/,/^== /p' \
           | grep -v '^==' | grep -v '^$' || true)"
if [ -n "$DEVICES" ]; then
    printf '%s\n' "$DEVICES" | sed 's/^/    /'
else
    warn "no devices listed. Plug the iPad in with a cable, unlock it, and tap
          Trust when it asks."
fi

cat <<'NEXT'

Next, in Xcode:

  1. open Nettool.xcodeproj
  2. select the Nettool target -> Signing & Capabilities
  3. tick "Automatically manage signing" and choose your Team
     (a free Apple ID works - add it under Xcode > Settings > Accounts)
  4. if the bundle identifier is refused as taken, change it to something
     of your own, e.g. dev.yourname.nettool
  5. choose your iPad in the run destination menu at the top
  6. press Run

The first launch on the device will refuse to open until you trust the
certificate: on the iPad, Settings > General > VPN & Device Management >
your Apple ID > Trust.

With a free Apple ID the build stops working after seven days. Rebuilding
from Xcode resets it; nothing is lost.
NEXT
