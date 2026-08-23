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
# normal to have got this far without ever installing Xcode itself.
if ! command -v xcodebuild >/dev/null 2>&1; then
    die "Xcode is not installed. The Mac app and CLI only need the command line
       tools, but building for iPad needs the full Xcode from the App Store.
       Install it, open it once to accept the licence, then run this again."
fi

DEVELOPER_DIR="$(xcode-select -p 2>/dev/null || true)"
case "$DEVELOPER_DIR" in
    *CommandLineTools*)
        die "xcode-select points at the command line tools, not Xcode itself:
         $DEVELOPER_DIR
       Point it at Xcode and try again:
         sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
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
