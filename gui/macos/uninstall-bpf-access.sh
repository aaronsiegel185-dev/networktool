#!/bin/bash
# Remove what install-bpf-access.sh set up.
set -euo pipefail

PLIST=/Library/LaunchDaemons/dev.nettool.ChmodBPF.plist
HELPER_DIR=/Library/Application\ Support/nettool

if [[ $EUID -ne 0 ]]; then
    echo "error: run this with sudo." >&2
    exit 1
fi

launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
rm -rf "$HELPER_DIR"
echo "==> removed the ChmodBPF daemon"
echo "The access_bpf group was left in place; delete it with:"
echo "  sudo dseditgroup -o delete -t group access_bpf"
echo "BPF permissions reset at the next reboot."
