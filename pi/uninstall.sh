#!/bin/bash
# Remove everything pi/install.sh put on this machine.
set -euo pipefail

SERVICE=nettool-serve.service
say() { printf '\033[36m==>\033[0m %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo" >&2; exit 1; }

KEEP_CAPTURES=1
[ "${1:-}" = "--purge" ] && KEEP_CAPTURES=0

if command -v systemctl >/dev/null 2>&1 && \
   systemctl list-unit-files "$SERVICE" >/dev/null 2>&1; then
    say "Stopping $SERVICE"
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE"
    systemctl daemon-reload
fi

say "Removing the command and the code"
rm -f /usr/local/bin/nettool
rm -rf /opt/nettool

if [ "$KEEP_CAPTURES" -eq 0 ]; then
    say "Removing captures, the token and the user"
    rm -rf /var/lib/nettool /etc/nettool
    userdel nettool 2>/dev/null || true
else
    # Captures are the point of the exercise; deleting someone's evidence
    # because they uninstalled a tool would be a poor thankyou.
    say "Kept /var/lib/nettool (captures) and /etc/nettool (token)"
    say "Run with --purge to remove those too"
fi
say "Done"
