#!/bin/bash
# Let your user capture packets without sudo, the same way Wireshark's ChmodBPF does.
#
#   sudo ./gui/macos/install-bpf-access.sh
#
# It creates an `access_bpf` group, puts you in it, and installs a LaunchDaemon that
# chowns /dev/bpf* to that group at every boot. Undo with uninstall-bpf-access.sh.
set -euo pipefail

PLIST=/Library/LaunchDaemons/dev.nettool.ChmodBPF.plist
HELPER=/Library/Application\ Support/nettool/ChmodBPF
GROUP=access_bpf

if [[ $EUID -ne 0 ]]; then
    echo "error: run this with sudo." >&2
    exit 1
fi

TARGET_USER="${SUDO_USER:-$(stat -f '%Su' /dev/console)}"
echo "==> granting BPF access to user: $TARGET_USER"

if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    echo "==> creating group $GROUP"
    # Pick a free group id in the system range.
    GID=$(dscl . -list /Groups PrimaryGroupID | awk '$2 > 500 && $2 < 700 {print $2}' | sort -n | tail -1)
    GID=$(( ${GID:-500} + 1 ))
    dscl . -create "/Groups/$GROUP"
    dscl . -create "/Groups/$GROUP" PrimaryGroupID "$GID"
    dscl . -create "/Groups/$GROUP" RealName "nettool packet capture access"
    dscl . -create "/Groups/$GROUP" Password "*"
fi

dseditgroup -o edit -a "$TARGET_USER" -t user "$GROUP" 2>/dev/null || true

mkdir -p "$(dirname "$HELPER")"
cat > "$HELPER" <<'HELPER_EOF'
#!/bin/sh
# Hand the BPF devices to the access_bpf group so packet capture works without root.
syslog -s -l notice "nettool ChmodBPF: adjusting /dev/bpf* permissions"
chgrp access_bpf /dev/bpf*
chmod g+rw /dev/bpf*
HELPER_EOF
chmod +x "$HELPER"

cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.nettool.ChmodBPF</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HELPER</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
PLIST_EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo "==> done"
echo "Log out and back in (or run 'newgrp $GROUP') so the new group membership applies."
echo "Then capture, LLDP and ARP sweeps work from the app without sudo."
