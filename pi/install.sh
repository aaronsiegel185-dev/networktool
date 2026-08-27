#!/bin/bash
# Install nettool on a Raspberry Pi (or any systemd Linux) as a network probe.
#
# Leaves behind:
#   /opt/nettool                 the code
#   /usr/local/bin/nettool       the command, on everyone's PATH
#   /etc/nettool/token           the pairing token, readable only by the service
#   /var/lib/nettool/captures    where captures are written
#   nettool-serve.service        the API, running as its own unprivileged user
#
# The service is not run as root. Packet capture needs two capabilities and
# systemd can grant exactly those, which is a great deal less than handing the
# machine to something that listens on the network.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/nettool
BIN=/usr/local/bin/nettool
CONF=/etc/nettool
STATE=/var/lib/nettool
SERVICE=nettool-serve.service
USERNAME=nettool

say()  { printf '\033[36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m warning:\033[0m %s\n' "$1"; }
die()  { printf '\033[31m error:\033[0m %s\n' "$1" >&2; exit 1; }

WITH_SERVICE=1
for arg in "$@"; do
    case "$arg" in
        --no-service) WITH_SERVICE=0 ;;
        -h|--help)
            sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown option: $arg (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this with sudo: sudo $0"

# --- what we are running on ------------------------------------------------
if [ -r /proc/device-tree/model ]; then
    say "$(tr -d '\0' < /proc/device-tree/model)"
elif [ -r /etc/os-release ]; then
    say "$(. /etc/os-release && echo "$PRETTY_NAME")"
fi

python3 - <<'PYCHECK' || die "nettool needs Python 3.8 or newer"
import sys
raise SystemExit(0 if sys.version_info >= (3, 8) else 1)
PYCHECK
say "python $(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"

# --- optional tools --------------------------------------------------------
# Nothing here is required: the Wi-Fi views fall back through iw, nmcli and
# /proc in that order, and say so when none of them is present.
MISSING=()
command -v iw    >/dev/null 2>&1 || MISSING+=(iw)
command -v nmcli >/dev/null 2>&1 || MISSING+=(network-manager)
if [ ${#MISSING[@]} -gt 0 ] && command -v apt-get >/dev/null 2>&1; then
    say "Installing optional tools: ${MISSING[*]}"
    apt-get update -qq
    # iw is what the Wi-Fi scan and the airtime survey use; without it the
    # radio views are limited to what /proc reports.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING[@]}" \
        || warn "could not install ${MISSING[*]}; the Wi-Fi views will be limited"
fi

# --- the code --------------------------------------------------------------
say "Installing to $PREFIX"
install -d -m 755 "$PREFIX"
rm -rf "$PREFIX/nettool"
cp -R "$REPO/nettool" "$PREFIX/nettool"
find "$PREFIX/nettool" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
chmod -R a+rX "$PREFIX"

cat > "$BIN" <<LAUNCH
#!/bin/sh
# nettool, installed by pi/install.sh
exec python3 -m nettool "\$@"
LAUNCH
chmod 755 "$BIN"
# -m nettool has to find the package, and $PREFIX is not on sys.path by default.
sed -i "2i export PYTHONPATH=\"$PREFIX\${PYTHONPATH:+:\$PYTHONPATH}\"" "$BIN"

say "Checking it runs"
"$BIN" --version >/dev/null || die "the installed command does not run"

if [ "$WITH_SERVICE" -eq 0 ]; then
    say "Done. The service was not installed (--no-service)."
    printf '\n  nettool iface\n  nettool wifi analyze\n  sudo nettool capture -i eth0 -d 10 -w /tmp/out.pcap\n\n'
    exit 0
fi

# --- the service -----------------------------------------------------------
# systemctl being on PATH proves nothing - it is present in containers and on
# machines booted with another init, where daemon-reload simply fails.
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    warn "systemd is not running here, so the service was skipped."
    warn "The command still works; start the API by hand with:"
    warn "    sudo nettool serve --lan"
    exit 0
fi

if ! id "$USERNAME" >/dev/null 2>&1; then
    say "Creating the $USERNAME user"
    useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$USERNAME"
fi

install -d -m 750 -o "$USERNAME" -g "$USERNAME" "$STATE" "$STATE/captures"
install -d -m 750 "$CONF"

if [ ! -s "$CONF/token" ]; then
    say "Generating a pairing token"
    python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "$CONF/token"
fi
# Only the service reads this. A token that anyone on the box can read is not
# one, and the server refuses to start with a world-readable file anyway.
chown "$USERNAME:$USERNAME" "$CONF/token"
chmod 600 "$CONF/token"

say "Installing $SERVICE"
install -m 644 "$REPO/pi/$SERVICE" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload
systemctl enable --now "$SERVICE"

sleep 2
if ! systemctl is-active --quiet "$SERVICE"; then
    warn "the service did not come up; the last few log lines:"
    journalctl -u "$SERVICE" -n 15 --no-pager || true
    exit 1
fi

ADDRESS="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="$(cat "$CONF/token")"
say "Running as $USERNAME, enabled at boot"

cat <<NEXT

  Pair a phone or a Mac with this link:

      nettool://${ADDRESS:-<this-pi>}:8765/?token=$TOKEN

  The Pi also advertises itself over Bonjour as "$(hostname)", so the iOS app
  should find it without the address.

  Useful afterwards:

      systemctl status $SERVICE
      journalctl -u $SERVICE -f
      sudo cat $CONF/token          # the pairing token again
      sudo $0                       # re-run to upgrade in place

NEXT
