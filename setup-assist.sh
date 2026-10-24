#!/bin/bash
# Set up the local model that Assist talks to.
#
# Installs Ollama if it is not already there, picks models your machine can
# actually hold, pulls them, and checks that Assist can reach the result.
#
# Everything this sets up runs on this machine and listens on loopback only.
# The one thing that uses the internet is the download of Ollama and the model
# weights themselves - after that you can pull the plug and Assist still works.
#
#   ./setup-assist.sh                 choose models from this machine's memory
#   ./setup-assist.sh --small         the lightest usable pair
#   ./setup-assist.sh --text-only     skip the vision model (no screenshot reading)
#   ./setup-assist.sh --no-install    only pull models; do not install Ollama
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"

say()  { printf '\033[36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m warning:\033[0m %s\n' "$1"; }
die()  { printf '\033[31m error:\033[0m %s\n' "$1" >&2; exit 1; }

SIZE=auto
WITH_VISION=1
INSTALL=1
for arg in "$@"; do
    case "$arg" in
        --small)      SIZE=small ;;
        --large)      SIZE=large ;;
        --text-only)  WITH_VISION=0 ;;
        --no-install) INSTALL=0 ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown option: $arg (try --help)" ;;
    esac
done

# --- how much memory is there, really -------------------------------------
# A model has to fit in memory to run at a usable speed. If it does not, Ollama
# will still load it and it will crawl, so it is worth being honest up front.
total_memory_gb() {
    if [ "$(uname -s)" = "Darwin" ]; then
        echo $(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
    elif [ -r /proc/meminfo ]; then
        echo $(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
    else
        echo 0
    fi
}

RAM=$(total_memory_gb)
if [ "$RAM" -gt 0 ]; then
    say "this machine has about ${RAM} GB of memory"
else
    warn "could not read how much memory this machine has; assuming a small one"
    RAM=8
fi

if [ "$SIZE" = auto ]; then
    if   [ "$RAM" -ge 32 ]; then SIZE=large
    elif [ "$RAM" -ge 16 ]; then SIZE=medium
    else                         SIZE=small
    fi
fi

case "$SIZE" in
    small)  TEXT=llama3.2:3b;   TEXT_GB=2;  VISION=llama3.2-vision:11b; VISION_GB=8 ;;
    medium) TEXT=llama3.1:8b;   TEXT_GB=5;  VISION=llama3.2-vision:11b; VISION_GB=8 ;;
    large)  TEXT=llama3.1:70b;  TEXT_GB=40; VISION=llama3.2-vision:90b; VISION_GB=55 ;;
esac

say "picking the ${SIZE} pair: ${TEXT} (~${TEXT_GB} GB)"
[ "$WITH_VISION" -eq 1 ] && say "  and ${VISION} (~${VISION_GB} GB) for screenshots"

NEEDED=$TEXT_GB
[ "$WITH_VISION" -eq 1 ] && NEEDED=$VISION_GB   # they are not loaded at once
if [ "$RAM" -lt "$NEEDED" ]; then
    warn "${NEEDED} GB of weights on a ${RAM} GB machine will be slow."
    warn "Try: $0 --small --text-only"
fi

# --- Ollama ----------------------------------------------------------------
if ! command -v ollama >/dev/null 2>&1; then
    [ "$INSTALL" -eq 1 ] || die "ollama is not installed, and --no-install was given"
    case "$(uname -s)" in
        Darwin)
            if command -v brew >/dev/null 2>&1; then
                say "installing Ollama with Homebrew"
                brew install ollama
            else
                die "install Ollama from https://ollama.com/download, then run this again"
            fi ;;
        Linux)
            say "installing Ollama (this downloads and runs Ollama's own installer)"
            curl -fsSL https://ollama.com/install.sh | sh ;;
        *) die "unsupported system: $(uname -s). Install Ollama by hand, then use --no-install" ;;
    esac
else
    say "ollama is already installed: $(command -v ollama)"
fi

# --- make sure it is serving ----------------------------------------------
# `ollama pull` needs the server up. On macOS the app starts it; under systemd
# the installer enables a unit; otherwise we start one here for this session.
STARTED_SERVER=0
if ! curl -fsS --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        say "starting the ollama service"
        sudo systemctl enable --now ollama 2>/dev/null || true
    fi
    if ! curl -fsS --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        say "starting ollama serve in the background"
        ollama serve >/tmp/ollama-setup.log 2>&1 &
        STARTED_SERVER=$!
        for _ in $(seq 1 30); do
            curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
            sleep 1
        done
    fi
fi
curl -fsS --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 \
    || die "ollama is not answering on 127.0.0.1:11434 (see /tmp/ollama-setup.log)"
say "the model server is answering on 127.0.0.1:11434"

# --- the weights -----------------------------------------------------------
say "pulling ${TEXT} - this is the download, and it is large"
ollama pull "$TEXT"
if [ "$WITH_VISION" -eq 1 ]; then
    say "pulling ${VISION} - this is what reads your screenshots"
    ollama pull "$VISION"
fi

# --- point Assist at it ----------------------------------------------------
ASSIST=(python3 -m assist)
command -v toolbox >/dev/null 2>&1 && ASSIST=(toolbox assist)
run_assist() { (cd "$REPO" && "${ASSIST[@]}" "$@"); }

say "pointing Assist at the local server"
run_assist config --set endpoint=http://127.0.0.1:11434/v1 \
                  --set "text_model=$TEXT" >/dev/null
if [ "$WITH_VISION" -eq 1 ]; then
    run_assist config --set "vision_model=$VISION" >/dev/null
else
    # Leaving a vision model named that was never pulled would have Assist
    # reach for it the moment a screenshot is dropped in, and fail there.
    run_assist config --set "vision_model=" >/dev/null
    warn "no vision model: screenshots can be attached, but not read."
fi

if ! command -v ffmpeg >/dev/null 2>&1; then
    warn "ffmpeg is not installed: screenshots work, screen recordings will not."
    case "$(uname -s)" in
        Darwin) warn "  brew install ffmpeg" ;;
        Linux)  warn "  sudo apt install ffmpeg" ;;
    esac
fi

say "checking what Assist sees"
run_assist doctor

cat <<EOF

Ready. Nothing in a notebook leaves this machine.

  toolbox assist new "Wi-Fi drops every afternoon"
  toolbox assist add <notebook> span.pcap wifi.log ~/Desktop/shot.png
  toolbox assist ask <notebook> "what should I check first?"
  toolbox assist prompt <notebook>      # exactly what would be sent

Or open the desktop app, which starts in the Assist section.
EOF

if [ "$STARTED_SERVER" -ne 0 ]; then
    echo
    warn "ollama was started just for this setup (pid $STARTED_SERVER)."
    warn "To have it always running: 'brew services start ollama' on macOS,"
    warn "or 'sudo systemctl enable --now ollama' on Linux."
fi
