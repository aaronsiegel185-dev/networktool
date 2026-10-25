# Running it

Three stages. Each one works on its own, so stop wherever you have what you need.

```bash
git clone https://github.com/aaronsiegel185-dev/networktool.git
cd networktool
git checkout claude/network-tool-repo-0od69n
```

---

## 1. Network Tool — nothing to install

Python 3.8+ and nothing else. On a Mac the system Python is enough
(`xcode-select --install` if you have never run it).

```bash
python3 -m toolbox net iface          # what interfaces this machine has
python3 -m toolbox net diag           # link, addressing, gateway, DNS, path MTU
python3 -m toolbox net wifi --analyze # channel congestion and who is interfering
```

Discovery and capture need raw sockets, so those take `sudo`:

```bash
sudo python3 -m toolbox net discover            # what is on this LAN
sudo python3 -m toolbox net capture -i en0 -c 200 -w out.pcap
python3 -m toolbox net analyze out.pcap         # reading it back needs no sudo
```

**Optional:** `pip install .` puts `toolbox`, `nettool` and `assist` on your
PATH, so you can drop the `python3 -m` everywhere below.

---

## 2. The desktop app

Needs [Rust](https://rustup.rs). First build takes a few minutes.

```bash
cd gui
cargo run --release
```

Or build a double-clickable Mac app:

```bash
./gui/macos/build-app.sh                    # --universal for Intel + Apple Silicon
open gui/target/macos/nettool.app           # then drag it to /Applications
```

The bundle carries the CLI inside it, so the app is self-contained.

It opens on **Assist**. Until you do stage 3, the banner will say the model
server is not running — the **Network Tool** section at the top left works
regardless.

---

## 3. Assist — the local AI

```bash
./setup-assist.sh
```

This installs [Ollama](https://ollama.com), reads how much memory the machine
has, picks a text model and a vision model that fit, pulls them, and checks that
Assist can reach the result. The model download is large — several GB — and is
the only thing here that uses the internet. After it, everything runs offline.

If the machine is tight on memory:

```bash
./setup-assist.sh --small --text-only       # lightest, no screenshot reading
```

Then:

```bash
toolbox assist new "Wi-Fi drops every afternoon" -b "Starts around 2pm."
toolbox assist add <notebook> capture.pcap wifi.log ~/Desktop/screenshot.png
toolbox assist ask <notebook> "what should I check first?"
```

Check it before you trust it with anything:

```bash
toolbox assist doctor      # where the model runs; says "data leaves this machine: NO"
toolbox assist prompt <notebook>   # exactly what would be sent, in full
```

---

## Clients and documentation

Optional, and worth it the second time you touch the same network.

```bash
toolbox assist client new "Acme Corp" --fact firewall=203.0.113.1
toolbox assist new "VPN flapping" --client acme    # carries their setup with it
```

If your documentation already lives somewhere, pull it in instead of typing it:

```bash
toolbox assist connector add folder --path ~/docs      # no network at all
toolbox assist connector add netbox --url http://netbox.lan --token-file ~/.nb
toolbox assist connector link netbox acme
toolbox assist sync acme
```

---

## If something does not work

| What you see | What it means |
| --- | --- |
| `no wireless interface found` | the Wi-Fi commands need a real radio; a VM or a wired-only box has none |
| `Operation not permitted` on capture | run it with `sudo`, or `sudo ./gui/macos/install-bpf-access.sh` once to avoid needing it |
| SSIDs show as `<redacted>` on macOS | grant Location Services to the app — macOS hides network names otherwise |
| `model server not running` | `ollama serve`, or `brew services start ollama` to have it always up |
| `pull llama3.1:8b` in the banner | the model was not downloaded: `ollama pull llama3.1:8b` |
| a connector says `401` | the API token is wrong or expired; `toolbox assist connector check` tells you which |

Everything else: `toolbox net --help`, `toolbox assist --help`, and
[README.md](README.md) for the full reference.
