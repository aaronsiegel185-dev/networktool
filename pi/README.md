# nettool on a Raspberry Pi

A Pi makes a good permanent probe: leave one plugged into the switch you care
about, and the Mac app and the iPhone app can both drive it from anywhere on the
network. It captures, it scans, it watches the Wi-Fi, and it costs nothing to
leave running.

## Install

On the Pi:

```bash
git clone https://github.com/aaronsiegel185-dev/networktool.git
cd networktool
sudo ./pi/install.sh
```

That installs the code to `/opt/nettool`, puts `nettool` on everyone's PATH,
generates a pairing token, and starts the API as a service that comes back after
a reboot. It prints a pairing link at the end - open that on your phone and the
app is connected.

`--no-service` installs the command only, if you would rather run things by hand.

Re-running the installer upgrades in place and keeps the existing token, so
paired devices stay paired.

## What it runs as

Not root. Packet capture on Linux needs `CAP_NET_RAW` and `CAP_NET_ADMIN`, and
systemd can grant exactly those two to an ordinary user - which is a great deal
less than handing the machine to a service that listens on the network. The unit
also gets `ProtectSystem=strict`, a private `/tmp`, and write access to nothing
but `/var/lib/nettool`.

The pairing token lives in `/etc/nettool/token`, mode 600, owned by the service
user. It is passed to the process as a filename rather than an argument, because
a command line is visible to every user on the box through `ps` - and the server
refuses to start if the file is readable by anyone else.

## Afterwards

```bash
systemctl status nettool-serve         # is it up
journalctl -u nettool-serve -f         # what is it doing
sudo cat /etc/nettool/token            # the pairing token again
sudo systemctl restart nettool-serve   # after changing anything
```

Captures written by the API land in `/var/lib/nettool/captures`, which is what
the app's "Captures on the Mac" list shows.

## What works on a Pi, and what does not

Everything the Linux build does, which is all of it bar the platform-specific
parts:

| | On a Pi |
|---|---|
| Capture, mirror/VLAN, LLDP/CDP, analysis | yes - AF_PACKET, no driver needed |
| Discover, port scan, ping, traceroute, MTU | yes |
| Wi-Fi scan, link quality, interference | yes, with `iw` (the installer adds it) |
| Airtime survey | yes - Linux is the only platform that reports it |
| **Monitor mode on the built-in radio** | no - see below |
| The desktop GUI | buildable, but see below |

**Monitor mode.** The Pi's onboard Broadcom radio does not support it. The
`brcmfmac` driver has no monitor mode worth the name, and no amount of software
changes that - an external USB adapter with an Atheros or Ralink chipset is the
usual answer. Everything else in the Wi-Fi tab works on the built-in radio.

**The desktop GUI** is a Rust/egui app and will build on a Pi 4 or 5 with a
desktop image, but slowly and to little purpose: the point of a Pi here is to be
the thing your Mac and phone talk to, not the thing you sit in front of. Install
with `--no-service` and build `gui/` by hand if you want it anyway.

**Older Pis.** Anything running Python 3.8 or newer works, which means Raspberry
Pi OS Buster and later. A Pi Zero will run the CLI and the API perfectly well;
capture on a saturated gigabit link is where it will start dropping frames, and
the capture summary reports kernel drops when that happens rather than quietly
losing packets.

## Removing it

```bash
sudo ./pi/uninstall.sh            # keeps captures and the token
sudo ./pi/uninstall.sh --purge    # removes those too
```
