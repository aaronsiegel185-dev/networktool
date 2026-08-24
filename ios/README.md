# nettool for iPhone

A packet-capture reader and network diagnostics app, and a remote control for
`nettool` running on a Mac.

## What runs where, and why

iOS will not give any app a raw socket or a monitor-mode radio - not at any
developer tier, not with any entitlement. That is not a limitation of this app
and no amount of paying Apple changes it. So the work is split by what the
platform actually permits:

| | Runs on the phone | Needs the Mac |
|---|---|---|
| Read a .pcap / .pcapng | yes | |
| Decode Ethernet, IPv4/6, TCP, UDP, ARP, DNS, 802.11 | yes | |
| Conversations, endpoints, protocol mix, TCP health | yes | |
| Follow a TCP stream | yes | |
| Display filters | yes | |
| Ping, port scan | yes | |
| **Capture packets** | | yes - no raw socket on iOS |
| **Scan for Wi-Fi networks** | | yes - iOS has no scan API |
| **Your own Wi-Fi name** | paid tier only | yes |

The phone half is the whole standalone app: a capture arrives by AirDrop, Files
or a share sheet, and everything after that is local. The Mac half is for the
two things iOS refuses.

## Free account first, paid later

The app is built so a **free Apple ID** can install it on your own device, with
one screen degraded. That is deliberate, and it is why the entitlement is a
build configuration rather than a runtime check: an entitlement the provisioning
profile does not carry makes the *install* fail, not the call. The free build
must therefore not reference it at all.

* **`Nettool`** - the free target. Never mentions the Wi-Fi entitlement. The
  Wi-Fi tab says why it cannot name your network, and offers the Mac instead.
* **`NettoolEntitled`** - the same code compiled with `NETTOOL_ENTITLED`, which
  turns on `NEHotspotNetwork`. Needs a paid account with
  `com.apple.developer.networking.wifi-info` added to the App ID.

Moving from one to the other is switching scheme. No code changes.

## Getting it onto an iPad or iPhone

There is no way around needing a Mac with **full Xcode** - not the command line
tools, which is all the rest of this repository needs. Apple has no path that
puts a self-built app on a device without one.

```bash
./ios/setup.sh          # checks Xcode, installs xcodegen, generates the project
open ios/Nettool.xcodeproj
```

Then in Xcode:

1. Select the **Nettool** target → **Signing & Capabilities**
2. Tick *Automatically manage signing* and pick your Team. A free Apple ID
   works - add it under Xcode → Settings → Accounts.
3. If the bundle identifier is refused as already taken, change it to something
   of your own, such as `dev.yourname.nettool`.
4. Plug the iPad in, unlock it, tap **Trust**, and choose it in the run
   destination menu.
5. Press Run.

The first launch is refused until the certificate is trusted: on the iPad,
**Settings → General → VPN & Device Management → your Apple ID → Trust**.

The app targets iOS 16, so any iPad from 2017 onwards will run it, and it is
built for both device families - the same binary is an iPhone app and an iPad
app.

### What a free Apple ID costs you

| | Free | Paid ($99/yr) |
|---|---|---|
| Install on your own devices | yes | yes |
| Rebuild every | 7 days | 1 year |
| Apps installed at once | 3 | unlimited |
| Wi-Fi entitlement (your network's name) | no | yes |
| TestFlight, App Store | no | yes |

The seven-day expiry is Apple's rule for free accounts, not this app's: when it
lapses the app refuses to launch, and rebuilding from Xcode fixes it. Nothing
stored on the device is lost.

### Without a Mac

You cannot. TestFlight needs a paid account *and* a Mac (or Xcode Cloud) to
upload the build in the first place, so it is not a way round the requirement -
only a way to distribute afterwards.

## Tests

Fastest, and needs no simulator:

```bash
cd ios/NettoolKit && swift test
```

Or Cmd-U in Xcode - the `Nettool` scheme runs the same sources through the
`NettoolKitTests` target.

## A note on generated files

`project.yml` is the source of truth. The `.xcodeproj`, both `Info.plist` files
and the entitlements file are produced from it by `xcodegen generate` and are
not committed - editing them by hand works until the next regeneration silently
throws the edit away. Change `project.yml` and regenerate.

## Pairing with a Mac

On the Mac, from the repository:

```bash
python3 -m nettool serve --lan
```

`--lan` matters: without it the server binds to localhost and no phone can
reach it, which is the default because a diagnostics API that binds every
interface by surprise is a gift to whoever else is on the coffee-shop Wi-Fi.

It prints a pairing link:

```
nettool://192.168.1.10:8765/?token=xY3k...
```

The app registers the `nettool://` scheme, so **opening that link pairs the
app** - nothing is typed on a phone keyboard. Any of these gets it there:

* copy it on the Mac and paste on the phone, if Universal Clipboard is on
  (both devices signed into the same Apple ID, Handoff enabled);
* message or AirDrop it to yourself and tap it;
* paste it into the box on the Mac tab by hand.

Leave the server running while you use the app. Ctrl-C stops it.

The token is kept in the keychain rather than in preferences, because it is a
bearer credential for a machine on your network. Pairing survives relaunches;
Unpair on the Mac tab forgets it.

The Mac tab also lists servers found over Bonjour, which saves finding the
address - but the token still has to come from the link, and the discovery row
assumes the default port 8765. If you ran the server on another port, use the
printed link rather than the discovered row.

The server is deliberately narrow: bound to localhost unless `--lan` is passed,
every endpoint needs the token, nothing changes state, and no client-supplied
string reaches a shell or escapes the capture directory. `tests/test_server.py`
holds it to that.

## Layout

```
ios/
  project.yml              XcodeGen definition - the .xcodeproj is generated
  Nettool/                 the SwiftUI app
    App/                   entry point, shared store, keychain
    Features/
      Captures/            file import, packet list, detail, follow stream
      WiFi/                signal, and the survey from the Mac
      Tools/               ping, port scan
      Mac/                 pairing, remote capture
  NettoolKit/              everything that is not a view
    Sources/NettoolKit/
      Capture/             pcap and pcapng readers, bounds-checked byte reader
      Decode/              Ethernet, IP, TCP/UDP, ARP, DNS, radiotap, 802.11
      Analysis/            conversations, findings, follow stream, filters
      Net/                 ICMP ping, TCP port scan
      Mac/                 the companion client and Bonjour browser
      Wireless/            Wi-Fi info, behind the entitlement flag
    Tests/                 44 cases, no simulator needed
```

The logic lives in the package rather than the app target so it can be tested
without a simulator, which is the only way any of it was checked at all - see
the note in the repository README about what could and could not be verified.
