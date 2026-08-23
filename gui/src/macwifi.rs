//! Wi-Fi names read in-process, through CoreWLAN.
//!
//! Everything else nettool knows comes from the Python CLI, and that works
//! fine - except for network names. macOS blanks those for a process without
//! Location Services, and the grant does not travel: nettool.app spawns
//! `python3`, which spawns `system_profiler` and `wdutil`, and those are
//! Apple-signed binaries that macOS holds responsible for themselves rather
//! than for the app that launched them. So the app can hold the permission and
//! the names still come back blank, which is exactly what happens.
//!
//! CoreWLAN, asked from inside this process, is covered by the app's own grant.
//! We only use it to fill in the names - channels, signal, airtime and the whole
//! congestion analysis still come from the CLI, none of which macOS redacts.

use crate::model::{looks_like_mac, Bss};

/// macOS hands these back in place of an address it will not give out, so they
/// must never be matched on or shown - two links "sharing" 02:00:00:00:00:00
/// would otherwise look like the same access point.
pub const WITHHELD_BSSIDS: [&str; 2] = ["02:00:00:00:00:00", "00:00:00:00:00:00"];

/// A BSSID worth keeping, lowercased, or "" if macOS withheld it.
pub fn usable_bssid(value: &str) -> String {
    let mac = value.trim().to_lowercase();
    if !looks_like_mac(&mac) || WITHHELD_BSSIDS.contains(&mac.as_str()) {
        return String::new();
    }
    mac
}

/// One BSS as CoreWLAN sees it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Neighbour {
    pub ssid: String,
    pub bssid: String,
    pub channel: i64,
    pub rssi: i64,
}

/// Put names back on the networks macOS blanked.
///
/// Kept apart from the Objective-C so the matching is testable anywhere. A BSSID
/// is the honest key, but macOS hands out neighbouring BSSIDs only under the
/// same permission it hid the names behind, so most rows arrive without one -
/// then the channel plus a signal within a few dB is the best handle there is,
/// and each CoreWLAN entry is spent once so two APs on a channel cannot collapse
/// into the same name.
pub fn fill_names(networks: &mut [Bss], found: &[Neighbour]) -> usize {
    let mut spent = vec![false; found.len()];
    let mut filled = 0;

    // BSSID matches first: they are certain, and taking them up front stops a
    // fuzzy channel match from stealing the entry a certain one needed.
    for net in networks.iter_mut() {
        if !net.ssid.is_empty() {
            continue;
        }
        // A withheld placeholder is not an identity: matching on it would make
        // every network macOS declined to name look like the same access point.
        let want = usable_bssid(&net.bssid);
        if want.is_empty() {
            continue;
        }
        let match_index = found.iter().enumerate().position(|(index, n)| {
            !spent[index] && !n.ssid.is_empty() && usable_bssid(&n.bssid) == want
        });
        if let Some(index) = match_index {
            net.ssid = found[index].ssid.clone();
            net.redacted = false;
            spent[index] = true;
            filled += 1;
        }
    }

    for net in networks.iter_mut() {
        if !net.ssid.is_empty() {
            continue;
        }
        let Some(channel) = net.channel else {
            continue;
        };
        let Some(signal) = net.signal_dbm else {
            continue;
        };
        let best = found
            .iter()
            .enumerate()
            .filter(|(index, n)| {
                !spent[*index] && n.channel == channel && !n.ssid.is_empty()
            })
            .map(|(index, n)| (index, (n.rssi as f64 - signal).abs()))
            .filter(|(_, distance)| *distance <= 8.0)
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        if let Some((index, _)) = best {
            net.ssid = found[index].ssid.clone();
            net.redacted = false;
            spent[index] = true;
            filled += 1;
        }
    }
    filled
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Neighbour;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};

    #[link(name = "CoreWLAN", kind = "framework")]
    extern "C" {}

    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
    }

    unsafe fn selector(name: &str) -> *mut c_void {
        let name = CString::new(name).expect("selector name has no interior nul");
        sel_registerName(name.as_ptr())
    }

    unsafe fn class(name: &str) -> *mut c_void {
        let name = CString::new(name).expect("class name has no interior nul");
        objc_getClass(name.as_ptr())
    }

    // objc_msgSend is variadic, so each message has to be sent through its own
    // prototype - on arm64 the calling convention differs per signature.
    unsafe fn send_ptr(receiver: *mut c_void, message: &str) -> *mut c_void {
        if receiver.is_null() {
            return std::ptr::null_mut();
        }
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(receiver, selector(message))
    }

    unsafe fn send_ptr_index(receiver: *mut c_void, message: &str, index: usize) -> *mut c_void {
        if receiver.is_null() {
            return std::ptr::null_mut();
        }
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(receiver, selector(message), index)
    }

    unsafe fn send_isize(receiver: *mut c_void, message: &str) -> isize {
        if receiver.is_null() {
            return 0;
        }
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(receiver, selector(message))
    }

    unsafe fn string(obj: *mut c_void) -> String {
        let raw = {
            if obj.is_null() {
                std::ptr::null()
            } else {
                let send: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const c_char =
                    std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                send(obj, selector("UTF8String"))
            }
        };
        if raw.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned()
    }

    unsafe fn interface() -> *mut c_void {
        let client = send_ptr(class("CWWiFiClient"), "sharedWiFiClient");
        send_ptr(client, "interface")
    }

    unsafe fn channel_of(obj: *mut c_void) -> i64 {
        send_isize(send_ptr(obj, "wlanChannel"), "channelNumber") as i64
    }

    unsafe fn neighbour(network: *mut c_void) -> Neighbour {
        Neighbour {
            ssid: string(send_ptr(network, "ssid")),
            bssid: super::usable_bssid(&string(send_ptr(network, "bssid"))),
            channel: channel_of(network),
            rssi: send_isize(network, "rssiValue") as i64,
        }
    }

    /// Our own association, named.
    pub fn link() -> Option<Neighbour> {
        unsafe {
            let iface = interface();
            if iface.is_null() {
                return None;
            }
            let found = neighbour(iface);
            if found.ssid.is_empty() && found.bssid.is_empty() {
                return None;
            }
            Some(found)
        }
    }

    /// Neighbours from the radio's last scan.
    ///
    /// Cached results only: a live scan takes seconds and knocks the link about,
    /// and macOS refreshes the cache on its own often enough to name what the
    /// CLI just saw.
    pub fn scan() -> Vec<Neighbour> {
        unsafe {
            let iface = interface();
            if iface.is_null() {
                return Vec::new();
            }
            let results = send_ptr(iface, "cachedScanResults");
            let all = send_ptr(results, "allObjects");
            let count = send_isize(all, "count").max(0) as usize;
            (0..count)
                .map(|index| neighbour(send_ptr_index(all, "objectAtIndex:", index)))
                .filter(|n| !n.ssid.is_empty())
                .collect()
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::Neighbour;

    pub fn link() -> Option<Neighbour> {
        None
    }
    pub fn scan() -> Vec<Neighbour> {
        Vec::new()
    }
}

pub use imp::{link, scan};
