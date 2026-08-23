//! Putting names back on the networks macOS blanked.

use nettool_gui::macwifi::{fill_names, Neighbour};
use nettool_gui::model::Bss;

fn blanked(bssid: &str, channel: i64, signal: f64) -> Bss {
    Bss {
        ssid: String::new(),
        bssid: bssid.into(),
        channel: Some(channel),
        signal_dbm: Some(signal),
        redacted: true,
        ..Default::default()
    }
}

fn seen(ssid: &str, bssid: &str, channel: i64, rssi: i64) -> Neighbour {
    Neighbour {
        ssid: ssid.into(),
        bssid: bssid.into(),
        channel,
        rssi,
    }
}

#[test]
fn a_bssid_match_is_taken_first_and_exactly() {
    let mut networks = vec![blanked("AA:BB:CC:11:22:33", 6, -60.0)];
    let found = vec![
        seen("Decoy", "", 6, -60),
        seen("HomeNet", "aa:bb:cc:11:22:33", 6, -75),
    ];
    assert_eq!(fill_names(&mut networks, &found), 1);
    // Case folded, and the signal disagreeing does not overrule a BSSID.
    assert_eq!(networks[0].ssid, "HomeNet");
    assert!(!networks[0].redacted);
}

#[test]
fn falls_back_to_channel_and_the_closest_signal() {
    let mut networks = vec![blanked("", 36, -58.0), blanked("", 36, -80.0)];
    let found = vec![seen("Far", "", 36, -79), seen("Near", "", 36, -57)];
    assert_eq!(fill_names(&mut networks, &found), 2);
    assert_eq!(networks[0].ssid, "Near");
    assert_eq!(networks[1].ssid, "Far");
}

#[test]
fn one_name_is_never_spent_on_two_networks() {
    let mut networks = vec![blanked("", 11, -60.0), blanked("", 11, -61.0)];
    let found = vec![seen("OnlyOne", "", 11, -60)];
    assert_eq!(fill_names(&mut networks, &found), 1);
    assert_eq!(networks[0].ssid, "OnlyOne");
    assert!(networks[1].ssid.is_empty());
    assert!(networks[1].redacted);
}

#[test]
fn a_distant_signal_on_the_same_channel_is_not_a_match() {
    let mut networks = vec![blanked("", 1, -40.0)];
    let found = vec![seen("Elsewhere", "", 1, -85)];
    assert_eq!(fill_names(&mut networks, &found), 0);
    assert!(networks[0].ssid.is_empty());
}

#[test]
fn a_different_channel_is_never_a_match() {
    let mut networks = vec![blanked("", 6, -55.0)];
    let found = vec![seen("Other", "", 11, -55)];
    assert_eq!(fill_names(&mut networks, &found), 0);
}

#[test]
fn names_we_already_have_are_left_alone() {
    let mut networks = vec![Bss {
        ssid: "Known".into(),
        channel: Some(6),
        signal_dbm: Some(-55.0),
        ..Default::default()
    }];
    let found = vec![seen("Wrong", "", 6, -55)];
    assert_eq!(fill_names(&mut networks, &found), 0);
    assert_eq!(networks[0].ssid, "Known");
}

#[test]
fn nothing_from_corewlan_changes_nothing() {
    let mut networks = vec![blanked("", 6, -55.0)];
    assert_eq!(fill_names(&mut networks, &[]), 0);
    assert!(networks[0].redacted);
}
