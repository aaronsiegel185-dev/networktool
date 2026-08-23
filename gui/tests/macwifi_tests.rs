//! Putting names back on the networks macOS blanked.

use nettool_gui::macwifi::{append_unseen, fill_names, Neighbour};
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

#[test]
fn a_withheld_placeholder_is_not_an_address() {
    use nettool_gui::macwifi::usable_bssid;
    assert_eq!(usable_bssid("02:00:00:00:00:00"), "");
    assert_eq!(usable_bssid("00:00:00:00:00:00"), "");
    assert_eq!(usable_bssid("0x0200000"), "");
    assert_eq!(usable_bssid(""), "");
    assert_eq!(usable_bssid("3C:22:FB:11:22:33"), "3c:22:fb:11:22:33");
}

#[test]
fn two_withheld_networks_do_not_look_like_one_ap() {
    // Both sides carrying the placeholder must not match on it.
    let mut networks = vec![Bss {
        ssid: String::new(),
        bssid: "02:00:00:00:00:00".into(),
        channel: Some(36),
        signal_dbm: Some(-50.0),
        redacted: true,
        ..Default::default()
    }];
    let found = vec![Neighbour {
        ssid: "Elsewhere".into(),
        bssid: "02:00:00:00:00:00".into(),
        channel: 149,
        rssi: -80,
    }];
    assert_eq!(fill_names(&mut networks, &found), 0);
    assert!(networks[0].ssid.is_empty());
}

#[test]
fn our_own_name_is_found_in_the_scan_by_address() {
    let link = Neighbour {
        ssid: String::new(),
        bssid: "3c:22:fb:11:22:33".into(),
        channel: 48,
        rssi: -42,
    };
    let found = vec![
        seen("Neighbour", "aa:bb:cc:dd:ee:ff", 48, -70),
        seen("HomeNet", "3C:22:FB:11:22:33", 48, -42),
    ];
    assert_eq!(
        nettool_gui::macwifi::resolve_own_ssid(&link, &found),
        Some("HomeNet".to_string())
    );
}

#[test]
fn a_name_we_already_have_is_not_looked_up() {
    let link = seen("HomeNet", "3c:22:fb:11:22:33", 48, -42);
    let found = vec![seen("Wrong", "3c:22:fb:11:22:33", 48, -42)];
    assert_eq!(nettool_gui::macwifi::resolve_own_ssid(&link, &found), None);
}

#[test]
fn without_a_usable_address_there_is_nothing_to_look_up() {
    let withheld = Neighbour {
        ssid: String::new(),
        bssid: "02:00:00:00:00:00".into(),
        channel: 48,
        rssi: -42,
    };
    let found = vec![seen("HomeNet", "02:00:00:00:00:00", 48, -42)];
    assert_eq!(nettool_gui::macwifi::resolve_own_ssid(&withheld, &found), None);
}

#[test]
fn networks_the_cli_never_saw_are_added() {
    // system_profiler collapsed everything on channel 36 into one blanked row.
    let mut networks = vec![blanked("", 36, -58.0)];
    let found = vec![
        seen("Named", "aa:bb:cc:00:00:01", 36, -57),
        seen("AlsoHere", "aa:bb:cc:00:00:02", 36, -71),
        seen("Upstairs", "aa:bb:cc:00:00:03", 149, -80),
    ];
    assert_eq!(fill_names(&mut networks, &found), 1);
    assert_eq!(networks[0].ssid, "Named");

    assert_eq!(append_unseen(&mut networks, &found), 2);
    let names: Vec<&str> = networks.iter().map(|n| n.ssid.as_str()).collect();
    assert_eq!(names, ["Named", "AlsoHere", "Upstairs"]);
    assert_eq!(networks[2].band, "5");
    assert_eq!(networks[2].signal_dbm, Some(-80.0));
}

#[test]
fn a_network_already_listed_is_not_added_twice() {
    let mut networks = vec![Bss {
        ssid: "HomeNet".into(),
        bssid: "aa:bb:cc:00:00:01".into(),
        channel: Some(6),
        signal_dbm: Some(-50.0),
        ..Default::default()
    }];
    // Same BSS, and the same name on the same channel without an address.
    let found = vec![
        seen("HomeNet", "AA:BB:CC:00:00:01", 6, -50),
        seen("HomeNet", "", 6, -50),
    ];
    assert_eq!(append_unseen(&mut networks, &found), 0);
    assert_eq!(networks.len(), 1);
}

#[test]
fn the_same_name_on_another_channel_is_its_own_bss() {
    // A dual-band AP is two BSSes and belongs in the list twice.
    let mut networks = vec![Bss {
        ssid: "HomeNet".into(),
        channel: Some(6),
        signal_dbm: Some(-50.0),
        ..Default::default()
    }];
    let found = vec![seen("HomeNet", "aa:bb:cc:00:00:02", 149, -62)];
    assert_eq!(append_unseen(&mut networks, &found), 1);
    assert_eq!(networks[1].channel, Some(149));
    assert_eq!(networks[1].band, "5");
}

#[test]
fn a_nameless_corewlan_entry_is_not_worth_adding() {
    let mut networks: Vec<Bss> = Vec::new();
    let found = vec![seen("", "aa:bb:cc:00:00:01", 6, -50)];
    assert_eq!(append_unseen(&mut networks, &found), 0);
    assert!(networks.is_empty());
}
