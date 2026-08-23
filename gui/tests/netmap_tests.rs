//! The network map is built from whatever the app currently knows; these pin the shape
//! it produces so the picture cannot silently lose nodes or connect them wrongly.

use nettool_gui::model::*;
use nettool_gui::ui::netmap::{self, MapInputs, NodeKind};

fn link() -> WifiLink {
    serde_json::from_str(
        r#"{"connected": true, "ssid": "HomeNet", "bssid": "3c:37:86:11:22:33",
            "band": "2.4", "channel": 6, "signal_dbm": -47.0, "snr_db": 42.0,
            "interface": "en0"}"#,
    )
    .unwrap()
}

fn scan() -> WifiScanReport {
    serde_json::from_str(
        r#"{"source": "iw", "networks": [
            {"ssid": "HomeNet", "bssid": "3c:37:86:11:22:33", "channel": 6,
             "band": "2.4", "signal_dbm": -47.0, "associated": true},
            {"ssid": "NeighborWifi", "bssid": "60:22:32:aa:bb:cc", "channel": 1,
             "band": "2.4", "signal_dbm": -72.0},
            {"ssid": "", "bssid": "04:18:d6:de:ad:01", "channel": 149,
             "band": "5", "signal_dbm": -80.0}]}"#,
    )
    .unwrap()
}

fn hosts() -> DiscoverReport {
    serde_json::from_str(
        r#"{"method": "arp", "hosts": [
            {"ip": "192.168.1.1", "mac": "3c:22:fb:11:22:33", "vendor": "Cisco"},
            {"ip": "192.168.1.14", "mac": "b8:27:eb:aa:bb:cc", "vendor": "Raspberry Pi",
             "name": "pi-hole.lan"},
            {"ip": "192.168.1.22", "mac": "00:1b:21:aa:00:05", "vendor": "Intel"}],
            "duplicate_ips": {}}"#,
    )
    .unwrap()
}

fn inventory() -> IfaceReport {
    serde_json::from_str(
        r#"{"interfaces": [], "routes": [], "default_gateway": "192.168.1.1",
            "dns_servers": ["192.168.1.1"]}"#,
    )
    .unwrap()
}

fn survey() -> WirelessSurvey {
    serde_json::from_str(
        r#"{"frames": 100, "access_points": [
              {"bssid": "3c:37:86:11:22:33", "ssid": "HomeNet", "channel": 6,
               "band": "2.4", "signal_dbm": -47.0},
              {"bssid": "60:22:32:aa:bb:cc", "ssid": "NeighborWifi", "channel": 1,
               "band": "2.4", "signal_dbm": -72.0}],
            "clients": [
              {"mac": "b8:27:eb:dd:00:09", "vendor": "Raspberry Pi", "frames": 40,
               "bssids": ["3c:37:86:11:22:33"], "signal_dbm": -55.0},
              {"mac": "ac:63:be:00:44:55", "vendor": "Amazon", "frames": 12,
               "bssids": ["60:22:32:aa:bb:cc"], "signal_dbm": -70.0}],
            "findings": []}"#,
    )
    .unwrap()
}

#[test]
fn empty_inputs_explain_themselves() {
    let map = netmap::build(&MapInputs::default());
    assert!(map.nodes.is_empty());
    assert!(map.empty_reason.is_some());
}

#[test]
fn builds_the_path_from_the_internet_to_this_machine() {
    let (link, scan, hosts, inventory) = (link(), scan(), hosts(), inventory());
    let map = netmap::build(&MapInputs {
        link: Some(&link),
        scan: Some(&scan),
        hosts: Some(&hosts),
        inventory: Some(&inventory),
        ..Default::default()
    });
    assert!(map.empty_reason.is_none());
    for id in ["internet", "gateway", "ap:mine", "me"] {
        assert!(map.node(id).is_some(), "missing {id}");
    }
    let edges: Vec<(String, String)> = map
        .edges
        .iter()
        .map(|edge| (edge.from.clone(), edge.to.clone()))
        .collect();
    assert!(edges.contains(&("internet".into(), "gateway".into())));
    assert!(edges.contains(&("gateway".into(), "ap:mine".into())));
    assert!(edges.contains(&("ap:mine".into(), "me".into())));
}

#[test]
fn the_link_edge_carries_the_signal_and_reads_it_out() {
    let (link, inventory) = (link(), inventory());
    let map = netmap::build(&MapInputs {
        link: Some(&link),
        inventory: Some(&inventory),
        ..Default::default()
    });
    let edge = map
        .edges
        .iter()
        .find(|edge| edge.to == "me")
        .expect("an edge to this machine");
    assert_eq!(edge.signal, Some(-47.0));
    assert!(edge.label.contains("-47"), "the link should be labelled with its signal");
}

#[test]
fn my_access_point_is_not_repeated_as_a_neighbour() {
    let (link, scan) = (link(), scan());
    let map = netmap::build(&MapInputs {
        link: Some(&link),
        scan: Some(&scan),
        ..Default::default()
    });
    assert_eq!(map.count(NodeKind::AccessPoint), 1);
    assert_eq!(map.count(NodeKind::OtherAccessPoint), 2);
    assert!(map.node("ap:3c:37:86:11:22:33").is_none());
}

#[test]
fn this_machine_sits_under_its_access_point() {
    let (link, scan, hosts, inventory) = (link(), scan(), hosts(), inventory());
    let map = netmap::build(&MapInputs {
        link: Some(&link),
        scan: Some(&scan),
        hosts: Some(&hosts),
        inventory: Some(&inventory),
        ..Default::default()
    });
    let ap = map.node("ap:mine").unwrap();
    let me = map.node("me").unwrap();
    assert!(me.row > ap.row);
    // Same slot, give or take one, and never on top of another node.
    assert!((me.x - ap.x).abs() < 0.2, "me at {} vs ap at {}", me.x, ap.x);
    let clashes = map
        .nodes
        .iter()
        .filter(|node| node.row == me.row && node.id != me.id && (node.x - me.x).abs() < 0.01)
        .count();
    assert_eq!(clashes, 0, "another node shares this machine's position");
}

#[test]
fn stations_from_a_capture_attach_to_their_own_access_point() {
    let (link, survey, inventory) = (link(), survey(), inventory());
    let map = netmap::build(&MapInputs {
        link: Some(&link),
        survey: Some(&survey),
        inventory: Some(&inventory),
        ..Default::default()
    });
    assert_eq!(map.count(NodeKind::WirelessClient), 2);
    let edges: Vec<(String, String)> = map
        .edges
        .iter()
        .map(|edge| (edge.from.clone(), edge.to.clone()))
        .collect();
    // The Amazon device was heard on the neighbour's BSSID, so it hangs off that AP.
    assert!(edges.contains(&(
        "ap:60:22:32:aa:bb:cc".into(),
        "sta:ac:63:be:00:44:55".into()
    )));
    // The Pi was on ours.
    assert!(edges.contains(&("ap:mine".into(), "sta:b8:27:eb:dd:00:09".into())));
}

#[test]
fn lan_hosts_hang_off_the_gateway_and_skip_the_gateway_itself() {
    let (hosts, inventory) = (hosts(), inventory());
    let map = netmap::build(&MapInputs {
        hosts: Some(&hosts),
        inventory: Some(&inventory),
        ..Default::default()
    });
    assert!(map.node("host:192.168.1.1").is_none(), "gateway duplicated");
    assert!(map.node("host:192.168.1.14").is_some());
    assert!(map
        .edges
        .iter()
        .any(|edge| edge.from == "gateway" && edge.to == "host:192.168.1.14" && edge.dashed));
}

#[test]
fn neighbours_are_capped_and_sorted_by_signal() {
    let mut scan = scan();
    for index in 0..20 {
        scan.networks.push(serde_json::from_str(&format!(
            r#"{{"ssid": "Net{index}", "bssid": "aa:bb:cc:00:00:{index:02x}",
                 "channel": 11, "band": "2.4", "signal_dbm": -{}.0}}"#,
            60 + index
        ))
        .unwrap());
    }
    let link = link();
    let map = netmap::build(&MapInputs {
        link: Some(&link),
        scan: Some(&scan),
        max_other_aps: 4,
        ..Default::default()
    });
    assert_eq!(map.count(NodeKind::OtherAccessPoint), 4);
    let strongest = map
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::OtherAccessPoint)
        .map(|node| node.signal.unwrap_or(-999.0))
        .collect::<Vec<_>>();
    let mut sorted = strongest.clone();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(strongest, sorted, "neighbours should be strongest first");
}

#[test]
fn colours_follow_the_signal() {
    let (link, inventory) = (link(), inventory());
    let map = netmap::build(&MapInputs {
        link: Some(&link),
        inventory: Some(&inventory),
        ..Default::default()
    });
    let strong = map.node("ap:mine").unwrap().color();
    let mut weak_link = link.clone();
    weak_link.signal_dbm = Some(-85.0);
    let weak_map = netmap::build(&MapInputs {
        link: Some(&weak_link),
        inventory: Some(&inventory),
        ..Default::default()
    });
    let weak = weak_map.node("ap:mine").unwrap().color();
    assert_ne!(strong, weak, "a weak access point must not look like a strong one");
}

#[test]
fn not_associated_still_draws_the_wired_side() {
    let mut offline = link();
    offline.connected = false;
    offline.signal_dbm = None;
    let (hosts, inventory) = (hosts(), inventory());
    let map = netmap::build(&MapInputs {
        link: Some(&offline),
        hosts: Some(&hosts),
        inventory: Some(&inventory),
        ..Default::default()
    });
    assert!(map.node("me").is_none());
    assert!(map.node("gateway").is_some());
    assert!(map.count(NodeKind::WiredHost) > 0);
}
