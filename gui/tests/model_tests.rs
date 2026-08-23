//! The GUI is only as good as its reading of nettool's JSON, so every fixture in
//! `fixtures/` (recorded from the real tool) is parsed and checked here.

use nettool_gui::model::*;

fn load<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn parses_interface_inventory() {
    let report: IfaceReport = load("iface.json");
    assert!(!report.interfaces.is_empty());
    // Whatever the primary interface is called on the machine that recorded the
    // fixture, it must parse with an address, a prefix and live counters.
    let primary = report
        .interfaces
        .iter()
        .find(|i| !i.loopback && !i.ipv4.is_empty())
        .expect("an addressed interface in the fixture");
    assert!(primary.up);
    assert_eq!(primary.prefixlen, 24);
    assert_eq!(primary.cidr(), format!("{}/24", primary.ipv4));
    assert!(primary.counters.rx_bytes > 0);
    assert!(report.default_gateway.is_some());
    assert!(!report.dns_servers.is_empty());
    assert!(report.routes.iter().any(|r| r.prefixlen == 0));
}

#[test]
fn computes_subnet_from_address_and_prefix() {
    let mut iface = Iface {
        ipv4: "192.168.17.42".into(),
        prefixlen: 24,
        ..Default::default()
    };
    assert_eq!(iface.subnet(), "192.168.17.0/24");
    iface.prefixlen = 16;
    assert_eq!(iface.subnet(), "192.168.0.0/16");
    iface.prefixlen = 28;
    iface.ipv4 = "10.0.0.203".into();
    assert_eq!(iface.subnet(), "10.0.0.192/28");
    iface.ipv4 = String::new();
    assert_eq!(iface.subnet(), "");
}

#[test]
fn parses_diag_report() {
    let report: DiagReport = load("diag.json");
    assert!(!report.checks.is_empty());
    assert!(!report.verdict.is_empty());
    assert!(report
        .checks
        .iter()
        .all(|c| ["ok", "info", "warn", "critical"].contains(&c.severity.as_str())));
    assert!(report.checks.iter().any(|c| c.check == "gateway"));
}

#[test]
fn parses_discovery() {
    let report: DiscoverReport = load("discover.json");
    assert!(!report.method.is_empty());
    assert!(report.hosts.iter().all(|h| !h.ip.is_empty()));
}

#[test]
fn parses_port_scan() {
    let report: ScanReport = load("scan.json");
    assert_eq!(report.proto, "tcp");
    assert!(report.seconds >= 0.0);
    let open: Vec<&PortResult> = report.results.iter().filter(|r| r.is_open()).collect();
    assert!(!open.is_empty(), "fixture should contain an open port");
    assert!(report.results.iter().any(|r| r.state == "closed"));
}

#[test]
fn open_state_matches_udp_ambiguity() {
    let mut result = PortResult {
        state: "open|filtered".into(),
        ..Default::default()
    };
    assert!(result.is_open());
    result.state = "closed".into();
    assert!(!result.is_open());
}

#[test]
fn parses_lldp_neighbours() {
    let report: LldpReport = load("lldp.json");
    assert_eq!(report.neighbors.len(), 2);
    let lldp = report
        .neighbors
        .iter()
        .find(|n| n.protocol == "LLDP")
        .expect("an LLDP neighbour");
    assert_eq!(lldp.title(), "sw-idf3-01");
    assert_eq!(lldp.port_id, "GigabitEthernet1/0/24");
    assert_eq!(lldp.port_vlan_id, Some(30));
    assert_eq!(lldp.mgmt_ip(), "10.20.0.5");
    assert_eq!(lldp.max_frame_size, Some(9216));
    let poe = lldp.poe.as_ref().expect("PoE TLV");
    assert_eq!(poe.allocated_mw, Some(15400));
    assert_eq!(lldp.vlans[0].name, "LABS");

    let cdp = report
        .neighbors
        .iter()
        .find(|n| n.protocol == "CDP")
        .expect("a CDP neighbour");
    assert_eq!(cdp.title(), "sw-core-1.example.net");
    assert_eq!(cdp.port_vlan_id, Some(77));
    assert_eq!(cdp.duplex.as_deref(), Some("full"));
}

#[test]
fn neighbour_title_falls_back_to_mac() {
    let neighbor = Neighbor {
        src_mac: "aa:bb:cc:dd:ee:ff".into(),
        ..Default::default()
    };
    assert_eq!(neighbor.title(), "aa:bb:cc:dd:ee:ff");
    assert_eq!(neighbor.mgmt_ip(), "");
}

#[test]
fn parses_capture_summaries() {
    let live: CaptureReport = load("capture.json");
    assert!(live.packets > 0);
    assert!(!live.protocols.is_empty());

    let offline: CaptureReport = load("pcap.json");
    assert!(offline.packets > 0);
    let ranked = CaptureReport::ranked(&offline.top_talkers);
    assert!(!ranked.is_empty());
    for pair in ranked.windows(2) {
        assert!(pair[0].1 >= pair[1].1, "ranked must be descending");
    }
}

#[test]
fn parses_ping() {
    let report: PingReport = load("ping.json");
    assert!(report.sent > 0);
    assert!(report.loss_pct >= 0.0 && report.loss_pct <= 100.0);
    if report.received > 0 {
        assert!(report.rtt_avg.unwrap() > 0.0);
    }
}

#[test]
fn parses_wifi_scan() {
    let report: WifiScanReport = load("wifi_scan.json");
    assert_eq!(report.networks.len(), 4);
    let home = &report.networks[0];
    assert_eq!(home.ssid, "HomeNet");
    assert_eq!(home.channel, Some(6));
    assert_eq!(home.band, "2.4");
    assert_eq!(home.width_mhz, Some(40));
    assert_eq!(home.stations, Some(7));
    assert!(home.associated);
    assert!(home.utilization_pct.unwrap() > 50.0);
    let hidden = report.networks.iter().find(|n| n.ssid.is_empty()).unwrap();
    assert_eq!(hidden.display_ssid(), "(hidden)");
}

#[test]
fn parses_wifi_link() {
    let link: WifiLink = load("wifi_link.json");
    assert!(link.connected);
    assert_eq!(link.ssid, "HomeNet");
    assert_eq!(link.channel, Some(6));
    assert_eq!(link.snr_db, Some(42.0));
    let station = link.station.expect("station stats");
    assert_eq!(station.retry_pct, Some(25.0));
    assert_eq!(link.proc_stats.unwrap().missed_beacons, Some(4));
}

#[test]
fn parses_wifi_survey() {
    #[derive(serde::Deserialize)]
    struct SurveyWrapper {
        survey: Vec<SurveyEntry>,
    }
    let wrapper: SurveyWrapper = load("wifi_survey.json");
    let in_use = wrapper
        .survey
        .iter()
        .find(|s| s.in_use)
        .expect("one channel in use");
    assert_eq!(in_use.channel, Some(6));
    assert_eq!(in_use.busy_pct, Some(75.0));
    assert_eq!(in_use.interference_pct, Some(60.0));
}

#[test]
fn parses_wifi_analysis_including_integer_keyed_maps() {
    let report: WifiAnalyzeReport = load("wifi_analyze.json");
    assert_eq!(report.report.total_bss, 4);

    let band = report.report.bands.get("2.4").expect("2.4 GHz band");
    // Python emits integer dict keys as JSON strings; they must come back as numbers.
    assert!(band.channels.contains_key(&6));
    assert!(band.congestion_score.contains_key(&11));
    assert_eq!(band.best_channel, Some(11));
    let channel6 = &band.channels[&6];
    assert_eq!(channel6.strongest_ssid, "HomeNet");
    assert_eq!(channel6.bss, 1);

    let five = report.report.bands.get("5").expect("5 GHz band");
    assert!(five.best_channel.is_some());

    assert!(!report.report.findings.is_empty());
    assert!(report
        .report
        .findings
        .iter()
        .all(|(severity, message)| !severity.is_empty() && !message.is_empty()));
    assert!(report
        .report
        .findings
        .iter()
        .any(|(_, message)| message.to_lowercase().contains("retry")));
    assert!(report.report.recommendations.contains_key("2.4"));
    assert_eq!(report.current.ssid, "HomeNet");
    assert!(!report.survey.is_empty());
}

#[test]
fn parses_analysis_report() {
    let report: AnalysisReport = load("analyze.json");
    assert!(report.packets > 0);
    assert!(report.duration > 0.0);

    // Conversations exist at every layer the capture contains, counted per direction.
    let tcp = &report.conversations.tcp;
    assert!(!tcp.is_empty());
    let busiest = &tcp[0];
    assert_eq!(busiest.packets, busiest.packets_ab + busiest.packets_ba);
    assert_eq!(busiest.bytes, busiest.bytes_ab + busiest.bytes_ba);
    assert!(!busiest.one_sided());
    assert!(!report.conversations.udp.is_empty());
    assert!(!report.conversations.ip.is_empty());
    assert!(!report.conversations.ethernet.is_empty());

    // The dead connection attempt is the one-sided conversation.
    assert!(tcp.iter().any(|c| c.one_sided()));

    assert!(!report.endpoints.is_empty());
    assert!(report
        .endpoints
        .iter()
        .all(|e| e.packets == e.packets_tx + e.packets_rx));

    let hierarchy: Vec<&str> = report.hierarchy.iter().map(|h| h.layers.as_str()).collect();
    assert!(hierarchy.iter().any(|layers| layers.contains("TCP")));
    assert!(report.hierarchy.iter().all(|h| h.packets_pct <= 100.0));

    assert!(report.tcp.retransmissions > 0);
    assert!(report.tcp.retransmission_pct > 0.0);
    assert!(report.tcp.handshake_ms_avg.is_some());
    assert!(!report.tcp.unanswered_syns.is_empty());

    assert!(report.dns.queries > 0);
    assert!(report.dns.unanswered > 0);
    assert!(!report.dns.failures.is_empty());
    assert!(!report.dns.slowest.is_empty());

    assert!(report.throughput.len() >= 2);
    assert!(!report.findings.is_empty());
}

#[test]
fn one_sided_detection() {
    let two_way = Conversation {
        packets_ab: 3,
        packets_ba: 4,
        ..Default::default()
    };
    assert!(!two_way.one_sided());
    assert!(Conversation {
        packets_ab: 5,
        packets_ba: 0,
        ..Default::default()
    }
    .one_sided());
}

#[test]
fn parses_followed_stream() {
    let dump: StreamDump = load("analyze_stream.json");
    assert!(dump.bytes > 0);
    assert!(dump.stream.contains("->"));
    assert!(dump.stream.contains("<-"));
    assert!(!dump.conversation.a.is_empty());
}

#[test]
fn parses_mirror_report() {
    let report: MirrorReport = load("mirror.json");
    assert!(report.packets > 0);
    assert!(report.tagged > 0);
    assert!(!report.vlans.is_empty());

    let tagged: Vec<&VlanReport> = report.vlans.iter().filter(|v| v.vlan.is_some()).collect();
    assert!(!tagged.is_empty(), "the fixture has VLAN-tagged traffic");
    let first = tagged[0];
    assert!(first.packets > 0);
    assert!(first.unique_hosts > 0);
    assert!(first.label().starts_with("VLAN "));
    assert!(first.hosts.iter().all(|h| !h.ip.is_empty() && !h.mac.is_empty()));

    // The untagged bucket is reported with a null vlan, and must not be dropped.
    let untagged = report.vlans.iter().find(|v| v.vlan.is_none());
    if let Some(untagged) = untagged {
        assert_eq!(untagged.label(), "untagged");
    }
    assert!(!report.findings.is_empty());
    assert!(report
        .findings
        .iter()
        .all(|(severity, message)| !severity.is_empty() && !message.is_empty()));
}

#[test]
fn broadcast_share_is_derived_not_parsed() {
    let vlan = VlanReport {
        packets: 200,
        broadcast: 50,
        ..Default::default()
    };
    assert!((vlan.broadcast_pct() - 25.0).abs() < 0.001);
    assert_eq!(VlanReport::default().broadcast_pct(), 0.0);
}

#[test]
fn parses_mirror_plan() {
    let plan: MirrorPlan = load("mirror_plan.json");
    assert_eq!(plan.vendor, "cisco-ios");
    assert!(plan.config.contains("monitor session"));
    assert_eq!(plan.source_vlan, Some(30));
}

#[test]
fn tolerates_missing_and_unknown_fields() {
    let minimal: WifiLink = serde_json::from_str(r#"{"connected": false}"#).unwrap();
    assert!(!minimal.connected);
    assert!(minimal.signal_dbm.is_none());

    let future: ScanReport =
        serde_json::from_str(r#"{"proto":"tcp","results":[],"brand_new_field":42}"#).unwrap();
    assert_eq!(future.proto, "tcp");

    let empty: DiagReport = serde_json::from_str("{}").unwrap();
    assert!(empty.checks.is_empty());
}
