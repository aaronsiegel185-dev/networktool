//! Typed views over `nettool --json` output.
//!
//! The structs mirror nettool's JSON schema in full, including fields no view reads
//! yet - they are the contract between the two programs and are asserted in the tests.
#![allow(dead_code)]

//!
//! Every field is optional or defaulted: the GUI must keep working when it is pointed
//! at a slightly older or newer `nettool`, and half the fields are genuinely absent
//! depending on privileges and hardware.

use serde::Deserialize;
use std::collections::BTreeMap;

fn de_num_key_map<'de, D, T>(d: D) -> Result<BTreeMap<i64, T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    // Python's json turns integer dict keys into strings; turn them back.
    let raw: BTreeMap<String, T> = BTreeMap::deserialize(d)?;
    Ok(raw
        .into_iter()
        .filter_map(|(k, v)| k.parse::<i64>().ok().map(|k| (k, v)))
        .collect())
}

// --- interfaces ------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Counters {
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub rx_packets: u64,
    #[serde(default)]
    pub tx_packets: u64,
    #[serde(default)]
    pub rx_errors: u64,
    #[serde(default)]
    pub tx_errors: u64,
    #[serde(default)]
    pub rx_dropped: u64,
    #[serde(default)]
    pub tx_dropped: u64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Iface {
    pub name: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub prefixlen: u8,
    #[serde(default)]
    pub ipv6: Vec<String>,
    #[serde(default)]
    pub mtu: u32,
    #[serde(default)]
    pub operstate: String,
    #[serde(default)]
    pub speed_mbps: Option<i64>,
    #[serde(default)]
    pub duplex: String,
    #[serde(default)]
    pub wireless: bool,
    #[serde(default)]
    pub up: bool,
    #[serde(default)]
    pub loopback: bool,
    #[serde(default)]
    pub counters: Counters,
}

impl Iface {
    pub fn cidr(&self) -> String {
        if self.ipv4.is_empty() {
            String::new()
        } else {
            format!("{}/{}", self.ipv4, self.prefixlen)
        }
    }

    /// The subnet this interface is on, as a CIDR suitable for a sweep.
    pub fn subnet(&self) -> String {
        if self.ipv4.is_empty() || self.prefixlen == 0 {
            return String::new();
        }
        let octets: Vec<u32> = self
            .ipv4
            .split('.')
            .filter_map(|o| o.parse().ok())
            .collect();
        if octets.len() != 4 {
            return String::new();
        }
        let addr = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
        let mask = if self.prefixlen == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefixlen as u32)
        };
        let net = addr & mask;
        format!(
            "{}.{}.{}.{}/{}",
            net >> 24,
            (net >> 16) & 0xff,
            (net >> 8) & 0xff,
            net & 0xff,
            self.prefixlen
        )
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Route {
    #[serde(default)]
    pub iface: String,
    #[serde(default)]
    pub dest: String,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub prefixlen: u8,
    #[serde(default)]
    pub metric: i64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ArpEntry {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub iface: String,
    #[serde(default)]
    pub incomplete: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct IfaceReport {
    #[serde(default)]
    pub interfaces: Vec<Iface>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub default_gateway: Option<String>,
    #[serde(default)]
    pub gateway_interface: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub dns_search: Vec<String>,
    #[serde(default)]
    pub arp: Vec<ArpEntry>,
}

// --- diag ------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Check {
    #[serde(default)]
    pub check: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct DiagReport {
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub worst: String,
    #[serde(default)]
    pub checks: Vec<Check>,
}

// --- discover --------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Host {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct DiscoverReport {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub duplicate_ips: BTreeMap<String, Vec<String>>,
}

// --- scan ------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct PortResult {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub detail: String,
}

impl PortResult {
    pub fn is_open(&self) -> bool {
        self.state.starts_with("open")
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ScanReport {
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub hosts: usize,
    #[serde(default)]
    pub ports: usize,
    #[serde(default)]
    pub seconds: f64,
    #[serde(default)]
    pub results: Vec<PortResult>,
}

// --- lldp ------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct MgmtAddr {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub interface: Option<i64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct VlanEntry {
    #[serde(default)]
    pub vlan: i64,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Poe {
    #[serde(default)]
    pub port_class: Option<String>,
    #[serde(default)]
    pub power_class: Option<i64>,
    #[serde(default)]
    pub requested_mw: Option<i64>,
    #[serde(default)]
    pub allocated_mw: Option<i64>,
    #[serde(default)]
    pub consumption_mw: Option<i64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Neighbor {
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub src_mac: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub chassis_id: String,
    #[serde(default)]
    pub chassis_id_type: String,
    #[serde(default)]
    pub port_id: String,
    #[serde(default)]
    pub port_id_type: String,
    #[serde(default)]
    pub port_description: String,
    #[serde(default)]
    pub system_name: String,
    #[serde(default)]
    pub system_description: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub enabled_capabilities: Vec<String>,
    #[serde(default)]
    pub mgmt_addrs: Vec<MgmtAddr>,
    #[serde(default)]
    pub vlans: Vec<VlanEntry>,
    #[serde(default)]
    pub port_vlan_id: Option<i64>,
    #[serde(default)]
    pub voice_vlan: Option<i64>,
    #[serde(default)]
    pub mau_type: Option<String>,
    #[serde(default)]
    pub duplex: Option<String>,
    #[serde(default)]
    pub max_frame_size: Option<i64>,
    #[serde(default)]
    pub mtu: Option<i64>,
    #[serde(default)]
    pub vtp_domain: Option<String>,
    #[serde(default)]
    pub ttl: Option<i64>,
    #[serde(default)]
    pub poe: Option<Poe>,
    #[serde(default)]
    pub interface: Option<String>,
}

impl Neighbor {
    pub fn title(&self) -> String {
        if !self.system_name.is_empty() {
            self.system_name.clone()
        } else if !self.chassis_id.is_empty() {
            self.chassis_id.clone()
        } else {
            self.src_mac.clone()
        }
    }

    pub fn mgmt_ip(&self) -> String {
        self.mgmt_addrs
            .first()
            .map(|a| a.address.clone())
            .unwrap_or_default()
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct LldpReport {
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
}

// --- capture ---------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct CaptureReport {
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub kernel_dropped: Option<u64>,
    #[serde(default)]
    pub protocols: BTreeMap<String, u64>,
    #[serde(default)]
    pub top_talkers: BTreeMap<String, u64>,
    #[serde(default)]
    pub conversations: BTreeMap<String, u64>,
    #[serde(default)]
    pub vlans: BTreeMap<String, u64>,
    #[serde(default)]
    pub file: Option<String>,
}

impl CaptureReport {
    /// Counters sorted by value, descending - the useful order for "top N" lists.
    pub fn ranked(map: &BTreeMap<String, u64>) -> Vec<(String, u64)> {
        let mut items: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        items
    }
}

// --- analysis --------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Conversation {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub a: String,
    #[serde(default)]
    pub b: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub packets_ab: u64,
    #[serde(default)]
    pub bytes_ab: u64,
    #[serde(default)]
    pub packets_ba: u64,
    #[serde(default)]
    pub bytes_ba: u64,
    #[serde(default)]
    pub start: f64,
    #[serde(default)]
    pub duration: f64,
    #[serde(default)]
    pub bps_ab: f64,
    #[serde(default)]
    pub bps_ba: f64,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub service: Option<i64>,
}

impl Conversation {
    /// True when only one side of the exchange was captured.
    pub fn one_sided(&self) -> bool {
        self.packets_ab == 0 || self.packets_ba == 0
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct EndpointStat {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub packets_tx: u64,
    #[serde(default)]
    pub bytes_tx: u64,
    #[serde(default)]
    pub packets_rx: u64,
    #[serde(default)]
    pub bytes_rx: u64,
    #[serde(default)]
    pub peers: u64,
    #[serde(default)]
    pub top_ports: Vec<i64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct HierarchyRow {
    #[serde(default)]
    pub layers: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub packets_pct: f64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub bytes_pct: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct UnansweredSyn {
    #[serde(default)]
    pub to: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct TcpHealth {
    #[serde(default)]
    pub segments: u64,
    #[serde(default)]
    pub flows: u64,
    #[serde(default)]
    pub completed_handshakes: u64,
    #[serde(default)]
    pub syns: u64,
    #[serde(default)]
    pub retransmissions: u64,
    #[serde(default)]
    pub retransmission_pct: f64,
    #[serde(default)]
    pub out_of_order: u64,
    #[serde(default)]
    pub duplicate_acks: u64,
    #[serde(default)]
    pub zero_window: u64,
    #[serde(default)]
    pub resets: u64,
    #[serde(default)]
    pub handshake_ms_avg: Option<f64>,
    #[serde(default)]
    pub handshake_ms_max: Option<f64>,
    #[serde(default)]
    pub unanswered_syns: Vec<UnansweredSyn>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SlowLookup {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ms: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct DnsHealth {
    #[serde(default)]
    pub queries: u64,
    #[serde(default)]
    pub answered: u64,
    #[serde(default)]
    pub unanswered: u64,
    #[serde(default)]
    pub latency_ms_avg: Option<f64>,
    #[serde(default)]
    pub latency_ms_max: Option<f64>,
    #[serde(default)]
    pub slowest: Vec<SlowLookup>,
    #[serde(default)]
    pub failures: BTreeMap<String, u64>,
    #[serde(default)]
    pub top_names: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ThroughputPoint {
    #[serde(default)]
    pub t: f64,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub bps: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Conversations {
    #[serde(default)]
    pub tcp: Vec<Conversation>,
    #[serde(default)]
    pub udp: Vec<Conversation>,
    #[serde(default)]
    pub ip: Vec<Conversation>,
    #[serde(default)]
    pub ipv6: Vec<Conversation>,
    #[serde(default)]
    pub ethernet: Vec<Conversation>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct AnalysisReport {
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub duration: f64,
    #[serde(default)]
    pub protocols: BTreeMap<String, u64>,
    #[serde(default)]
    pub hierarchy: Vec<HierarchyRow>,
    #[serde(default)]
    pub vlans: BTreeMap<String, u64>,
    #[serde(default)]
    pub conversations: Conversations,
    #[serde(default)]
    pub endpoints: Vec<EndpointStat>,
    #[serde(default)]
    pub mac_endpoints: Vec<EndpointStat>,
    #[serde(default)]
    pub tcp: TcpHealth,
    #[serde(default)]
    pub dns: DnsHealth,
    #[serde(default)]
    pub throughput: Vec<ThroughputPoint>,
    /// `[severity, message]` pairs.
    #[serde(default)]
    pub findings: Vec<(String, String)>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct StreamDump {
    #[serde(default)]
    pub conversation: Conversation,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub stream: String,
}

// --- wireless survey (from a monitor-mode capture) --------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SurveyAccessPoint {
    #[serde(default)]
    pub bssid: String,
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub channel: Option<i64>,
    #[serde(default)]
    pub band: String,
    #[serde(default)]
    pub signal_dbm: Option<f64>,
    #[serde(default)]
    pub beacons: u64,
    #[serde(default)]
    pub security: Vec<String>,
    #[serde(default)]
    pub standards: Vec<String>,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub stations: Option<i64>,
    #[serde(default)]
    pub utilization_pct: Option<f64>,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SurveyClient {
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub frames: u64,
    #[serde(default)]
    pub bssids: Vec<String>,
    #[serde(default)]
    pub probes: Vec<String>,
    #[serde(default)]
    pub signal_dbm: Option<f64>,
    #[serde(default)]
    pub retry_pct: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct WirelessSurvey {
    #[serde(default)]
    pub frames: u64,
    #[serde(default)]
    pub duration: f64,
    #[serde(default)]
    pub retry_pct: f64,
    #[serde(default)]
    pub access_points: Vec<SurveyAccessPoint>,
    #[serde(default)]
    pub clients: Vec<SurveyClient>,
    /// `[severity, message]` pairs.
    #[serde(default)]
    pub findings: Vec<(String, String)>,
}

// --- mirror ----------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct MirrorHost {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub vendor: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct VlanReport {
    /// `None` is the untagged bucket.
    #[serde(default)]
    pub vlan: Option<i64>,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub duration: f64,
    #[serde(default)]
    pub broadcast: u64,
    #[serde(default)]
    pub multicast: u64,
    #[serde(default)]
    pub unique_macs: u64,
    #[serde(default)]
    pub unique_hosts: u64,
    #[serde(default)]
    pub hosts: Vec<MirrorHost>,
    #[serde(default)]
    pub top_talkers: BTreeMap<String, u64>,
    #[serde(default)]
    pub conversations: BTreeMap<String, u64>,
    #[serde(default)]
    pub protocols: BTreeMap<String, u64>,
    #[serde(default)]
    pub services: BTreeMap<String, u64>,
    #[serde(default)]
    pub dhcp_servers: Vec<String>,
    #[serde(default)]
    pub routers: Vec<String>,
}

impl VlanReport {
    pub fn label(&self) -> String {
        match self.vlan {
            Some(vlan) => format!("VLAN {vlan}"),
            None => "untagged".to_string(),
        }
    }

    pub fn broadcast_pct(&self) -> f64 {
        if self.packets == 0 {
            0.0
        } else {
            100.0 * self.broadcast as f64 / self.packets as f64
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct MirrorFile {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct MirrorReport {
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub duration: f64,
    #[serde(default)]
    pub tagged: u64,
    #[serde(default)]
    pub untagged: u64,
    #[serde(default)]
    pub qinq: u64,
    #[serde(default)]
    pub own_traffic: u64,
    #[serde(default)]
    pub foreign_traffic: u64,
    #[serde(default)]
    pub bidirectional_share: Option<f64>,
    #[serde(default)]
    pub kernel_dropped: u64,
    #[serde(default)]
    pub kernel_filtered: bool,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub vlans: Vec<VlanReport>,
    #[serde(default)]
    pub files: Vec<MirrorFile>,
    /// `[severity, message]` pairs.
    #[serde(default)]
    pub findings: Vec<(String, String)>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct MirrorPlan {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub switch: String,
    #[serde(default)]
    pub management_ip: String,
    #[serde(default)]
    pub destination_port: String,
    #[serde(default)]
    pub source_vlan: Option<i64>,
    #[serde(default)]
    pub source_port: Option<String>,
    #[serde(default)]
    pub native_vlan: Option<i64>,
    #[serde(default)]
    pub config: String,
}

// --- ping ------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct PingReport {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub sent: u32,
    #[serde(default)]
    pub received: u32,
    #[serde(default)]
    pub loss_pct: f64,
    #[serde(default)]
    pub rtt_min: Option<f64>,
    #[serde(default)]
    pub rtt_avg: Option<f64>,
    #[serde(default)]
    pub rtt_max: Option<f64>,
    #[serde(default)]
    pub jitter: Option<f64>,
    #[serde(default)]
    pub errors: Vec<String>,
}

// --- wifi ------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Bss {
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub bssid: String,
    #[serde(default)]
    pub band: String,
    #[serde(default)]
    pub channel: Option<i64>,
    #[serde(default)]
    pub freq: Option<i64>,
    #[serde(default)]
    pub signal_dbm: Option<f64>,
    #[serde(default)]
    pub quality_pct: Option<i64>,
    #[serde(default)]
    pub rating: String,
    #[serde(default)]
    pub width_mhz: Option<i64>,
    #[serde(default)]
    pub utilization_pct: Option<f64>,
    #[serde(default)]
    pub stations: Option<i64>,
    #[serde(default)]
    pub standards: Vec<String>,
    #[serde(default)]
    pub security: Vec<String>,
    #[serde(default)]
    pub associated: bool,
    /// macOS blanked this name because we lack Location Services.
    #[serde(default)]
    pub redacted: bool,
}

impl Bss {
    pub fn display_ssid(&self) -> &str {
        match (self.ssid.is_empty(), self.redacted) {
            (false, _) => &self.ssid,
            (true, true) => "(hidden by macOS)",
            (true, false) => "(hidden)",
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct WifiScanReport {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub networks: Vec<Bss>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Station {
    #[serde(default)]
    pub tx_retries: Option<i64>,
    #[serde(default)]
    pub tx_failed: Option<i64>,
    #[serde(default)]
    pub tx_packets: Option<i64>,
    #[serde(default)]
    pub retry_pct: Option<f64>,
    #[serde(default)]
    pub fail_pct: Option<f64>,
    #[serde(default)]
    pub connected_time: Option<i64>,
    #[serde(default)]
    pub signal_avg_dbm: Option<i64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ProcWireless {
    #[serde(default)]
    pub link_quality: Option<f64>,
    #[serde(default)]
    pub noise_dbm: Option<f64>,
    #[serde(default)]
    pub missed_beacons: Option<i64>,
    #[serde(default)]
    pub rx_invalid_crypt: Option<i64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct WifiLink {
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub bssid: String,
    #[serde(default)]
    pub band: String,
    #[serde(default)]
    pub channel: Option<i64>,
    #[serde(default)]
    pub freq: Option<i64>,
    #[serde(default)]
    pub signal_dbm: Option<f64>,
    #[serde(default)]
    pub noise_dbm: Option<f64>,
    #[serde(default)]
    pub snr_db: Option<f64>,
    #[serde(default)]
    pub quality_pct: Option<i64>,
    #[serde(default)]
    pub rating: String,
    #[serde(default)]
    pub tx_bitrate: String,
    #[serde(default)]
    pub rx_bitrate: String,
    #[serde(default)]
    pub station: Option<Station>,
    #[serde(rename = "proc", default)]
    pub proc_stats: Option<ProcWireless>,
    /// macOS blanked the name because we lack Location Services.
    #[serde(default)]
    pub redacted: bool,
}

impl WifiLink {
    pub fn display_ssid(&self) -> &str {
        match (self.ssid.is_empty(), self.redacted) {
            (false, _) => &self.ssid,
            (true, true) => "(hidden by macOS)",
            (true, false) => "(unknown)",
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SurveyEntry {
    #[serde(default)]
    pub channel: Option<i64>,
    #[serde(default)]
    pub freq: Option<i64>,
    #[serde(default)]
    pub band: String,
    #[serde(default)]
    pub in_use: bool,
    #[serde(default)]
    pub noise_dbm: Option<i64>,
    #[serde(default)]
    pub busy_pct: Option<f64>,
    #[serde(default)]
    pub rx_pct: Option<f64>,
    #[serde(default)]
    pub tx_pct: Option<f64>,
    #[serde(default)]
    pub interference_pct: Option<f64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ChannelInfo {
    #[serde(default)]
    pub bss: i64,
    #[serde(default)]
    pub cochannel: i64,
    #[serde(default)]
    pub overlapping: i64,
    #[serde(default)]
    pub strongest_dbm: Option<f64>,
    #[serde(default)]
    pub strongest_ssid: String,
    #[serde(default)]
    pub utilization_pct: Option<f64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct BandReport {
    #[serde(default)]
    pub bss_count: i64,
    #[serde(default, deserialize_with = "de_num_key_map")]
    pub channels: BTreeMap<i64, ChannelInfo>,
    #[serde(default, deserialize_with = "de_num_key_map")]
    pub congestion_score: BTreeMap<i64, f64>,
    #[serde(default)]
    pub best_channel: Option<i64>,
    #[serde(default)]
    pub best_score: Option<f64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Recommendation {
    #[serde(default)]
    pub channel: i64,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct WifiAnalysis {
    #[serde(default)]
    pub total_bss: i64,
    #[serde(default)]
    pub bands: BTreeMap<String, BandReport>,
    /// `[severity, message]` pairs.
    #[serde(default)]
    pub findings: Vec<(String, String)>,
    #[serde(default)]
    pub recommendations: BTreeMap<String, Recommendation>,
    /// Some name in this report was blanked by macOS.
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct WifiAnalyzeReport {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub report: WifiAnalysis,
    #[serde(default)]
    pub networks: Vec<Bss>,
    #[serde(default)]
    pub current: WifiLink,
    #[serde(default)]
    pub survey: Vec<SurveyEntry>,
}

