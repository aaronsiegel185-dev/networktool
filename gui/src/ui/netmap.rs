//! A picture of the network: what you are connected to, and what else is on it.
//!
//! The layout is deliberately simple and deterministic - internet at the top, then the
//! gateway, then access points, then the things attached to them - because a force
//! layout that reshuffles on every refresh is impossible to read.

use eframe::egui;

use super::widgets;
use crate::model::{DiscoverReport, IfaceReport, WifiLink, WifiScanReport, WirelessSurvey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Internet,
    Gateway,
    AccessPoint,
    OtherAccessPoint,
    Me,
    WirelessClient,
    WiredHost,
}

#[derive(Debug, Clone)]
pub struct MapNode {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub kind: NodeKind,
    /// RSSI in dBm where it means something (access points and wireless clients).
    pub signal: Option<f64>,
    pub row: usize,
    pub column: usize,
    pub columns_in_row: usize,
    /// Horizontal position within the row, 0.0 (left) to 1.0 (right). "This machine" is
    /// pinned under its access point rather than taking an even slot, so the link you
    /// care about reads as one vertical line.
    pub x: f32,
}

impl MapNode {
    pub fn color(&self) -> egui::Color32 {
        match self.kind {
            NodeKind::Me => widgets::ACCENT,
            NodeKind::Internet => egui::Color32::from_gray(150),
            NodeKind::Gateway => egui::Color32::from_rgb(150, 170, 200),
            NodeKind::AccessPoint => match self.signal {
                Some(dbm) => widgets::signal_color(dbm),
                None => widgets::ACCENT,
            },
            NodeKind::OtherAccessPoint => egui::Color32::from_gray(95),
            NodeKind::WirelessClient => match self.signal {
                Some(dbm) => widgets::signal_color(dbm),
                None => egui::Color32::from_gray(130),
            },
            NodeKind::WiredHost => egui::Color32::from_rgb(130, 160, 140),
        }
    }

    pub fn radius(&self) -> f32 {
        match self.kind {
            NodeKind::Me => 26.0,
            NodeKind::AccessPoint => 24.0,
            NodeKind::Gateway | NodeKind::Internet => 20.0,
            NodeKind::OtherAccessPoint => 14.0,
            _ => 13.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MapEdge {
    pub from: String,
    pub to: String,
    /// Drives the line colour: RSSI for a radio link, None for wired.
    pub signal: Option<f64>,
    pub dashed: bool,
    pub label: String,
}

#[derive(Debug, Default, Clone)]
pub struct NetworkMap {
    pub nodes: Vec<MapNode>,
    pub edges: Vec<MapEdge>,
    pub rows: usize,
    /// Set when we know nothing worth drawing.
    pub empty_reason: Option<String>,
}

impl NetworkMap {
    pub fn node(&self, id: &str) -> Option<&MapNode> {
        self.nodes.iter().find(|node| node.id == id)
    }

    pub fn count(&self, kind: NodeKind) -> usize {
        self.nodes.iter().filter(|node| node.kind == kind).count()
    }
}

/// Everything the map can be built from. All of it is optional: the map shows whatever
/// the app currently knows.
#[derive(Default)]
pub struct MapInputs<'a> {
    pub link: Option<&'a WifiLink>,
    pub scan: Option<&'a WifiScanReport>,
    pub hosts: Option<&'a DiscoverReport>,
    pub inventory: Option<&'a IfaceReport>,
    pub survey: Option<&'a WirelessSurvey>,
    /// Nearby access points beyond this many are not drawn.
    pub max_other_aps: usize,
    pub max_hosts: usize,
}

/// Assemble the map. Pure, so the shape can be asserted in tests.
pub fn build(inputs: &MapInputs) -> NetworkMap {
    let mut map = NetworkMap::default();
    let max_other = if inputs.max_other_aps == 0 { 6 } else { inputs.max_other_aps };
    let max_hosts = if inputs.max_hosts == 0 { 14 } else { inputs.max_hosts };

    let gateway = inputs
        .inventory
        .and_then(|inventory| inventory.default_gateway.clone())
        .unwrap_or_default();
    let connected = inputs
        .link
        .map(|link| link.connected || link.signal_dbm.is_some())
        .unwrap_or(false);

    // Row 0: the internet, if we have a gateway to reach it through.
    let mut rows: Vec<Vec<MapNode>> = Vec::new();
    if !gateway.is_empty() {
        rows.push(vec![node("internet", "Internet", "", NodeKind::Internet, None)]);
        let dns = inputs
            .inventory
            .map(|inventory| inventory.dns_servers.join(", "))
            .unwrap_or_default();
        rows.push(vec![node(
            "gateway",
            "Gateway",
            &if dns.is_empty() {
                gateway.clone()
            } else {
                format!("{gateway}  ·  DNS {dns}")
            },
            NodeKind::Gateway,
            None,
        )]);
    }

    // Row 2: the access point we are on, plus the neighbours worth showing.
    let mut ap_row: Vec<MapNode> = Vec::new();
    let mut my_bssid = String::new();
    if let Some(link) = inputs.link {
        if connected {
            my_bssid = link.bssid.to_lowercase();
            let ssid = link.display_ssid();
            let detail = format!(
                "{}  ·  ch {}  ·  {} GHz",
                if link.bssid.is_empty() { "BSSID unknown" } else { &link.bssid },
                link.channel.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                if link.band.is_empty() { "?" } else { &link.band },
            );
            ap_row.push(node(
                "ap:mine",
                ssid,
                &detail,
                NodeKind::AccessPoint,
                link.signal_dbm,
            ));
        }
    }
    // Neighbours: from a monitor capture if we have one, otherwise from the scan.
    let mut neighbours: Vec<(String, String, Option<i64>, Option<f64>)> = Vec::new();
    if let Some(survey) = inputs.survey {
        for ap in &survey.access_points {
            if ap.bssid.to_lowercase() == my_bssid {
                continue;
            }
            neighbours.push((
                ap.bssid.clone(),
                if ap.ssid.is_empty() { "(hidden)".into() } else { ap.ssid.clone() },
                ap.channel,
                ap.signal_dbm,
            ));
        }
    } else if let Some(scan) = inputs.scan {
        for net in &scan.networks {
            if net.bssid.to_lowercase() == my_bssid && !my_bssid.is_empty() {
                continue;
            }
            if net.associated && !my_bssid.is_empty() {
                continue;
            }
            neighbours.push((
                net.bssid.clone(),
                net.display_ssid().to_string(),
                net.channel,
                net.signal_dbm,
            ));
        }
    }
    neighbours.sort_by(|a, b| {
        b.3.unwrap_or(-999.0)
            .partial_cmp(&a.3.unwrap_or(-999.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (bssid, ssid, channel, signal) in neighbours.into_iter().take(max_other) {
        let detail = format!(
            "ch {}{}",
            channel.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
            signal.map(|s| format!("  ·  {s:.0} dBm")).unwrap_or_default()
        );
        ap_row.push(node(
            &format!("ap:{bssid}"),
            &ssid,
            &detail,
            NodeKind::OtherAccessPoint,
            signal,
        ));
    }
    if !ap_row.is_empty() {
        rows.push(ap_row);
    }

    // Row 3: this machine, the stations a monitor capture saw, and LAN hosts.
    let mut leaf_row: Vec<MapNode> = Vec::new();
    if connected {
        let link = inputs.link.unwrap();
        let detail = match (link.signal_dbm, link.snr_db) {
            (Some(signal), Some(snr)) => format!("{signal:.0} dBm  ·  SNR {snr:.0} dB"),
            (Some(signal), None) => format!("{signal:.0} dBm"),
            _ => link.interface.clone(),
        };
        leaf_row.push(node("me", "This Mac", &detail, NodeKind::Me, link.signal_dbm));
    }
    if let Some(survey) = inputs.survey {
        for client in survey.clients.iter().take(max_hosts) {
            let vendor = if client.vendor.is_empty() { "" } else { &client.vendor };
            leaf_row.push(node(
                &format!("sta:{}", client.mac),
                if vendor.is_empty() { &client.mac } else { vendor },
                &format!(
                    "{}  ·  {} frames{}",
                    client.mac,
                    client.frames,
                    client
                        .signal_dbm
                        .map(|s| format!("  ·  {s:.0} dBm"))
                        .unwrap_or_default()
                ),
                NodeKind::WirelessClient,
                client.signal_dbm,
            ));
        }
    }
    if let Some(hosts) = inputs.hosts {
        let already: Vec<String> = leaf_row.iter().map(|n| n.id.clone()).collect();
        for host in hosts.hosts.iter().take(max_hosts) {
            let id = format!("host:{}", host.ip);
            if already.contains(&id) {
                continue;
            }
            if !gateway.is_empty() && host.ip == gateway {
                continue;
            }
            let name = if !host.name.is_empty() {
                host.name.clone()
            } else if !host.vendor.is_empty() {
                host.vendor.clone()
            } else {
                host.ip.clone()
            };
            let detail = if host.mac.is_empty() {
                host.ip.clone()
            } else {
                format!("{}  ·  {}", host.ip, host.mac)
            };
            leaf_row.push(node(&id, &name, &detail, NodeKind::WiredHost, None));
        }
    }
    if !leaf_row.is_empty() {
        rows.push(leaf_row);
    }

    if rows.is_empty() {
        map.empty_reason = Some(
            "Nothing to draw yet - run the scan and discovery buttons above.".to_string(),
        );
        return map;
    }

    for row in rows.iter_mut() {
        centre_primary(row);
    }

    // Even slots across each row. "This machine" claims the slot nearest its access
    // point, so the link you care about reads as one vertical line and nothing sits on
    // top of anything else.
    let ap_row_x: Option<f32> = rows.iter().find_map(|row| {
        let slots = row.len().max(1);
        row.iter()
            .position(|node| node.id == "ap:mine")
            .map(|index| (index as f32 + 0.5) / slots as f32)
    });
    for (row_index, row) in rows.iter().enumerate() {
        let slots = row.len().max(1);
        let me_slot = row
            .iter()
            .position(|node| node.kind == NodeKind::Me)
            .and(ap_row_x)
            .map(|target| {
                let slot = (target * slots as f32 - 0.5).round();
                slot.clamp(0.0, (slots - 1) as f32) as usize
            });
        let mut next_slot = 0;
        for template in row.iter() {
            let mut placed = template.clone();
            placed.row = row_index;
            placed.columns_in_row = slots;
            let slot = if placed.kind == NodeKind::Me {
                me_slot.unwrap_or(slots / 2)
            } else {
                while Some(next_slot) == me_slot {
                    next_slot += 1;
                }
                let slot = next_slot.min(slots - 1);
                next_slot += 1;
                slot
            };
            placed.column = slot;
            placed.x = (slot as f32 + 0.5) / slots as f32;
            map.nodes.push(placed);
        }
    }
    map.rows = rows.len();

    // Edges follow the same story: internet - gateway - AP - clients.
    if map.node("internet").is_some() && map.node("gateway").is_some() {
        map.edges.push(edge("internet", "gateway", None, false, ""));
    }
    let ap_ids: Vec<String> = map
        .nodes
        .iter()
        .filter(|node| matches!(node.kind, NodeKind::AccessPoint | NodeKind::OtherAccessPoint))
        .map(|node| node.id.clone())
        .collect();
    if map.node("gateway").is_some() {
        if map.node("ap:mine").is_some() {
            map.edges.push(edge("gateway", "ap:mine", None, false, ""));
        } else if let Some(first) = ap_ids.first() {
            map.edges.push(edge("gateway", first, None, true, ""));
        }
    }
    if let Some(me) = map.node("me") {
        let signal = me.signal;
        if map.node("ap:mine").is_some() {
            let label = signal.map(|dbm| format!("{dbm:.0} dBm")).unwrap_or_default();
            map.edges.push(edge("ap:mine", "me", signal, false, &label));
        } else if map.node("gateway").is_some() {
            map.edges.push(edge("gateway", "me", None, false, ""));
        }
    }
    let station_edges: Vec<(String, Option<f64>)> = map
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::WirelessClient)
        .map(|node| (node.id.clone(), node.signal))
        .collect();
    for (id, signal) in station_edges {
        let bssid = inputs
            .survey
            .and_then(|survey| {
                survey
                    .clients
                    .iter()
                    .find(|client| id == format!("sta:{}", client.mac))
                    .and_then(|client| client.bssids.first().cloned())
            })
            .unwrap_or_default();
        // A station heard on our own BSSID, or one we cannot place, hangs off our AP.
        let parent = if !bssid.is_empty() && map.node(&format!("ap:{bssid}")).is_some() {
            format!("ap:{bssid}")
        } else if map.node("ap:mine").is_some() {
            "ap:mine".to_string()
        } else if let Some(first) = ap_ids.first() {
            first.clone()
        } else {
            continue;
        };
        map.edges.push(edge(&parent, &id, signal, false, ""));
    }
    let wired: Vec<String> = map
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::WiredHost)
        .map(|node| node.id.clone())
        .collect();
    for id in wired {
        if map.node("gateway").is_some() {
            map.edges.push(edge("gateway", &id, None, true, ""));
        } else if map.node("ap:mine").is_some() {
            map.edges.push(edge("ap:mine", &id, None, true, ""));
        }
    }
    map
}

/// Move "your access point" / "this machine" to the middle of their row.
fn centre_primary(row: &mut Vec<MapNode>) {
    let primary = row
        .iter()
        .position(|node| matches!(node.kind, NodeKind::Me | NodeKind::AccessPoint));
    let Some(index) = primary else {
        return;
    };
    let middle = row.len() / 2;
    if index != middle {
        let node = row.remove(index);
        row.insert(middle, node);
    }
}

fn node(id: &str, label: &str, detail: &str, kind: NodeKind, signal: Option<f64>) -> MapNode {
    MapNode {
        id: id.to_string(),
        label: label.to_string(),
        detail: detail.to_string(),
        kind,
        signal,
        row: 0,
        column: 0,
        columns_in_row: 1,
        x: 0.5,
    }
}

fn edge(from: &str, to: &str, signal: Option<f64>, dashed: bool, label: &str) -> MapEdge {
    MapEdge {
        from: from.to_string(),
        to: to.to_string(),
        signal,
        dashed,
        label: label.to_string(),
    }
}

/// Draw the map, returning the id of any node the pointer is over.
pub fn draw(ui: &mut egui::Ui, map: &NetworkMap, height: f32) -> Option<String> {
    let width = ui.available_width().max(320.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, egui::Color32::from_gray(24));

    if let Some(reason) = &map.empty_reason {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            reason,
            egui::FontId::proportional(13.0),
            widgets::MUTED,
        );
        return None;
    }

    // The bottom row carries two lines of text under its nodes, so leave room for them.
    let plot = egui::Rect::from_min_max(
        rect.min + egui::vec2(6.0, 10.0),
        rect.max - egui::vec2(6.0, 38.0),
    );
    let rows = map.rows.max(1) as f32;
    let row_height = plot.height() / rows;
    let position = |node: &MapNode| -> egui::Pos2 {
        egui::pos2(
            plot.left() + plot.width() * node.x,
            plot.top() + row_height * (node.row as f32 + 0.35),
        )
    };

    for edge in &map.edges {
        let (Some(from), Some(to)) = (map.node(&edge.from), map.node(&edge.to)) else {
            continue;
        };
        let start = position(from);
        let end = position(to);
        let color = match edge.signal {
            Some(dbm) => widgets::signal_color(dbm).gamma_multiply(0.9),
            None => egui::Color32::from_gray(70),
        };
        let width = if edge.signal.is_some() { 2.5 } else { 1.5 };
        if edge.dashed {
            dashed_line(&painter, start, end, color, width);
        } else {
            painter.line_segment([start, end], egui::Stroke::new(width, color));
        }
        if !edge.label.is_empty() {
            // Two thirds of the way down, clear of the node captions at either end.
            let middle = start + (end - start) * 0.66;
            painter.text(
                middle + egui::vec2(12.0, 0.0),
                egui::Align2::LEFT_CENTER,
                &edge.label,
                egui::FontId::monospace(11.0),
                color,
            );
        }
    }

    let pointer = response.hover_pos();
    let mut hovered = None;
    for node in &map.nodes {
        let centre = position(node);
        let radius = node.radius();
        let color = node.color();
        if matches!(node.kind, NodeKind::Me | NodeKind::AccessPoint) {
            painter.circle_filled(centre, radius + 5.0, color.gamma_multiply(0.18));
        }
        painter.circle_filled(centre, radius, color.gamma_multiply(0.30));
        painter.circle_stroke(centre, radius, egui::Stroke::new(2.0, color));
        painter.text(
            centre,
            egui::Align2::CENTER_CENTER,
            glyph(node.kind),
            egui::FontId::proportional(radius * 0.9),
            color,
        );
        // Dense rows stagger their labels so neighbouring text cannot collide, and
        // small nodes keep their detail for the hover line rather than the canvas.
        let crowded = node.columns_in_row > 4;
        let stagger = if crowded && node.column % 2 == 1 { 15.0 } else { 0.0 };
        let label_limit = if crowded { 14 } else { 22 };
        painter.text(
            centre + egui::vec2(0.0, radius + 12.0 + stagger),
            egui::Align2::CENTER_CENTER,
            truncate(&node.label, label_limit),
            egui::FontId::proportional(12.0),
            egui::Color32::from_gray(225),
        );
        let show_detail = !node.detail.is_empty()
            && matches!(
                node.kind,
                NodeKind::Me | NodeKind::AccessPoint | NodeKind::Gateway
                    | NodeKind::OtherAccessPoint
            );
        if show_detail {
            painter.text(
                centre + egui::vec2(0.0, radius + 26.0 + stagger),
                egui::Align2::CENTER_CENTER,
                truncate(&node.detail, if crowded { 20 } else { 34 }),
                egui::FontId::monospace(10.0),
                widgets::MUTED,
            );
        }
        if let Some(pointer) = pointer {
            if pointer.distance(centre) <= radius + 6.0 {
                hovered = Some(node.id.clone());
            }
        }
    }
    hovered
}

fn glyph(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Internet => "W",
        NodeKind::Gateway => "G",
        NodeKind::AccessPoint | NodeKind::OtherAccessPoint => "A",
        NodeKind::Me => "M",
        NodeKind::WirelessClient => "c",
        NodeKind::WiredHost => "h",
    }
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut out: String = text.chars().take(limit.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn dashed_line(
    painter: &egui::Painter,
    start: egui::Pos2,
    end: egui::Pos2,
    color: egui::Color32,
    width: f32,
) {
    let delta = end - start;
    let length = delta.length();
    if length <= 0.5 {
        return;
    }
    let step = 8.0;
    let direction = delta / length;
    let mut travelled = 0.0;
    while travelled < length {
        let segment_end = (travelled + step * 0.6).min(length);
        painter.line_segment(
            [start + direction * travelled, start + direction * segment_end],
            egui::Stroke::new(width, color),
        );
        travelled += step;
    }
}
