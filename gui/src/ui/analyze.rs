//! Deep analysis of a capture file: conversations, endpoints, protocol hierarchy,
//! TCP health, DNS timing and stream following.

use eframe::egui;

use super::widgets::{self, fmt_bytes, header_row, kv, BarChartItem};
use super::{job_footer, run_controls, Action};
use crate::model::{AnalysisReport, Conversation, IfaceReport, StreamDump};
use crate::runner::{args, Job, Settings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Conversations,
    Endpoints,
    Protocols,
    Tcp,
    Dns,
    Throughput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp,
    Udp,
    Ip,
    Ipv6,
    Ethernet,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Tcp => "TCP",
            Kind::Udp => "UDP",
            Kind::Ip => "IPv4",
            Kind::Ipv6 => "IPv6",
            Kind::Ethernet => "Ethernet",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortBy {
    Bytes,
    Packets,
    Duration,
    Start,
}

pub struct AnalyzeTab {
    path: String,
    filter: String,
    view: View,
    kind: Kind,
    sort: SortBy,
    job: Option<Job>,
    report: Option<AnalysisReport>,
    error: Option<String>,

    stream_job: Option<Job>,
    stream: Option<StreamDump>,
    stream_error: Option<String>,
    stream_hex: bool,
}

impl Default for AnalyzeTab {
    fn default() -> Self {
        Self {
            path: String::new(),
            filter: String::new(),
            view: View::Conversations,
            kind: Kind::Tcp,
            sort: SortBy::Bytes,
            job: None,
            report: None,
            error: None,
            stream_job: None,
            stream: None,
            stream_error: None,
            stream_hex: false,
        }
    }
}

impl AnalyzeTab {
    /// Preload a capture the user just took elsewhere in the app.
    pub fn set_path(&mut self, path: String) {
        self.path = path;
    }

    pub fn set_view(&mut self, view: View) {
        self.view = view;
    }

    pub fn autorun(&mut self, settings: &Settings) {
        if !self.path.trim().is_empty() {
            self.start(settings);
        }
    }

    fn start(&mut self, settings: &Settings) {
        if self.path.trim().is_empty() {
            self.error = Some("enter the path of a capture file".into());
            return;
        }
        let mut argv = args(&["analyze"]);
        argv.push(self.path.trim().to_string());
        argv.push("--json".into());
        argv.push("-n".into());
        argv.push("100".into());
        if !self.filter.trim().is_empty() {
            argv.push("-f".into());
            argv.push(self.filter.trim().to_string());
        }
        self.error = None;
        self.report = None;
        self.stream = None;
        self.job = Some(Job::spawn(settings, "analyze", argv));
    }

    fn follow(&mut self, settings: &Settings, index: usize, kind: Kind) {
        let mut argv = args(&["analyze"]);
        argv.push(self.path.trim().to_string());
        argv.push("--json".into());
        argv.push("--follow".into());
        argv.push(index.to_string());
        argv.push("--stream-kind".into());
        argv.push(if kind == Kind::Udp { "udp".into() } else { "tcp".to_string() });
        if self.stream_hex {
            argv.push("--hex".into());
        }
        self.stream_error = None;
        self.stream = None;
        self.stream_job = Some(Job::spawn(settings, "follow", argv));
    }

    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(job) = self.job.as_mut() {
            let updated = job.poll();
            if updated && !job.running() {
                match job.parse_json::<AnalysisReport>() {
                    Some(Ok(report)) => self.report = Some(report),
                    Some(Err(err)) => self.error = Some(err),
                    None => {}
                }
            }
            changed |= updated;
        }
        if let Some(job) = self.stream_job.as_mut() {
            let updated = job.poll();
            if updated && !job.running() {
                match job.parse_json::<StreamDump>() {
                    Some(Ok(dump)) => self.stream = Some(dump),
                    Some(Err(err)) => self.stream_error = Some(err),
                    None => {}
                }
            }
            changed |= updated;
        }
        changed
    }

    fn conversations(&self) -> &[Conversation] {
        let Some(report) = self.report.as_ref() else {
            return &[];
        };
        match self.kind {
            Kind::Tcp => &report.conversations.tcp,
            Kind::Udp => &report.conversations.udp,
            Kind::Ip => &report.conversations.ip,
            Kind::Ipv6 => &report.conversations.ipv6,
            Kind::Ethernet => &report.conversations.ethernet,
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &Settings,
        _inventory: &Option<IfaceReport>,
    ) -> Action {
        widgets::heading(ui, "Analyse a capture");
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.path)
                    .desired_width(300.0)
                    .hint_text("path/to/capture.pcap"),
            );
            ui.label("filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(180.0)
                    .hint_text("optional, e.g. host 10.0.0.5"),
            );
            if run_controls(ui, &self.job, "Analyse") {
                self.start(settings);
            }
        });

        let Some(report) = self.report.clone() else {
            if self.job.is_none() {
                ui.weak(
                    "Conversations, endpoints, protocol hierarchy, TCP retransmissions and \
                     resets, DNS timing - the Statistics menu, on any pcap the mirror or \
                     capture tabs wrote.",
                );
            }
            job_footer(ui, &self.job, &self.error);
            return Action::None;
        };

        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "{} packets, {}, {}",
                    report.packets,
                    fmt_bytes(report.bytes),
                    widgets::fmt_secs(report.duration)
                ))
                .strong(),
            );
            if report.duration > 0.0 {
                ui.label(
                    egui::RichText::new(format!(
                        "{}/s average",
                        fmt_bytes((report.bytes as f64 / report.duration) as u64)
                    ))
                    .color(widgets::MUTED),
                );
            }
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            for (view, label) in [
                (View::Conversations, "Conversations"),
                (View::Endpoints, "Endpoints"),
                (View::Protocols, "Protocols"),
                (View::Tcp, "TCP health"),
                (View::Dns, "DNS"),
                (View::Throughput, "Throughput"),
            ] {
                if ui.selectable_label(self.view == view, label).clicked() {
                    self.view = view;
                }
            }
        });
        ui.add_space(4.0);

        match self.view {
            View::Conversations => self.conversations_view(ui, settings),
            View::Endpoints => endpoints_view(ui, &report),
            View::Protocols => protocols_view(ui, &report),
            View::Tcp => tcp_view(ui, &report),
            View::Dns => dns_view(ui, &report),
            View::Throughput => throughput_view(ui, &report),
        }

        ui.add_space(8.0);
        widgets::heading(ui, "Findings");
        for (severity, message) in &report.findings {
            ui.horizontal_top(|ui| {
                widgets::severity_badge(ui, severity);
                ui.label(message);
            });
        }
        ui.add_space(6.0);
        job_footer(ui, &self.job, &self.error);
        Action::None
    }

    fn conversations_view(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal_wrapped(|ui| {
            for kind in [Kind::Tcp, Kind::Udp, Kind::Ip, Kind::Ipv6, Kind::Ethernet] {
                if ui.selectable_label(self.kind == kind, kind.label()).clicked() {
                    self.kind = kind;
                }
            }
            ui.separator();
            ui.label("sort by");
            for (sort, label) in [
                (SortBy::Bytes, "bytes"),
                (SortBy::Packets, "packets"),
                (SortBy::Duration, "duration"),
                (SortBy::Start, "start"),
            ] {
                if ui.selectable_label(self.sort == sort, label).clicked() {
                    self.sort = sort;
                }
            }
            ui.checkbox(&mut self.stream_hex, "hex dump");
        });
        ui.add_space(4.0);

        let mut rows: Vec<(usize, Conversation)> = self
            .conversations()
            .iter()
            .cloned()
            .enumerate()
            .collect();
        match self.sort {
            SortBy::Bytes => rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes)),
            SortBy::Packets => rows.sort_by(|a, b| b.1.packets.cmp(&a.1.packets)),
            SortBy::Duration => rows.sort_by(|a, b| {
                b.1.duration
                    .partial_cmp(&a.1.duration)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            SortBy::Start => rows.sort_by(|a, b| {
                a.1.start
                    .partial_cmp(&b.1.start)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
        }

        let followable = matches!(self.kind, Kind::Tcp | Kind::Udp);
        let mut follow_index = None;
        egui::ScrollArea::vertical()
            .id_salt("conversations")
            .max_height(320.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("conversation_table")
                    .num_columns(10)
                    .spacing([12.0, 3.0])
                    .striped(true)
                    .show(ui, |ui| {
                        header_row(
                            ui,
                            &["address A", "address B", "A->B", "bytes", "B->A", "bytes",
                              "total", "duration", "bit/s A->B", ""],
                        );
                        for (index, conversation) in &rows {
                            ui.monospace(&conversation.a);
                            ui.monospace(&conversation.b);
                            ui.monospace(conversation.packets_ab.to_string());
                            ui.monospace(fmt_bytes(conversation.bytes_ab));
                            ui.monospace(conversation.packets_ba.to_string());
                            ui.monospace(fmt_bytes(conversation.bytes_ba));
                            ui.monospace(fmt_bytes(conversation.bytes));
                            ui.monospace(format!("{:.2}s", conversation.duration));
                            ui.monospace(format!("{:.0}", conversation.bps_ab));
                            if conversation.one_sided() {
                                ui.label(
                                    egui::RichText::new("one-sided")
                                        .size(11.0)
                                        .color(widgets::WARN),
                                )
                                .on_hover_text(
                                    "Only one direction was captured - a mirror configured \
                                     rx or tx only, or an unanswered connection.",
                                );
                            } else if followable && ui.small_button("follow").clicked() {
                                follow_index = Some(*index);
                            } else if !followable {
                                ui.label("");
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(index) = follow_index {
            let kind = self.kind;
            self.follow(settings, index, kind);
        }

        if self.stream_job.as_ref().map(|j| j.running()).unwrap_or(false) {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("reassembling the stream...");
            });
        }
        if let Some(dump) = &self.stream {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "stream: {} <-> {} ({})",
                        dump.conversation.a,
                        dump.conversation.b,
                        fmt_bytes(dump.bytes)
                    ))
                    .strong(),
                );
                ui.label(
                    egui::RichText::new("-> is A to B, <- is B to A")
                        .size(11.0)
                        .color(widgets::MUTED),
                );
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(dump.stream.clone());
                }
            });
            let mut text = dump.stream.clone();
            egui::ScrollArea::vertical()
                .id_salt("stream_body")
                .max_height(240.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );
                });
        }
        job_footer(ui, &self.stream_job, &self.stream_error);
    }
}

fn endpoints_view(ui: &mut egui::Ui, report: &AnalysisReport) {
    egui::Grid::new("endpoint_table")
        .num_columns(8)
        .spacing([14.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            header_row(
                ui,
                &["address", "packets", "bytes", "tx", "bytes tx", "rx", "bytes rx",
                  "peers / ports"],
            );
            for endpoint in report.endpoints.iter().take(40) {
                ui.monospace(&endpoint.address);
                ui.monospace(endpoint.packets.to_string());
                ui.monospace(fmt_bytes(endpoint.bytes));
                ui.monospace(endpoint.packets_tx.to_string());
                ui.monospace(fmt_bytes(endpoint.bytes_tx));
                ui.monospace(endpoint.packets_rx.to_string());
                ui.monospace(fmt_bytes(endpoint.bytes_rx));
                ui.label(
                    egui::RichText::new(format!(
                        "{} peers  {}",
                        endpoint.peers,
                        endpoint
                            .top_ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    ))
                    .size(11.0),
                );
                ui.end_row();
            }
        });
}

fn protocols_view(ui: &mut egui::Ui, report: &AnalysisReport) {
    egui::Grid::new("hierarchy_table")
        .num_columns(5)
        .spacing([14.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            header_row(ui, &["layers", "packets", "of packets", "bytes", "of bytes"]);
            for row in &report.hierarchy {
                ui.monospace(&row.layers);
                ui.monospace(row.packets.to_string());
                share_bar(ui, row.packets_pct);
                ui.monospace(fmt_bytes(row.bytes));
                share_bar(ui, row.bytes_pct);
                ui.end_row();
            }
        });
    if !report.vlans.is_empty() {
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(format!(
                "VLANs: {}",
                report
                    .vlans
                    .iter()
                    .map(|(vlan, count)| format!("{vlan} ({count})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .size(11.0),
        );
    }
}

fn share_bar(ui: &mut egui::Ui, percent: f64) {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(90.0, 12.0), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 2.0, egui::Color32::from_gray(45));
    let filled = egui::Rect::from_min_size(
        rect.min,
        egui::vec2(rect.width() * (percent as f32 / 100.0).clamp(0.0, 1.0), rect.height()),
    );
    painter.rect_filled(filled, 2.0, widgets::ACCENT.gamma_multiply(0.8));
    painter.text(
        rect.right_center() - egui::vec2(4.0, 0.0),
        egui::Align2::RIGHT_CENTER,
        format!("{percent:.1}%"),
        egui::FontId::monospace(10.0),
        egui::Color32::from_gray(230),
    );
    response.on_hover_text(format!("{percent:.2}%"));
}

fn tcp_view(ui: &mut egui::Ui, report: &AnalysisReport) {
    let tcp = &report.tcp;
    egui::Grid::new("tcp_health")
        .num_columns(2)
        .spacing([18.0, 4.0])
        .show(ui, |ui| {
            kv(ui, "segments / flows", format!("{} / {}", tcp.segments, tcp.flows));
            kv(
                ui,
                "completed handshakes",
                format!("{} of {} SYNs", tcp.completed_handshakes, tcp.syns),
            );
            kv(
                ui,
                "handshake time",
                format!(
                    "avg {} ms, max {} ms",
                    widgets::fmt_opt_f(tcp.handshake_ms_avg, 1),
                    widgets::fmt_opt_f(tcp.handshake_ms_max, 1)
                ),
            );
            ui.label(egui::RichText::new("retransmissions").color(widgets::MUTED));
            ui.colored_label(
                if tcp.retransmission_pct > 5.0 {
                    widgets::CRIT
                } else if tcp.retransmission_pct > 1.0 {
                    widgets::WARN
                } else {
                    widgets::MUTED
                },
                format!("{} ({:.2}%)", tcp.retransmissions, tcp.retransmission_pct),
            );
            ui.end_row();
            kv(ui, "out of order", tcp.out_of_order.to_string());
            kv(ui, "duplicate acks", tcp.duplicate_acks.to_string());
            kv(ui, "zero window", tcp.zero_window.to_string());
            kv(ui, "resets", tcp.resets.to_string());
        });
    if !tcp.unanswered_syns.is_empty() {
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new("connection attempts with no SYN/ACK")
                .strong()
                .color(widgets::WARN),
        );
        for entry in tcp.unanswered_syns.iter().take(10) {
            ui.monospace(&entry.to);
        }
    }
}

fn dns_view(ui: &mut egui::Ui, report: &AnalysisReport) {
    let dns = &report.dns;
    egui::Grid::new("dns_health")
        .num_columns(2)
        .spacing([18.0, 4.0])
        .show(ui, |ui| {
            kv(ui, "queries", dns.queries.to_string());
            kv(
                ui,
                "answered / unanswered",
                format!("{} / {}", dns.answered, dns.unanswered),
            );
            kv(
                ui,
                "response time",
                format!(
                    "avg {} ms, max {} ms",
                    widgets::fmt_opt_f(dns.latency_ms_avg, 1),
                    widgets::fmt_opt_f(dns.latency_ms_max, 1)
                ),
            );
        });
    if !dns.slowest.is_empty() {
        ui.add_space(6.0);
        ui.label(egui::RichText::new("slowest lookups").strong());
        egui::Grid::new("dns_slow")
            .num_columns(2)
            .spacing([14.0, 3.0])
            .striped(true)
            .show(ui, |ui| {
                for entry in &dns.slowest {
                    ui.monospace(&entry.name);
                    ui.monospace(format!("{:.1} ms", entry.ms));
                    ui.end_row();
                }
            });
    }
    if !dns.failures.is_empty() {
        ui.add_space(6.0);
        ui.label(egui::RichText::new("failures").strong().color(widgets::WARN));
        for (failure, count) in &dns.failures {
            ui.monospace(format!("{failure}  x{count}"));
        }
    }
}

fn throughput_view(ui: &mut egui::Ui, report: &AnalysisReport) {
    if report.throughput.len() < 2 {
        ui.weak("not enough of a time span to plot");
        return;
    }
    let items: Vec<BarChartItem> = report
        .throughput
        .iter()
        .map(|point| BarChartItem {
            label: format!("{:.0}", point.t),
            value: point.bps / 1000.0,
            color: widgets::ACCENT.gamma_multiply(0.85),
            marker: None,
        })
        .collect();
    ui.label(
        egui::RichText::new("kilobits per second, by second of capture")
            .size(11.0)
            .color(widgets::MUTED),
    );
    widgets::bar_chart(ui, &items, 160.0);
    let peak = report
        .throughput
        .iter()
        .map(|point| point.bps)
        .fold(0.0_f64, f64::max);
    ui.label(format!(
        "peak {}/s over {} buckets",
        fmt_bytes((peak / 8.0) as u64),
        report.throughput.len()
    ));
}
