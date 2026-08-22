//! Capture: live packet view, pcap export, and offline pcap inspection.

use eframe::egui;

use super::widgets::{self, fmt_bytes, header_row};
use super::{interface_picker, job_footer, root_hint, run_controls, stop_button, Action};
use crate::model::{CaptureReport, IfaceReport};
use crate::runner::{args, Job, Settings};

const FILTER_EXAMPLES: [(&str, &str); 6] = [
    ("", "everything"),
    ("tcp and port 443", "HTTPS"),
    ("dhcp or dns", "address and name service"),
    ("arp", "ARP chatter"),
    ("lldp or cdp", "switch announcements"),
    ("not port 22", "everything except my SSH session"),
];

pub struct CaptureTab {
    interface: String,
    filter: String,
    duration: u32,
    count: u32,
    snaplen: u32,
    outfile: String,
    promisc: bool,
    job: Option<Job>,
    error: Option<String>,
    tail: Vec<String>,

    open_path: String,
    open_job: Option<Job>,
    open_report: Option<CaptureReport>,
    open_error: Option<String>,
}

impl Default for CaptureTab {
    fn default() -> Self {
        Self {
            interface: String::new(),
            filter: String::new(),
            duration: 30,
            count: 0,
            snaplen: 65535,
            outfile: "capture.pcap".to_string(),
            promisc: true,
            job: None,
            error: None,
            tail: Vec::new(),
            open_path: String::new(),
            open_job: None,
            open_report: None,
            open_error: None,
        }
    }
}

impl CaptureTab {
    pub fn autorun(&mut self, settings: &Settings) {
        self.start(settings);
    }

    fn start(&mut self, settings: &Settings) {
        // Text mode (not --json) so packets stream in live; the trailing stats block
        // is printed by nettool when the capture ends.
        let mut argv = args(&["capture"]);
        if !self.interface.is_empty() {
            argv.push("-i".into());
            argv.push(self.interface.clone());
        }
        if !self.outfile.trim().is_empty() {
            argv.push("-w".into());
            argv.push(self.outfile.trim().to_string());
        }
        if self.duration > 0 {
            argv.push("-d".into());
            argv.push(self.duration.to_string());
        }
        if self.count > 0 {
            argv.push("-c".into());
            argv.push(self.count.to_string());
        }
        argv.push("-s".into());
        argv.push(self.snaplen.to_string());
        if !self.filter.trim().is_empty() {
            argv.push("-f".into());
            argv.push(self.filter.trim().to_string());
        }
        if !self.promisc {
            argv.push("--no-promisc".into());
        }
        self.error = None;
        self.tail.clear();
        self.job = Some(Job::spawn(settings, "capture", argv));
    }

    fn open_file(&mut self, settings: &Settings) {
        if self.open_path.trim().is_empty() {
            self.open_error = Some("enter the path of a pcap file".into());
            return;
        }
        let mut argv = args(&["pcap"]);
        argv.push(self.open_path.trim().to_string());
        argv.push("--json".into());
        if !self.filter.trim().is_empty() {
            argv.push("-f".into());
            argv.push(self.filter.trim().to_string());
        }
        self.open_error = None;
        self.open_report = None;
        self.open_job = Some(Job::spawn(settings, "pcap", argv));
    }

    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(job) = self.job.as_mut() {
            changed |= job.poll();
            if !job.running() {
                if let Some(result) = &job.result {
                    if !result.ok() && !job.cancelled && self.error.is_none() {
                        self.error = Some(result.error_text());
                    }
                }
            }
            self.tail = job.lines.iter().rev().take(400).rev().cloned().collect();
        }
        if let Some(job) = self.open_job.as_mut() {
            let updated = job.poll();
            if updated && !job.running() {
                match job.parse_json::<CaptureReport>() {
                    Some(Ok(report)) => self.open_report = Some(report),
                    Some(Err(err)) => self.open_error = Some(err),
                    None => {}
                }
            }
            changed |= updated;
        }
        changed
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &Settings,
        inventory: &Option<IfaceReport>,
    ) -> Action {
        let interfaces = inventory
            .as_ref()
            .map(|i| i.interfaces.as_slice())
            .unwrap_or(&[]);

        widgets::heading(ui, "Capture packets");
        ui.horizontal_wrapped(|ui| {
            ui.label("interface");
            interface_picker(ui, "cap_iface", &mut self.interface, interfaces, false);
            ui.label("for");
            ui.add(
                egui::DragValue::new(&mut self.duration)
                    .speed(1.0)
                    .range(0..=3600)
                    .suffix(" s"),
            );
            ui.label("or");
            ui.add(
                egui::DragValue::new(&mut self.count)
                    .speed(10.0)
                    .range(0..=1_000_000)
                    .suffix(" pkts"),
            );
            ui.label("snaplen");
            ui.add(
                egui::DragValue::new(&mut self.snaplen)
                    .speed(64.0)
                    .range(64..=262144),
            );
            ui.checkbox(&mut self.promisc, "promiscuous");
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("write to");
            ui.add(
                egui::TextEdit::singleline(&mut self.outfile)
                    .desired_width(220.0)
                    .hint_text("capture.pcap (leave empty for live view only)"),
            );
            if run_controls(ui, &self.job, "Start capture") {
                self.start(settings);
            }
            if stop_button(ui, &self.job) {
                if let Some(job) = self.job.as_mut() {
                    job.cancel();
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("filter");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(300.0)
                    .hint_text("tcp and port 443"),
            );
            egui::ComboBox::from_id_salt("filter_examples")
                .selected_text("examples")
                .width(200.0)
                .show_ui(ui, |ui| {
                    for (value, label) in FILTER_EXAMPLES {
                        if ui.selectable_label(self.filter == value, label).clicked() {
                            self.filter = value.to_string();
                        }
                    }
                });
        });
        ui.label(
            egui::RichText::new(
                "host / net / port / portrange / tcp / udp / icmp / arp / lldp / cdp / dhcp / \
                 dns / vlan N / ether host / tcp-syn, combined with and, or, not and ().",
            )
            .size(11.0)
            .color(widgets::MUTED),
        );
        root_hint(ui, "Capturing packets", settings.use_sudo);
        ui.add_space(6.0);

        let running = self.job.as_ref().map(|j| j.running()).unwrap_or(false);
        if self.job.is_some() {
            let header = if running {
                format!("live ({} lines)", self.tail.len())
            } else {
                "capture finished".to_string()
            };
            ui.label(egui::RichText::new(header).strong());
            egui::Frame::new()
                .fill(egui::Color32::from_gray(22))
                .inner_margin(egui::Margin::same(6))
                .corner_radius(4.0)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("cap_scroll")
                        .max_height(300.0)
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.tail {
                                ui.label(egui::RichText::new(line).monospace().size(11.0));
                            }
                            if self.tail.is_empty() {
                                ui.weak("waiting for packets...");
                            }
                        });
                });
        } else {
            ui.weak(
                "Captures are written as standard pcap files - open them in Wireshark, or \
                 summarise them below without leaving the app.",
            );
        }

        ui.add_space(6.0);
        job_footer(ui, &self.job, &self.error);

        ui.add_space(10.0);
        ui.separator();
        widgets::heading(ui, "Inspect a capture file");
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.open_path)
                    .desired_width(300.0)
                    .hint_text("path/to/capture.pcap"),
            );
            if ui.button("Summarise").clicked() {
                self.open_file(settings);
            }
            if !self.outfile.trim().is_empty() && ui.button("use last output file").clicked() {
                self.open_path = self.outfile.trim().to_string();
            }
            if self.open_job.as_ref().map(|j| j.running()).unwrap_or(false) {
                ui.spinner();
            }
            ui.label(
                egui::RichText::new("the capture filter above is applied to the file too")
                    .size(11.0)
                    .color(widgets::MUTED),
            );
        });

        if let Some(report) = &self.open_report {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "{} packets, {}",
                        report.packets,
                        fmt_bytes(report.bytes)
                    ))
                    .strong(),
                );
                if let Some(dropped) = report.kernel_dropped {
                    if dropped > 0 {
                        ui.colored_label(widgets::WARN, format!("{dropped} dropped by kernel"));
                    }
                }
            });
            ui.add_space(4.0);
            ui.columns(3, |columns| {
                counter_table(&mut columns[0], "protocol mix", &report.protocols, report.bytes);
                counter_table(&mut columns[1], "top talkers", &report.top_talkers, report.bytes);
                counter_table(
                    &mut columns[2],
                    "conversations",
                    &report.conversations,
                    report.bytes,
                );
            });
            if !report.vlans.is_empty() {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!(
                        "VLANs seen: {}",
                        report
                            .vlans
                            .iter()
                            .map(|(vlan, count)| format!("{vlan} ({count} pkts)"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .size(11.0),
                );
            }
        }
        job_footer(ui, &self.open_job, &self.open_error);
        Action::None
    }
}

fn counter_table(
    ui: &mut egui::Ui,
    title: &str,
    counters: &std::collections::BTreeMap<String, u64>,
    total: u64,
) {
    ui.label(egui::RichText::new(title).strong());
    egui::Grid::new(format!("counters_{title}"))
        .num_columns(3)
        .spacing([10.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            header_row(ui, &["name", "bytes", "share"]);
            for (name, value) in CaptureReport::ranked(counters).into_iter().take(10) {
                ui.label(egui::RichText::new(name).monospace().size(11.0));
                ui.monospace(fmt_bytes(value));
                let share = if total > 0 {
                    100.0 * value as f64 / total as f64
                } else {
                    0.0
                };
                ui.label(
                    egui::RichText::new(format!("{share:.0}%"))
                        .size(11.0)
                        .color(widgets::MUTED),
                );
                ui.end_row();
            }
        });
}
