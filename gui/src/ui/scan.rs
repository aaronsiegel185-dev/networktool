//! Port scan: TCP connect or UDP probe scanning with banner grabbing.

use eframe::egui;
use std::collections::BTreeMap;

use super::widgets::{self, header_row};
use super::{job_footer, run_controls, stop_button, Action};
use crate::model::{IfaceReport, PortResult, ScanReport};
use crate::runner::{args, Job, Settings};

const PORT_PRESETS: [(&str, &str); 5] = [
    ("top", "top ~100 ports"),
    ("1-1024", "well-known 1-1024"),
    ("all", "all 65535 (slow)"),
    ("22,80,443,445,3389", "remote access"),
    ("80,443,8080,8443,8006,9090", "web admin"),
];

pub struct ScanTab {
    target: String,
    ports: String,
    udp: bool,
    banner: bool,
    all_states: bool,
    timeout: f32,
    workers: u32,
    job: Option<Job>,
    report: Option<ScanReport>,
    error: Option<String>,
}

impl Default for ScanTab {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: "top".to_string(),
            udp: false,
            banner: true,
            all_states: false,
            timeout: 1.0,
            workers: 256,
            job: None,
            report: None,
            error: None,
        }
    }
}

impl ScanTab {
    pub fn set_target(&mut self, target: String) {
        self.target = target;
    }

    pub fn autorun(&mut self, settings: &Settings) {
        if self.target.trim().is_empty() {
            self.target = "127.0.0.1".to_string();
        }
        self.start(settings);
    }

    fn start(&mut self, settings: &Settings) {
        if self.target.trim().is_empty() {
            self.error = Some("enter a target: an IP, hostname, CIDR or range".into());
            return;
        }
        let mut argv = args(&["scan"]);
        argv.push(self.target.trim().to_string());
        argv.push("--json".into());
        argv.push("-p".into());
        argv.push(self.ports.trim().to_string());
        if self.udp {
            argv.push("-u".into());
        }
        if self.banner && !self.udp {
            argv.push("-b".into());
        }
        if self.all_states {
            argv.push("--all-states".into());
        }
        argv.push("-t".into());
        argv.push(format!("{:.1}", self.timeout));
        argv.push("-w".into());
        argv.push(self.workers.to_string());
        self.error = None;
        self.report = None;
        self.job = Some(Job::spawn(settings, "scan", argv));
    }

    pub fn tick(&mut self) -> bool {
        let Some(job) = self.job.as_mut() else {
            return false;
        };
        let changed = job.poll();
        if changed && !job.running() {
            match job.parse_json::<ScanReport>() {
                Some(Ok(report)) => self.report = Some(report),
                Some(Err(err)) => self.error = Some(err),
                None => {}
            }
        }
        changed
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        settings: &Settings,
        _inventory: &Option<IfaceReport>,
    ) -> Action {
        widgets::heading(ui, "Scan ports");
        ui.horizontal_wrapped(|ui| {
            ui.label("target");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.target)
                    .desired_width(220.0)
                    .hint_text("10.0.0.5, host.local, 10.0.0.0/24, 10.0.0.1-50"),
            );
            ui.label("ports");
            ui.add(
                egui::TextEdit::singleline(&mut self.ports)
                    .desired_width(160.0)
                    .hint_text("top | all | 22,80,443 | 1-1024"),
            );
            egui::ComboBox::from_id_salt("port_preset")
                .selected_text("presets")
                .width(150.0)
                .show_ui(ui, |ui| {
                    for (value, label) in PORT_PRESETS {
                        if ui.selectable_label(self.ports == value, label).clicked() {
                            self.ports = value.to_string();
                        }
                    }
                });
            let submit = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if run_controls(ui, &self.job, "Scan") || submit {
                self.start(settings);
            }
            if stop_button(ui, &self.job) {
                if let Some(job) = self.job.as_mut() {
                    job.cancel();
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.udp, "UDP");
            ui.add_enabled(!self.udp, egui::Checkbox::new(&mut self.banner, "grab banners"));
            ui.checkbox(&mut self.all_states, "show closed/filtered");
            ui.label("timeout");
            ui.add(
                egui::DragValue::new(&mut self.timeout)
                    .speed(0.1)
                    .range(0.1..=10.0)
                    .suffix(" s"),
            );
            ui.label("parallel");
            ui.add(
                egui::DragValue::new(&mut self.workers)
                    .speed(8.0)
                    .range(1..=1024),
            );
        });
        if self.udp {
            ui.label(
                egui::RichText::new(
                    "UDP has no handshake: a silent port is reported open|filtered. \
                     Known protocols (DNS, NTP, SNMP, SSDP, mDNS, SIP, IKE) get real probes.",
                )
                .size(11.0)
                .color(widgets::MUTED),
            );
        }
        ui.add_space(6.0);

        if let Some(report) = &self.report {
            let open = report.results.iter().filter(|r| r.is_open()).count();
            ui.label(
                egui::RichText::new(format!(
                    "{open} open of {} port(s) across {} host(s) in {}",
                    report.ports,
                    report.hosts,
                    widgets::fmt_secs(report.seconds)
                ))
                .strong(),
            );
            ui.add_space(4.0);

            let mut by_host: BTreeMap<&str, Vec<&PortResult>> = BTreeMap::new();
            for result in &report.results {
                by_host.entry(result.host.as_str()).or_default().push(result);
            }
            for (host, results) in by_host {
                egui::CollapsingHeader::new(
                    egui::RichText::new(format!(
                        "{host}   ({} open)",
                        results.iter().filter(|r| r.is_open()).count()
                    ))
                    .monospace(),
                )
                .default_open(true)
                .id_salt(host)
                .show(ui, |ui| {
                    egui::Grid::new(format!("ports_{host}"))
                        .num_columns(5)
                        .spacing([16.0, 3.0])
                        .striped(true)
                        .show(ui, |ui| {
                            header_row(ui, &["port", "proto", "state", "service", "detail"]);
                            for result in results {
                                ui.monospace(result.port.to_string());
                                ui.label(&result.proto);
                                ui.colored_label(
                                    widgets::port_state_color(&result.state),
                                    &result.state,
                                );
                                ui.label(&result.service);
                                ui.label(
                                    egui::RichText::new(&result.detail)
                                        .monospace()
                                        .size(11.0),
                                );
                                ui.end_row();
                            }
                        });
                });
            }
            if report.results.is_empty() {
                ui.weak("No open ports found. Tick \"show closed/filtered\" to see every probe.");
            }
        } else if self.job.as_ref().map(|j| j.running()).unwrap_or(false) {
            ui.weak("scanning...");
        }

        ui.add_space(8.0);
        job_footer(ui, &self.job, &self.error);
        Action::None
    }
}
