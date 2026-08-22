//! Overview: the health check plus the interface, route and DNS inventory.

use eframe::egui;

use super::widgets::{self, fmt_bytes, header_row, kv};
use super::{job_footer, run_controls, Action};
use crate::model::{DiagReport, IfaceReport, PingReport};
use crate::runner::{args, Job, Settings};

pub struct OverviewTab {
    pub interface: String,
    pub skip_internet: bool,
    pub skip_mtu: bool,
    job: Option<Job>,
    report: Option<DiagReport>,
    error: Option<String>,

    ping_target: String,
    ping_count: u32,
    ping_job: Option<Job>,
    ping_report: Option<PingReport>,
    ping_error: Option<String>,
}

impl Default for OverviewTab {
    fn default() -> Self {
        Self {
            interface: String::new(),
            skip_internet: false,
            skip_mtu: false,
            job: None,
            report: None,
            error: None,
            ping_target: String::new(),
            ping_count: 5,
            ping_job: None,
            ping_report: None,
            ping_error: None,
        }
    }
}

impl OverviewTab {
    /// Start the tab's primary action (used by `--autorun`).
    pub fn autorun(&mut self, settings: &Settings) {
        self.start(settings);
    }

    fn start(&mut self, settings: &Settings) {
        let mut argv = args(&["diag", "--json"]);
        if !self.interface.is_empty() {
            argv.push("-i".into());
            argv.push(self.interface.clone());
        }
        if self.skip_internet {
            argv.push("--skip".into());
            argv.push("internet".into());
        }
        if self.skip_mtu {
            argv.push("--skip".into());
            argv.push("mtu".into());
        }
        self.error = None;
        self.job = Some(Job::spawn(settings, "diag", argv));
    }

    fn start_ping(&mut self, settings: &Settings) {
        let target = self.ping_target.trim();
        if target.is_empty() {
            self.ping_error = Some("enter a host or address to ping".into());
            return;
        }
        let argv = vec![
            "ping".to_string(),
            target.to_string(),
            "--json".to_string(),
            "-c".to_string(),
            self.ping_count.to_string(),
            "-n".to_string(),
            "0.25".to_string(),
        ];
        self.ping_error = None;
        self.ping_report = None;
        self.ping_job = Some(Job::spawn(settings, "ping", argv));
    }

    /// Drain the running jobs; returns true when the UI should repaint.
    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(job) = self.ping_job.as_mut() {
            let updated = job.poll();
            if updated && !job.running() {
                match job.parse_json::<PingReport>() {
                    Some(Ok(report)) => self.ping_report = Some(report),
                    Some(Err(err)) => self.ping_error = Some(err),
                    None => {}
                }
            }
            changed |= updated;
        }
        let Some(job) = self.job.as_mut() else {
            return changed;
        };
        let changed = changed | job.poll();
        if changed && !job.running() {
            // `diag` exits 1 when a check is critical, which is still a valid report.
            match job.parse_json::<DiagReport>() {
                Some(Ok(report)) => {
                    self.report = Some(report);
                    self.error = None;
                }
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
        inventory: &Option<IfaceReport>,
    ) -> Action {
        let mut action = Action::None;
        ui.horizontal(|ui| {
            widgets::heading(ui, "Health check");
            ui.add_space(8.0);
            super::interface_picker(
                ui,
                "diag_iface",
                &mut self.interface,
                inventory
                    .as_ref()
                    .map(|i| i.interfaces.as_slice())
                    .unwrap_or(&[]),
                false,
            );
            ui.checkbox(&mut self.skip_internet, "skip internet");
            ui.checkbox(&mut self.skip_mtu, "skip MTU");
            if run_controls(ui, &self.job, "Run check") {
                self.start(settings);
            }
        });
        ui.add_space(4.0);

        if let Some(report) = &self.report {
            let color = widgets::severity_color(&report.worst);
            egui::Frame::new()
                .fill(color.gamma_multiply(0.12))
                .inner_margin(egui::Margin::same(8))
                .corner_radius(4.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(&report.verdict).color(color).strong());
                });
            ui.add_space(6.0);
            egui::Grid::new("diag_checks")
                .num_columns(3)
                .spacing([10.0, 6.0])
                .striped(true)
                .show(ui, |ui| {
                    for check in &report.checks {
                        widgets::severity_badge(ui, &check.severity);
                        ui.label(egui::RichText::new(&check.check).monospace());
                        ui.label(&check.message);
                        ui.end_row();
                    }
                });
        } else if self.job.is_none() {
            ui.weak("Run the check to test link, addressing, gateway, DNS, internet, MTU and Wi-Fi in one pass.");
        }

        job_footer(ui, &self.job, &self.error);
        ui.add_space(10.0);
        ui.separator();

        widgets::heading(ui, "Reachability test");
        ui.horizontal_wrapped(|ui| {
            ui.label("ping");
            ui.add(
                egui::TextEdit::singleline(&mut self.ping_target)
                    .desired_width(200.0)
                    .hint_text("gateway, 1.1.1.1, host.local"),
            );
            ui.add(
                egui::DragValue::new(&mut self.ping_count)
                    .speed(1.0)
                    .range(1..=100)
                    .suffix(" probes"),
            );
            if let Some(gateway) = inventory.as_ref().and_then(|i| i.default_gateway.clone()) {
                if ui.button("use gateway").clicked() {
                    self.ping_target = gateway;
                }
            }
            if run_controls(ui, &self.ping_job, "Ping") {
                self.start_ping(settings);
            }
        });
        if let Some(report) = &self.ping_report {
            let loss_color = if report.loss_pct > 20.0 {
                widgets::CRIT
            } else if report.loss_pct > 0.0 {
                widgets::WARN
            } else {
                widgets::OK
            };
            ui.horizontal_wrapped(|ui| {
                ui.monospace(format!("{} ({})", report.host, report.address));
                ui.colored_label(
                    loss_color,
                    format!("{:.0}% loss", report.loss_pct),
                );
                ui.monospace(format!(
                    "rtt min/avg/max {} / {} / {} ms",
                    widgets::fmt_opt_f(report.rtt_min, 2),
                    widgets::fmt_opt_f(report.rtt_avg, 2),
                    widgets::fmt_opt_f(report.rtt_max, 2)
                ));
                if let Some(jitter) = report.jitter {
                    ui.monospace(format!("jitter {jitter:.2} ms"));
                }
            });
            for error in &report.errors {
                ui.colored_label(widgets::WARN, error);
            }
        }
        job_footer(ui, &self.ping_job, &self.ping_error);
        ui.add_space(10.0);
        ui.separator();

        ui.horizontal(|ui| {
            widgets::heading(ui, "Interfaces");
            if ui.button("Refresh").clicked() {
                action = Action::RefreshInterfaces;
            }
        });

        let Some(inventory) = inventory else {
            ui.weak("no interface data yet");
            return action;
        };

        egui::Grid::new("iface_table")
            .num_columns(9)
            .spacing([14.0, 4.0])
            .striped(true)
            .show(ui, |ui| {
                header_row(
                    ui,
                    &["iface", "type", "state", "ipv4", "mac", "mtu", "speed", "rx / tx", "errors"],
                );
                for iface in &inventory.interfaces {
                    ui.monospace(&iface.name);
                    ui.label(if iface.wireless {
                        "wifi"
                    } else if iface.loopback {
                        "loopback"
                    } else {
                        "wired"
                    });
                    let up = iface.up && iface.operstate != "down";
                    ui.colored_label(
                        if up { widgets::OK } else { widgets::MUTED },
                        if up { "up" } else { "down" },
                    );
                    ui.monospace(if iface.ipv4.is_empty() {
                        "-".to_string()
                    } else {
                        iface.cidr()
                    });
                    ui.monospace(&iface.mac);
                    ui.monospace(iface.mtu.to_string());
                    ui.monospace(match iface.speed_mbps {
                        Some(speed) if speed > 0 => format!("{speed} Mb/s"),
                        _ => "-".to_string(),
                    });
                    ui.monospace(format!(
                        "{} / {}",
                        fmt_bytes(iface.counters.rx_bytes),
                        fmt_bytes(iface.counters.tx_bytes)
                    ));
                    let errors = iface.counters.rx_errors + iface.counters.tx_errors;
                    ui.colored_label(
                        if errors > 0 { widgets::WARN } else { widgets::MUTED },
                        errors.to_string(),
                    );
                    ui.end_row();
                }
            });

        ui.add_space(8.0);
        ui.columns(2, |columns| {
            columns[0].label(egui::RichText::new("Routing").strong());
            egui::Grid::new("routes")
                .num_columns(4)
                .spacing([12.0, 3.0])
                .show(&mut columns[0], |ui| {
                    header_row(ui, &["iface", "destination", "gateway", "metric"]);
                    for route in &inventory.routes {
                        ui.monospace(&route.iface);
                        ui.monospace(format!("{}/{}", route.dest, route.prefixlen));
                        ui.monospace(&route.gateway);
                        ui.monospace(route.metric.to_string());
                        ui.end_row();
                    }
                });
            columns[1].label(egui::RichText::new("Resolution").strong());
            egui::Grid::new("dns")
                .num_columns(2)
                .spacing([12.0, 3.0])
                .show(&mut columns[1], |ui| {
                    kv(
                        ui,
                        "default gateway",
                        inventory
                            .default_gateway
                            .clone()
                            .unwrap_or_else(|| "(none)".into()),
                    );
                    kv(
                        ui,
                        "via interface",
                        inventory
                            .gateway_interface
                            .clone()
                            .unwrap_or_else(|| "-".into()),
                    );
                    kv(ui, "dns servers", inventory.dns_servers.join(", "));
                    if !inventory.dns_search.is_empty() {
                        kv(ui, "search domains", inventory.dns_search.join(" "));
                    }
                    kv(
                        ui,
                        "arp entries",
                        inventory
                            .arp
                            .iter()
                            .filter(|e| !e.incomplete)
                            .count()
                            .to_string(),
                    );
                });
        });
        action
    }
}
