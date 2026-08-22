//! Discover: sweep the LAN and list what answers.

use eframe::egui;

use super::widgets::{self, header_row};
use super::{interface_picker, job_footer, root_hint, run_controls, stop_button, Action};
use crate::model::{DiscoverReport, IfaceReport};
use crate::runner::{args, Job, Settings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Auto,
    Arp,
    Icmp,
    Tcp,
}

impl Method {
    fn flag(self) -> &'static str {
        match self {
            Method::Auto => "auto",
            Method::Arp => "arp",
            Method::Icmp => "icmp",
            Method::Tcp => "tcp",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Method::Auto => "ARP when privileged, TCP otherwise",
            Method::Arp => "broadcast ARP - finds hosts that ignore ping (needs root)",
            Method::Icmp => "ping sweep - works across routers, often firewalled",
            Method::Tcp => "connect probes on common ports - no privileges needed",
        }
    }
}

pub struct DiscoverTab {
    interface: String,
    cidr: String,
    method: Method,
    timeout: f32,
    resolve: bool,
    job: Option<Job>,
    report: Option<DiscoverReport>,
    error: Option<String>,
    filter: String,
}

impl Default for DiscoverTab {
    fn default() -> Self {
        Self {
            interface: String::new(),
            cidr: String::new(),
            method: Method::Auto,
            timeout: 3.0,
            resolve: true,
            job: None,
            report: None,
            error: None,
            filter: String::new(),
        }
    }
}

impl DiscoverTab {
    pub fn autorun(&mut self, settings: &Settings) {
        self.start(settings);
    }

    fn start(&mut self, settings: &Settings) {
        let mut argv = args(&["discover", "--json"]);
        if !self.interface.is_empty() {
            argv.push("-i".into());
            argv.push(self.interface.clone());
        }
        if !self.cidr.trim().is_empty() {
            argv.push("-c".into());
            argv.push(self.cidr.trim().to_string());
        }
        argv.push("-m".into());
        argv.push(self.method.flag().to_string());
        argv.push("-t".into());
        argv.push(format!("{:.1}", self.timeout));
        if !self.resolve {
            argv.push("--no-resolve".into());
        }
        self.error = None;
        self.report = None;
        self.job = Some(Job::spawn(settings, "discover", argv));
    }

    pub fn tick(&mut self) -> bool {
        let Some(job) = self.job.as_mut() else {
            return false;
        };
        let changed = job.poll();
        if changed && !job.running() {
            match job.parse_json::<DiscoverReport>() {
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
        inventory: &Option<IfaceReport>,
    ) -> Action {
        let mut action = Action::None;
        let interfaces = inventory
            .as_ref()
            .map(|i| i.interfaces.as_slice())
            .unwrap_or(&[]);

        widgets::heading(ui, "Find hosts on the LAN");
        ui.horizontal_wrapped(|ui| {
            ui.label("interface");
            interface_picker(ui, "disc_iface", &mut self.interface, interfaces, false);
            ui.label("subnet");
            ui.add(
                egui::TextEdit::singleline(&mut self.cidr)
                    .desired_width(150.0)
                    .hint_text("this interface's"),
            );
            if ui.button("use interface subnet").clicked() {
                if let Some(iface) = interfaces
                    .iter()
                    .find(|i| i.name == self.interface || self.interface.is_empty())
                    .filter(|i| !i.ipv4.is_empty())
                {
                    self.cidr = iface.subnet();
                }
            }
            egui::ComboBox::from_id_salt("disc_method")
                .selected_text(self.method.flag())
                .width(90.0)
                .show_ui(ui, |ui| {
                    for method in [Method::Auto, Method::Arp, Method::Icmp, Method::Tcp] {
                        ui.selectable_value(&mut self.method, method, method.flag());
                    }
                });
            ui.add(
                egui::DragValue::new(&mut self.timeout)
                    .speed(0.2)
                    .range(0.5..=30.0)
                    .suffix(" s"),
            );
            ui.checkbox(&mut self.resolve, "reverse DNS");
            if run_controls(ui, &self.job, "Sweep") {
                self.start(settings);
            }
            if stop_button(ui, &self.job) {
                if let Some(job) = self.job.as_mut() {
                    job.cancel();
                }
            }
        });
        ui.label(
            egui::RichText::new(self.method.describe())
                .size(11.0)
                .color(widgets::MUTED),
        );
        if matches!(self.method, Method::Arp | Method::Auto) {
            root_hint(ui, "ARP sweeping", settings.use_sudo);
        }
        ui.add_space(6.0);

        if let Some(report) = &self.report {
            if !report.duplicate_ips.is_empty() {
                egui::Frame::new()
                    .fill(widgets::CRIT.gamma_multiply(0.14))
                    .inner_margin(egui::Margin::same(8))
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.colored_label(
                                widgets::CRIT,
                                "Duplicate IP addresses - two devices are claiming one address:",
                            );
                            for (ip, macs) in &report.duplicate_ips {
                                ui.monospace(format!("{ip}  <-  {}", macs.join(", ")));
                            }
                        });
                    });
                ui.add_space(6.0);
            }

            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "{} host(s) found via {}",
                        report.hosts.len(),
                        report.method
                    ))
                    .strong(),
                );
                ui.add_space(12.0);
                ui.label("filter");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .desired_width(160.0)
                        .hint_text("ip, mac or vendor"),
                );
            });
            ui.add_space(4.0);

            let needle = self.filter.to_lowercase();
            egui::Grid::new("hosts")
                .num_columns(7)
                .spacing([14.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    header_row(
                        ui,
                        &["ip", "mac", "vendor", "hostname", "via", "rtt", ""],
                    );
                    for host in &report.hosts {
                        if !needle.is_empty()
                            && !host.ip.to_lowercase().contains(&needle)
                            && !host.mac.to_lowercase().contains(&needle)
                            && !host.vendor.to_lowercase().contains(&needle)
                            && !host.name.to_lowercase().contains(&needle)
                        {
                            continue;
                        }
                        ui.monospace(&host.ip);
                        ui.monospace(&host.mac);
                        ui.label(&host.vendor);
                        ui.label(&host.name);
                        ui.label(
                            egui::RichText::new(&host.method)
                                .size(11.0)
                                .color(widgets::MUTED),
                        );
                        ui.monospace(match host.rtt_ms {
                            Some(rtt) => format!("{rtt:.1} ms"),
                            None => "-".to_string(),
                        });
                        if ui.small_button("scan ports").clicked() {
                            action = Action::ScanTarget(host.ip.clone());
                        }
                        ui.end_row();
                    }
                });
        } else if self.job.is_none() {
            ui.weak(
                "An ARP sweep finds every device on the local subnet, including ones that \
                 drop pings and firewall every port.",
            );
        }

        ui.add_space(8.0);
        job_footer(ui, &self.job, &self.error);
        action
    }
}
