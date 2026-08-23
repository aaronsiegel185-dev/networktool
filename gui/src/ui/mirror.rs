//! Mirror (SPAN) port capture: what is on each VLAN, and whether the mirror works.

use eframe::egui;

use super::widgets::{self, fmt_bytes, header_row, kv};
use super::{interface_picker, job_footer, root_hint, run_controls, stop_button, Action};
use crate::model::{IfaceReport, MirrorPlan, MirrorReport};
use crate::runner::{args, Job, Settings};

pub struct MirrorTab {
    interface: String,
    vlans: String,
    untagged: bool,
    duration: u32,
    snaplen: u32,
    outfile: String,
    split: bool,
    rotate_mb: u32,

    job: Option<Job>,
    report: Option<MirrorReport>,
    error: Option<String>,
    expanded: Option<i64>,
    from_pcap: String,

    plan_job: Option<Job>,
    plan: Option<MirrorPlan>,
    plan_error: Option<String>,
    plan_wait: u32,
    vendor: String,
    source_port: String,
}

impl Default for MirrorTab {
    fn default() -> Self {
        Self {
            interface: String::new(),
            vlans: String::new(),
            untagged: false,
            duration: 30,
            snaplen: 65535,
            outfile: String::new(),
            split: false,
            rotate_mb: 0,
            job: None,
            report: None,
            error: None,
            expanded: None,
            from_pcap: String::new(),
            plan_job: None,
            plan: None,
            plan_error: None,
            plan_wait: 65,
            vendor: String::new(),
            source_port: String::new(),
        }
    }
}

const VENDORS: [(&str, &str); 9] = [
    ("", "detect from LLDP/CDP"),
    ("cisco-ios", "Cisco IOS / IOS-XE"),
    ("cisco-nxos", "Cisco NX-OS"),
    ("aruba-cx", "ArubaOS-CX"),
    ("aruba-procurve", "ProCurve / ArubaOS-Switch"),
    ("juniper", "Junos"),
    ("mikrotik", "MikroTik RouterOS"),
    ("ubiquiti", "UniFi / EdgeSwitch"),
    ("extreme", "Extreme EXOS"),
];

impl MirrorTab {
    pub fn autorun(&mut self, settings: &Settings) {
        self.start(settings, false);
    }

    fn base_args(&self) -> Vec<String> {
        let mut argv = args(&["mirror", "--json"]);
        if !self.interface.is_empty() {
            argv.push("-i".into());
            argv.push(self.interface.clone());
        }
        for vlan in self.vlan_list() {
            argv.push("--vlan".into());
            argv.push(vlan.to_string());
        }
        argv
    }

    fn vlan_list(&self) -> Vec<i64> {
        self.vlans
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter_map(|part| part.trim().parse::<i64>().ok())
            .filter(|vlan| (0..=4095).contains(vlan))
            .collect()
    }

    fn start(&mut self, settings: &Settings, check_only: bool) {
        let mut argv = self.base_args();
        if check_only {
            argv.push("--check".into());
        } else {
            argv.push("-d".into());
            argv.push(self.duration.to_string());
        }
        argv.push("-s".into());
        argv.push(self.snaplen.to_string());
        if self.untagged && !self.vlan_list().is_empty() {
            argv.push("--untagged".into());
        }
        if !self.outfile.trim().is_empty() {
            argv.push("-w".into());
            argv.push(self.outfile.trim().to_string());
            if self.split {
                argv.push("--split".into());
            }
            if self.rotate_mb > 0 {
                argv.push("--rotate".into());
                argv.push(self.rotate_mb.to_string());
            }
        }
        self.error = None;
        self.report = None;
        self.job = Some(Job::spawn(settings, "mirror", argv));
    }

    fn analyse_file(&mut self, settings: &Settings) {
        if self.from_pcap.trim().is_empty() {
            self.error = Some("enter the path of a capture taken from the mirror".into());
            return;
        }
        let mut argv = self.base_args();
        argv.push("--from-pcap".into());
        argv.push(self.from_pcap.trim().to_string());
        self.error = None;
        self.report = None;
        self.job = Some(Job::spawn(settings, "mirror-file", argv));
    }

    fn start_plan(&mut self, settings: &Settings) {
        let mut argv = args(&["mirror", "--plan", "--json"]);
        if !self.interface.is_empty() {
            argv.push("-i".into());
            argv.push(self.interface.clone());
        }
        if let Some(vlan) = self.vlan_list().first() {
            argv.push("--vlan".into());
            argv.push(vlan.to_string());
        }
        if !self.vendor.is_empty() {
            argv.push("--vendor".into());
            argv.push(self.vendor.clone());
            argv.push("--no-listen".into());
        } else {
            argv.push("--wait".into());
            argv.push(self.plan_wait.to_string());
        }
        if !self.source_port.trim().is_empty() {
            argv.push("--source-port".into());
            argv.push(self.source_port.trim().to_string());
        }
        self.plan_error = None;
        self.plan = None;
        self.plan_job = Some(Job::spawn(settings, "mirror-plan", argv));
    }

    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(job) = self.job.as_mut() {
            let updated = job.poll();
            if updated && !job.running() {
                match job.parse_json::<MirrorReport>() {
                    Some(Ok(report)) => self.report = Some(report),
                    Some(Err(err)) => self.error = Some(err),
                    None => {}
                }
            }
            changed |= updated;
        }
        if let Some(job) = self.plan_job.as_mut() {
            let updated = job.poll();
            if updated && !job.running() {
                match job.parse_json::<MirrorPlan>() {
                    Some(Ok(plan)) => self.plan = Some(plan),
                    Some(Err(err)) => self.plan_error = Some(err),
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

        widgets::heading(ui, "Capture from a switch port mirror");
        ui.horizontal_wrapped(|ui| {
            ui.label("interface");
            interface_picker(ui, "mirror_iface", &mut self.interface, interfaces, false);
            ui.label("VLANs");
            ui.add(
                egui::TextEdit::singleline(&mut self.vlans)
                    .desired_width(120.0)
                    .hint_text("all (or 30,40)"),
            );
            ui.add_enabled(
                !self.vlan_list().is_empty(),
                egui::Checkbox::new(&mut self.untagged, "keep untagged"),
            );
            ui.label("for");
            ui.add(
                egui::DragValue::new(&mut self.duration)
                    .speed(1.0)
                    .range(1..=3600)
                    .suffix(" s"),
            );
            ui.label("snaplen");
            ui.add(
                egui::DragValue::new(&mut self.snaplen)
                    .speed(64.0)
                    .range(64..=262144),
            );
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("write to");
            ui.add(
                egui::TextEdit::singleline(&mut self.outfile)
                    .desired_width(220.0)
                    .hint_text("optional span.pcap"),
            );
            ui.add_enabled(
                !self.outfile.trim().is_empty(),
                egui::Checkbox::new(&mut self.split, "one file per VLAN"),
            );
            ui.label("rotate");
            ui.add(
                egui::DragValue::new(&mut self.rotate_mb)
                    .speed(10.0)
                    .range(0..=100_000)
                    .suffix(" MB"),
            );
            if run_controls(ui, &self.job, "Capture") {
                self.start(settings, false);
            }
            if self.job.as_ref().map(|j| !j.running()).unwrap_or(true)
                && ui.button("Check mirror").clicked()
            {
                self.start(settings, true);
            }
            if stop_button(ui, &self.job) {
                if let Some(job) = self.job.as_mut() {
                    job.cancel();
                }
            }
        });
        if !self.vlan_list().is_empty() {
            ui.label(
                egui::RichText::new(
                    "VLAN filtering runs in the kernel, so a busy mirror does not drown \
                     the capture.",
                )
                .size(11.0)
                .color(widgets::MUTED),
            );
        }
        root_hint(ui, "Capturing from a mirror port", settings.use_sudo);
        ui.horizontal_wrapped(|ui| {
            ui.label("or analyse a capture");
            ui.add(
                egui::TextEdit::singleline(&mut self.from_pcap)
                    .desired_width(240.0)
                    .hint_text("path/to/span.pcap"),
            );
            if ui.button("Analyse file").clicked() {
                self.analyse_file(settings);
            }
        });
        ui.add_space(6.0);

        if let Some(report) = &self.report {
            summary_row(ui, report);
            ui.add_space(6.0);
            let expanded = self.expanded;
            let mut toggle = None;
            egui::Grid::new("mirror_vlans")
                .num_columns(9)
                .spacing([14.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    header_row(
                        ui,
                        &["vlan", "frames", "bytes", "hosts", "macs", "bcast", "protocols",
                          "top talker", ""],
                    );
                    for vlan in &report.vlans {
                        ui.monospace(vlan.label());
                        ui.monospace(vlan.packets.to_string());
                        ui.monospace(fmt_bytes(vlan.bytes));
                        ui.monospace(vlan.unique_hosts.to_string());
                        ui.monospace(vlan.unique_macs.to_string());
                        let broadcast = vlan.broadcast_pct();
                        ui.colored_label(
                            if broadcast > 30.0 { widgets::WARN } else { widgets::MUTED },
                            format!("{broadcast:.0}%"),
                        );
                        ui.label(
                            egui::RichText::new(
                                ranked_names(&vlan.protocols, 3).join(", "),
                            )
                            .size(11.0),
                        );
                        ui.monospace(
                            ranked_names(&vlan.top_talkers, 1)
                                .first()
                                .cloned()
                                .unwrap_or_default(),
                        );
                        let open = expanded == vlan.vlan && vlan.vlan.is_some();
                        if ui
                            .selectable_label(open, if open { "hide" } else { "hosts" })
                            .clicked()
                        {
                            toggle = Some(if open { None } else { vlan.vlan });
                        }
                        ui.end_row();
                    }
                });
            if let Some(next) = toggle {
                self.expanded = next;
            }

            if let Some(selected) = self.expanded {
                if let Some(vlan) = report.vlans.iter().find(|v| v.vlan == Some(selected)) {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(format!("{} - hosts", vlan.label())).strong());
                    egui::Grid::new("mirror_hosts")
                        .num_columns(3)
                        .spacing([14.0, 3.0])
                        .striped(true)
                        .show(ui, |ui| {
                            header_row(ui, &["ip", "mac", "vendor"]);
                            for host in vlan.hosts.iter().take(60) {
                                ui.monospace(&host.ip);
                                ui.monospace(&host.mac);
                                ui.label(&host.vendor);
                                ui.end_row();
                            }
                        });
                    if !vlan.dhcp_servers.is_empty() {
                        ui.label(format!("DHCP servers: {}", vlan.dhcp_servers.join(", ")));
                    }
                    if !vlan.conversations.is_empty() {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("conversations").strong());
                        egui::Grid::new("mirror_convs")
                            .num_columns(2)
                            .spacing([14.0, 3.0])
                            .show(ui, |ui| {
                                for (pair, bytes) in ranked(&vlan.conversations, 10) {
                                    ui.monospace(pair);
                                    ui.monospace(fmt_bytes(bytes));
                                    ui.end_row();
                                }
                            });
                    }
                }
            }

            if !report.files.is_empty() {
                ui.add_space(6.0);
                ui.label(egui::RichText::new("files written").strong());
                egui::Grid::new("mirror_files")
                    .num_columns(3)
                    .spacing([14.0, 3.0])
                    .show(ui, |ui| {
                        for file in &report.files {
                            ui.monospace(&file.file);
                            ui.monospace(file.packets.to_string());
                            ui.monospace(fmt_bytes(file.bytes));
                            ui.end_row();
                        }
                    });
            }

            ui.add_space(6.0);
            widgets::heading(ui, "Findings");
            for (severity, message) in &report.findings {
                ui.horizontal_top(|ui| {
                    widgets::severity_badge(ui, severity);
                    ui.label(message);
                });
            }
        } else if self.job.is_none() {
            ui.weak(
                "Plug into the switch's mirror destination port. This shows every VLAN on \
                 it, who is on each one, and warns when the mirror is misconfigured - \
                 tags stripped, one direction only, or nothing but your own traffic.",
            );
        }

        ui.add_space(6.0);
        job_footer(ui, &self.job, &self.error);

        ui.add_space(10.0);
        ui.separator();
        widgets::heading(ui, "Set the mirror up on the switch");
        ui.horizontal_wrapped(|ui| {
            ui.label("switch");
            egui::ComboBox::from_id_salt("mirror_vendor")
                .selected_text(
                    VENDORS
                        .iter()
                        .find(|(value, _)| *value == self.vendor)
                        .map(|(_, label)| *label)
                        .unwrap_or("detect from LLDP/CDP"),
                )
                .width(220.0)
                .show_ui(ui, |ui| {
                    for (value, label) in VENDORS {
                        ui.selectable_value(&mut self.vendor, value.to_string(), label);
                    }
                });
            ui.label("source port");
            ui.add(
                egui::TextEdit::singleline(&mut self.source_port)
                    .desired_width(150.0)
                    .hint_text("blank = mirror the VLAN"),
            );
            if run_controls(ui, &self.plan_job, "Show commands") {
                self.start_plan(settings);
            }
        });
        if self.vendor.is_empty() {
            ui.label(
                egui::RichText::new(format!(
                    "listens up to {}s for LLDP/CDP to identify the switch and the port \
                     you are plugged into",
                    self.plan_wait
                ))
                .size(11.0)
                .color(widgets::MUTED),
            );
        }

        if let Some(plan) = &self.plan {
            ui.add_space(6.0);
            egui::Grid::new("plan_detail")
                .num_columns(2)
                .spacing([16.0, 3.0])
                .show(ui, |ui| {
                    kv(ui, "switch", if plan.switch.is_empty() {
                        "(no LLDP/CDP neighbour)".to_string()
                    } else {
                        plan.switch.clone()
                    });
                    kv(ui, "platform", &plan.vendor);
                    if !plan.management_ip.is_empty() {
                        kv(ui, "management ip", &plan.management_ip);
                    }
                    kv(ui, "mirror destination", if plan.destination_port.is_empty() {
                        "(this machine's port)".to_string()
                    } else {
                        plan.destination_port.clone()
                    });
                    if let Some(vlan) = plan.source_vlan {
                        kv(ui, "mirror source", format!("VLAN {vlan}"));
                    }
                });
            ui.add_space(4.0);
            let mut config = plan.config.clone();
            ui.add(
                egui::TextEdit::multiline(&mut config)
                    .code_editor()
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            ui.horizontal(|ui| {
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(plan.config.clone());
                }
                ui.label(
                    egui::RichText::new(
                        "Review before pasting: a mirror destination port stops forwarding \
                         normal traffic.",
                    )
                    .size(11.0)
                    .color(widgets::WARN),
                );
            });
        }
        job_footer(ui, &self.plan_job, &self.plan_error);
        Action::None
    }
}

fn summary_row(ui: &mut egui::Ui, report: &MirrorReport) {
    egui::Grid::new("mirror_summary")
        .num_columns(4)
        .spacing([24.0, 3.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("frames").color(widgets::MUTED));
            ui.monospace(format!("{} ({})", report.packets, fmt_bytes(report.bytes)));
            ui.label(egui::RichText::new("tagged / untagged").color(widgets::MUTED));
            ui.monospace(format!("{} / {}", report.tagged, report.untagged));
            ui.end_row();

            ui.label(egui::RichText::new("from other devices").color(widgets::MUTED));
            ui.monospace(format!(
                "{} (own: {})",
                report.foreign_traffic, report.own_traffic
            ));
            ui.label(egui::RichText::new("both directions").color(widgets::MUTED));
            ui.monospace(match report.bidirectional_share {
                Some(share) => format!("{:.0}% of conversations", share * 100.0),
                None => "-".to_string(),
            });
            ui.end_row();

            ui.label(egui::RichText::new("dropped by kernel").color(widgets::MUTED));
            ui.colored_label(
                if report.kernel_dropped > 0 { widgets::WARN } else { widgets::MUTED },
                report.kernel_dropped.to_string(),
            );
            ui.label(egui::RichText::new("QinQ frames").color(widgets::MUTED));
            ui.monospace(report.qinq.to_string());
            ui.end_row();
        });
}

/// Counter maps come back keyed by name; the useful order is by value, descending.
fn ranked(map: &std::collections::BTreeMap<String, u64>, take: usize) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.truncate(take);
    items
}

fn ranked_names(map: &std::collections::BTreeMap<String, u64>, take: usize) -> Vec<String> {
    ranked(map, take).into_iter().map(|(name, _)| name).collect()
}
