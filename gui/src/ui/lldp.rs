//! LLDP / CDP: what switch and port is this cable in, and what VLAN does it carry?

use eframe::egui;

use super::widgets::{self, kv};
use super::{interface_picker, job_footer, root_hint, run_controls, stop_button, Action};
use crate::model::{IfaceReport, LldpReport, Neighbor};
use crate::runner::{args, Job, Settings};

pub struct LldpTab {
    interface: String,
    timeout: u32,
    wait_all: bool,
    save_pcap: String,
    from_pcap: String,
    job: Option<Job>,
    report: Option<LldpReport>,
    error: Option<String>,
    source: String,
}

impl Default for LldpTab {
    fn default() -> Self {
        Self {
            interface: String::new(),
            timeout: 65,
            wait_all: false,
            save_pcap: String::new(),
            from_pcap: String::new(),
            job: None,
            report: None,
            error: None,
            source: String::new(),
        }
    }
}

impl LldpTab {
    pub fn autorun(&mut self, settings: &Settings) {
        self.listen(settings);
    }

    fn listen(&mut self, settings: &Settings) {
        let mut argv = args(&["lldp", "--json"]);
        if !self.interface.is_empty() {
            argv.push("-i".into());
            argv.push(self.interface.clone());
        }
        argv.push("-t".into());
        argv.push(self.timeout.to_string());
        if self.wait_all {
            argv.push("--wait-all".into());
        }
        if !self.save_pcap.trim().is_empty() {
            argv.push("--pcap".into());
            argv.push(self.save_pcap.trim().to_string());
        }
        self.error = None;
        self.report = None;
        self.source = format!("listening on {}", if self.interface.is_empty() {
            "the default interface".to_string()
        } else {
            self.interface.clone()
        });
        self.job = Some(Job::spawn(settings, "lldp", argv));
    }

    fn load_pcap(&mut self, settings: &Settings) {
        if self.from_pcap.trim().is_empty() {
            self.error = Some("enter the path of a capture file".into());
            return;
        }
        let argv = vec![
            "lldp".to_string(),
            "--from-pcap".to_string(),
            self.from_pcap.trim().to_string(),
            "--json".to_string(),
        ];
        self.error = None;
        self.report = None;
        self.source = format!("from {}", self.from_pcap.trim());
        self.job = Some(Job::spawn(settings, "lldp-pcap", argv));
    }

    pub fn tick(&mut self) -> bool {
        let Some(job) = self.job.as_mut() else {
            return false;
        };
        let changed = job.poll();
        if changed && !job.running() {
            match job.parse_json::<LldpReport>() {
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
        let interfaces = inventory
            .as_ref()
            .map(|i| i.interfaces.as_slice())
            .unwrap_or(&[]);

        widgets::heading(ui, "Switch neighbours");
        ui.horizontal_wrapped(|ui| {
            ui.label("interface");
            interface_picker(ui, "lldp_iface", &mut self.interface, interfaces, false);
            ui.label("listen for");
            ui.add(
                egui::DragValue::new(&mut self.timeout)
                    .speed(1.0)
                    .range(5..=600)
                    .suffix(" s"),
            );
            ui.checkbox(&mut self.wait_all, "collect every neighbour");
            if run_controls(ui, &self.job, "Listen") {
                self.listen(settings);
            }
            if stop_button(ui, &self.job) {
                if let Some(job) = self.job.as_mut() {
                    job.cancel();
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("save frames to");
            ui.add(
                egui::TextEdit::singleline(&mut self.save_pcap)
                    .desired_width(220.0)
                    .hint_text("optional neighbours.pcap"),
            );
            ui.separator();
            ui.label("or decode a capture");
            ui.add(
                egui::TextEdit::singleline(&mut self.from_pcap)
                    .desired_width(220.0)
                    .hint_text("path/to/capture.pcap"),
            );
            if ui.button("Load file").clicked() {
                self.load_pcap(settings);
            }
        });
        ui.label(
            egui::RichText::new(
                "Switches announce themselves every 30 s (LLDP) or 60 s (CDP), so a listen \
                 can take a minute before anything appears.",
            )
            .size(11.0)
            .color(widgets::MUTED),
        );
        root_hint(ui, "Listening for LLDP", settings.use_sudo);
        ui.add_space(6.0);

        if self.job.as_ref().map(|j| j.running()).unwrap_or(false) {
            ui.label(
                egui::RichText::new(&self.source)
                    .color(widgets::ACCENT)
                    .size(12.0),
            );
        }

        if let Some(report) = &self.report {
            if report.neighbors.is_empty() {
                egui::Frame::new()
                    .fill(widgets::WARN.gamma_multiply(0.12))
                    .inner_margin(egui::Margin::same(8))
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.colored_label(widgets::WARN, "No LLDP or CDP frames seen.");
                            ui.label("- the switch port may have LLDP/CDP disabled");
                            ui.label("- you may be behind an unmanaged switch or a hypervisor bridge");
                            ui.label("- try listening for longer, e.g. 120 s");
                        });
                    });
            }
            for (index, neighbor) in report.neighbors.iter().enumerate() {
                neighbor_card(ui, index, neighbor);
                ui.add_space(6.0);
            }
        } else if self.job.is_none() {
            ui.weak(
                "The fastest way to answer \"which switch port am I plugged into?\" - \
                 it also reports the native VLAN, PoE budget and management IP.",
            );
        }

        ui.add_space(6.0);
        job_footer(ui, &self.job, &self.error);
        Action::None
    }
}

fn neighbor_card(ui: &mut egui::Ui, index: usize, neighbor: &Neighbor) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(neighbor.title())
                    .strong()
                    .size(15.0)
                    .color(widgets::ACCENT),
            );
            ui.label(
                egui::RichText::new(&neighbor.protocol)
                    .monospace()
                    .size(11.0)
                    .color(widgets::MUTED),
            );
            if !neighbor.vendor.is_empty() {
                ui.label(
                    egui::RichText::new(&neighbor.vendor)
                        .size(11.0)
                        .color(widgets::MUTED),
                );
            }
        });
        ui.add_space(4.0);
        egui::Grid::new(format!("neighbor_{index}"))
            .num_columns(2)
            .spacing([14.0, 3.0])
            .show(ui, |ui| {
                kv(
                    ui,
                    "port",
                    format!("{} ({})", neighbor.port_id, neighbor.port_id_type),
                );
                if !neighbor.port_description.is_empty() {
                    kv(ui, "port description", &neighbor.port_description);
                }
                kv(
                    ui,
                    "chassis",
                    format!("{} ({})", neighbor.chassis_id, neighbor.chassis_id_type),
                );
                if let Some(vlan) = neighbor.port_vlan_id {
                    kv(ui, "native VLAN", vlan.to_string());
                }
                if let Some(vlan) = neighbor.voice_vlan {
                    kv(ui, "voice VLAN", vlan.to_string());
                }
                if !neighbor.vlans.is_empty() {
                    kv(
                        ui,
                        "VLANs",
                        neighbor
                            .vlans
                            .iter()
                            .map(|v| format!("{} ({})", v.vlan, v.name))
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                }
                let mgmt = neighbor.mgmt_ip();
                if !mgmt.is_empty() {
                    kv(ui, "management IP", mgmt);
                }
                if !neighbor.platform.is_empty() {
                    kv(ui, "platform", &neighbor.platform);
                }
                let caps = if neighbor.enabled_capabilities.is_empty() {
                    &neighbor.capabilities
                } else {
                    &neighbor.enabled_capabilities
                };
                if !caps.is_empty() {
                    kv(ui, "capabilities", caps.join(", "));
                }
                if let Some(mau) = &neighbor.mau_type {
                    kv(ui, "link type", mau);
                }
                if let Some(duplex) = &neighbor.duplex {
                    kv(ui, "duplex", duplex);
                }
                if let Some(frame) = neighbor.max_frame_size.or(neighbor.mtu) {
                    kv(ui, "max frame", frame.to_string());
                }
                if let Some(domain) = &neighbor.vtp_domain {
                    kv(ui, "VTP domain", domain);
                }
                if let Some(poe) = &neighbor.poe {
                    let mut bits: Vec<String> = Vec::new();
                    if let Some(class) = &poe.port_class {
                        bits.push(format!("{class} class {}", widgets::fmt_opt(poe.power_class)));
                    }
                    if let Some(mw) = poe.allocated_mw {
                        bits.push(format!("allocated {:.1} W", mw as f64 / 1000.0));
                    }
                    if let Some(mw) = poe.requested_mw {
                        bits.push(format!("requested {:.1} W", mw as f64 / 1000.0));
                    }
                    if let Some(mw) = poe.consumption_mw {
                        bits.push(format!("draw {:.1} W", mw as f64 / 1000.0));
                    }
                    if !bits.is_empty() {
                        kv(ui, "PoE", bits.join(", "));
                    }
                }
                if let Some(ttl) = neighbor.ttl {
                    kv(ui, "advertised TTL", format!("{ttl} s"));
                }
            });
        if !neighbor.system_description.is_empty() {
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(neighbor.system_description.replace('\n', " "))
                    .size(11.0)
                    .color(widgets::MUTED),
            );
        }
    });
}
