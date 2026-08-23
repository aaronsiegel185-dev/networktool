//! Tab views. Each tab owns its inputs, its running job and its parsed result.

pub mod capture;
pub mod discover;
pub mod mirror;
pub mod lldp;
pub mod overview;
pub mod scan;
pub mod widgets;
pub mod wifi;

use crate::model::Iface;
use crate::runner::{running_as_root, Job};
use eframe::egui;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Discover,
    Scan,
    Lldp,
    Capture,
    Mirror,
    Wifi,
}

impl Tab {
    pub const ALL: [Tab; 7] = [
        Tab::Overview,
        Tab::Discover,
        Tab::Scan,
        Tab::Lldp,
        Tab::Capture,
        Tab::Mirror,
        Tab::Wifi,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Discover => "Discover",
            Tab::Scan => "Port scan",
            Tab::Lldp => "LLDP / CDP",
            Tab::Capture => "Capture",
            Tab::Mirror => "Mirror / VLAN",
            Tab::Wifi => "Wi-Fi",
        }
    }
}

/// Something a tab wants the application to do after its `ui` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Jump to the port-scan tab preloaded with this target.
    ScanTarget(String),
    /// Refresh the shared interface inventory.
    RefreshInterfaces,
}

/// Dropdown of interface names. `wireless_only` filters to Wi-Fi radios.
pub fn interface_picker(
    ui: &mut egui::Ui,
    id: &str,
    selected: &mut String,
    interfaces: &[Iface],
    wireless_only: bool,
) {
    let names: Vec<&Iface> = interfaces
        .iter()
        .filter(|i| !i.loopback && (!wireless_only || i.wireless))
        .collect();
    let shown = if selected.is_empty() {
        "(auto)".to_string()
    } else {
        selected.clone()
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(shown)
        .width(140.0)
        .show_ui(ui, |ui| {
            ui.selectable_value(selected, String::new(), "(auto)");
            for iface in names {
                let label = if iface.ipv4.is_empty() {
                    iface.name.clone()
                } else {
                    format!("{} - {}", iface.name, iface.cidr())
                };
                ui.selectable_value(selected, iface.name.clone(), label);
            }
        });
}

/// Run/Stop button plus a live elapsed timer. Returns true when Run was clicked.
pub fn run_controls(ui: &mut egui::Ui, job: &Option<Job>, run_label: &str) -> bool {
    let running = job.as_ref().map(|j| j.running()).unwrap_or(false);
    let mut clicked = false;
    ui.horizontal(|ui| {
        if running {
            ui.spinner();
            if let Some(job) = job {
                ui.label(
                    egui::RichText::new(format!("{:.1}s", job.elapsed().as_secs_f32()))
                        .monospace()
                        .color(widgets::MUTED),
                );
            }
        } else {
            clicked = ui.button(run_label).clicked();
        }
    });
    clicked
}

/// Stop button for a running job; returns true when pressed.
pub fn stop_button(ui: &mut egui::Ui, job: &Option<Job>) -> bool {
    let running = job.as_ref().map(|j| j.running()).unwrap_or(false);
    if !running {
        return false;
    }
    ui.add(egui::Button::new(
        egui::RichText::new("Stop").color(widgets::CRIT),
    ))
    .clicked()
}

/// The exact command that produced what is on screen, plus any error text.
pub fn job_footer(ui: &mut egui::Ui, job: &Option<Job>, error: &Option<String>) {
    if let Some(job) = job {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("command:").color(widgets::MUTED).size(11.0));
            ui.label(
                egui::RichText::new(&job.command_line)
                    .monospace()
                    .size(11.0)
                    .color(widgets::MUTED),
            );
        });
    }
    if let Some(error) = error {
        ui.add_space(4.0);
        egui::Frame::new()
            .fill(widgets::CRIT.gamma_multiply(0.12))
            .inner_margin(egui::Margin::same(8))
            .corner_radius(4.0)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(widgets::CRIT, "error:");
                    ui.label(error);
                });
            });
    }
}

/// Hint shown when a feature needs privileges the app may not have.
///
/// macOS has a tidier answer than sudo - the BPF access helper - so name that first.
pub fn root_hint(ui: &mut egui::Ui, what: &str, use_sudo: bool) {
    if use_sudo || running_as_root() {
        return;
    }
    let advice = if cfg!(target_os = "macos") {
        format!(
            "{what} needs access to /dev/bpf* - run `sudo macos/install-bpf-access.sh` \
             once, or enable \"run via sudo\" in Settings."
        )
    } else {
        format!(
            "{what} needs root - enable \"run via sudo\" in Settings, or start the GUI \
             with sudo."
        )
    };
    ui.label(egui::RichText::new(advice).color(widgets::WARN).size(11.0));
}
