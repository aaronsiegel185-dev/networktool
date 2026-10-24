//! Tab views. Each tab owns its inputs, its running job and its parsed result.

pub mod analyze;
pub mod assist;
pub mod capture;
pub mod discover;
pub mod mirror;
pub mod netmap;
pub mod lldp;
pub mod overview;
pub mod scan;
pub mod theme;
pub mod widgets;
pub mod wifi;

use crate::model::Iface;
use crate::runner::{running_as_root, Job};
use eframe::egui;

/// The two halves of Toolbox. They are separate sections rather than tabs in
/// one row because they are separate tools: Assist is a workspace you sit in,
/// Network Tool is a set of instruments you reach for. Putting the AI in the
/// same row as "Port scan" made it look like one more probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Section {
    #[default]
    Assist,
    Network,
}

impl Section {
    pub const ALL: [Section; 2] = [Section::Assist, Section::Network];

    pub fn title(self) -> &'static str {
        match self {
            Section::Assist => "Assist",
            Section::Network => "Network Tool",
        }
    }

    /// What this section is for, said once where someone switching can see it.
    pub fn blurb(self) -> &'static str {
        match self {
            Section::Assist => "notebooks, sources and a model on this machine",
            Section::Network => "measure the network",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Discover,
    Scan,
    Lldp,
    Capture,
    Mirror,
    Analyze,
    Wifi,
}

impl Tab {
    pub const ALL: [Tab; 8] = [
        Tab::Overview,
        Tab::Discover,
        Tab::Scan,
        Tab::Lldp,
        Tab::Capture,
        Tab::Mirror,
        Tab::Analyze,
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
            Tab::Analyze => "Analyse",
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
    /// Open a capture file in the analysis tab.
    AnalyzeFile(String),
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

/// What macOS blanking Wi-Fi names means, and how to stop it.
///
/// Only shown once a result has actually come back blanked - guessing at it up
/// front tells people their permissions are wrong when they are not.
pub fn hidden_names_hint(ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new(
            "macOS hid these network names: it blanks them for anything without Location \
             Services. Granting it to nettool fills them in here, in the app - the \
             command line cannot show them however it is run, because it reads names \
             through system_profiler and wdutil, which macOS holds responsible for \
             themselves rather than for nettool. Signal, channel and the interference \
             analysis are unaffected either way.",
        )
        .color(widgets::MUTED)
        .size(11.0),
    );
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

/// Poll a job and, when it finishes, decode its JSON into `slot`.
///
/// Shared because every tab wants the same three lines, and a tab that
/// reimplements them is a tab that forgets to clear the error.
pub fn poll_into<T: serde::de::DeserializeOwned>(
    job: &mut Option<Job>,
    slot: &mut Option<T>,
    error: &mut Option<String>,
) -> bool {
    let Some(job) = job.as_mut() else {
        return false;
    };
    let changed = job.poll();
    if changed && !job.running() {
        match job.parse_json::<T>() {
            Some(Ok(value)) => {
                *slot = Some(value);
                *error = None;
            }
            Some(Err(err)) => *error = Some(err),
            None => {}
        }
    }
    changed
}
