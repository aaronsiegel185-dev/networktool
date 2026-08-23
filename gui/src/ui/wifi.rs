//! Wi-Fi: scan, link quality, airtime survey, live signal monitor and the
//! interference analysis with a recommended channel.

use eframe::egui;
use std::time::{Duration, Instant};

use super::widgets::{self, header_row, kv, BarChartItem};
use super::{
    hidden_names_hint, interface_picker, job_footer, root_hint, run_controls, stop_button, Action,
};
use super::netmap;
use crate::maclocation;
use crate::macwifi;
use crate::model::{
    Bss, DiscoverReport, IfaceReport, SurveyEntry, WifiAnalyzeReport, WifiLink, WifiScanReport,
    WirelessSurvey,
};
use crate::runner::{args, Job, JobMode, Settings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Map,
    Scan,
    Link,
    Analyze,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortBy {
    Signal,
    Channel,
    Ssid,
}

pub struct WifiTab {
    view: View,
    interface: String,
    cached: bool,
    sort: SortBy,

    scan_job: Option<Job>,
    scan_report: Option<WifiScanReport>,
    scan_error: Option<String>,

    link_job: Option<Job>,
    link_report: Option<WifiLink>,
    link_error: Option<String>,

    analyze_job: Option<Job>,
    analyze_report: Option<WifiAnalyzeReport>,
    analyze_error: Option<String>,

    monitor_job: Option<Job>,
    monitor_error: Option<String>,
    monitor_interval: f32,
    history: Vec<f64>,
    seen_bssids: Vec<String>,
    last_sample: Option<WifiLink>,
    monitor_lines_seen: usize,

    hosts_job: Option<Job>,
    hosts_report: Option<DiscoverReport>,
    hosts_error: Option<String>,
    survey_path: String,
    survey_job: Option<Job>,
    survey_report: Option<WirelessSurvey>,
    survey_error: Option<String>,

    /// Set once CoreWLAN has actually given a blanked network its name back.
    names_recovered: bool,
    permission_status: Option<i32>,
    permission_deadline: Option<Instant>,
    permission_error: Option<String>,
}

impl Default for WifiTab {
    fn default() -> Self {
        Self {
            view: View::Analyze,
            interface: String::new(),
            cached: false,
            sort: SortBy::Signal,
            scan_job: None,
            scan_report: None,
            scan_error: None,
            link_job: None,
            link_report: None,
            link_error: None,
            analyze_job: None,
            analyze_report: None,
            analyze_error: None,
            monitor_job: None,
            monitor_error: None,
            monitor_interval: 1.0,
            history: Vec::new(),
            seen_bssids: Vec::new(),
            last_sample: None,
            monitor_lines_seen: 0,
            hosts_job: None,
            hosts_report: None,
            hosts_error: None,
            names_recovered: false,
            permission_status: None,
            permission_deadline: None,
            permission_error: None,
            survey_path: String::new(),
            survey_job: None,
            survey_report: None,
            survey_error: None,
        }
    }
}

impl WifiTab {
    pub fn set_view(&mut self, view: View) {
        self.view = view;
    }

    fn base_args(&self, subcommand: &str) -> Vec<String> {
        let mut argv = args(&["wifi", subcommand, "--json"]);
        if !self.interface.is_empty() {
            argv.push("-i".into());
            argv.push(self.interface.clone());
        }
        argv
    }

    /// Start whichever job the visible sub-view shows (used by `--autorun`).
    pub fn autorun(&mut self, settings: &Settings) {
        match self.view {
            View::Map => self.refresh_map(settings),
            View::Scan => self.start_scan(settings),
            View::Link => self.start_link(settings),
            View::Analyze => self.start_analyze(settings),
            View::Monitor => self.start_monitor(settings),
        }
    }

    fn start_scan(&mut self, settings: &Settings) {
        let mut argv = self.base_args("scan");
        if self.cached {
            argv.push("--cached".into());
        }
        self.scan_error = None;
        self.scan_job = Some(Job::spawn(settings, "wifi scan", argv));
    }

    fn start_link(&mut self, settings: &Settings) {
        self.link_error = None;
        self.link_job = Some(Job::spawn(settings, "wifi link", self.base_args("link")));
    }

    fn start_analyze(&mut self, settings: &Settings) {
        let mut argv = self.base_args("analyze");
        if self.cached {
            argv.push("--cached".into());
        }
        self.analyze_error = None;
        self.analyze_job = Some(Job::spawn(settings, "wifi analyze", argv));
    }

    /// The map wants everything at once: our link, the neighbours, and the LAN.
    fn refresh_map(&mut self, settings: &Settings) {
        self.start_link(settings);
        self.start_scan(settings);
        self.hosts_error = None;
        self.hosts_job = Some(Job::spawn(
            settings,
            "discover",
            args(&["discover", "--json", "-t", "3"]),
        ));
    }

    fn load_survey(&mut self, settings: &Settings) {
        if self.survey_path.trim().is_empty() {
            self.survey_error = Some("enter the path of a monitor-mode capture".into());
            return;
        }
        let argv = vec![
            "pcap".to_string(),
            self.survey_path.trim().to_string(),
            "--json".to_string(),
        ];
        self.survey_error = None;
        self.survey_report = None;
        self.survey_job = Some(Job::spawn(settings, "wireless survey", argv));
    }

    fn start_monitor(&mut self, settings: &Settings) {
        self.history.clear();
        self.seen_bssids.clear();
        self.last_sample = None;
        self.monitor_lines_seen = 0;
        self.monitor_error = None;
        self.monitor_job = Some(Job::spawn_mode(
            settings,
            "wifi monitor",
            self.base_args("link"),
            JobMode::Repeat(Duration::from_secs_f32(self.monitor_interval.max(0.5))),
        ));
    }

    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        changed |= poll_into(&mut self.scan_job, &mut self.scan_report, &mut self.scan_error);
        changed |= poll_into(&mut self.link_job, &mut self.link_report, &mut self.link_error);
        changed |= poll_into(
            &mut self.analyze_job,
            &mut self.analyze_report,
            &mut self.analyze_error,
        );

        changed |= poll_into(&mut self.hosts_job, &mut self.hosts_report,
                             &mut self.hosts_error);
        changed |= poll_into(&mut self.survey_job, &mut self.survey_report,
                             &mut self.survey_error);
        changed |= self.poll_permission();
        if changed {
            self.name_the_hidden();
        }

        if let Some(job) = self.monitor_job.as_mut() {
            let updated = job.poll();
            if updated {
                changed = true;
                while self.monitor_lines_seen < job.lines.len() {
                    let line = &job.lines[self.monitor_lines_seen];
                    self.monitor_lines_seen += 1;
                    match serde_json::from_str::<WifiLink>(line) {
                        Ok(sample) => {
                            if let Some(signal) = sample.signal_dbm {
                                self.history.push(signal);
                                if self.history.len() > 3600 {
                                    self.history.remove(0);
                                }
                            }
                            if !sample.bssid.is_empty()
                                && !self.seen_bssids.contains(&sample.bssid)
                            {
                                self.seen_bssids.push(sample.bssid.clone());
                            }
                            self.last_sample = Some(sample);
                        }
                        Err(_) => {
                            if self.monitor_error.is_none() {
                                if let Some(result) = &job.result {
                                    self.monitor_error = Some(result.error_text());
                                }
                            }
                        }
                    }
                }
                if !job.running() && self.history.is_empty() && self.monitor_error.is_none() {
                    if let Some(result) = &job.result {
                        if !result.ok() {
                            self.monitor_error = Some(result.error_text());
                        }
                    }
                }
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
        let has_radio = interfaces.iter().any(|i| i.wireless);

        ui.horizontal(|ui| {
            for (view, label) in [
                (View::Map, "Map"),
                (View::Analyze, "Analyze"),
                (View::Scan, "Networks"),
                (View::Link, "My link"),
                (View::Monitor, "Monitor"),
            ] {
                if ui.selectable_label(self.view == view, label).clicked() {
                    self.view = view;
                }
            }
            ui.separator();
            ui.label("radio");
            interface_picker(ui, "wifi_iface", &mut self.interface, interfaces, true);
            ui.checkbox(&mut self.cached, "use cached scan");
        });
        if !has_radio && !interfaces.is_empty() {
            ui.colored_label(
                widgets::WARN,
                "No wireless interface detected on this machine.",
            );
        }
        // Only monitor mode opens /dev/bpf*. The other views read the OS's own
        // Wi-Fi state, which needs no privileges on macOS at all - claiming
        // otherwise sent people chasing a permission problem they did not have.
        if self.view == View::Monitor {
            root_hint(ui, "Monitor-mode capture", settings.use_sudo);
        } else if !cfg!(target_os = "macos") {
            root_hint(ui, "A fresh Wi-Fi scan", settings.use_sudo);
        }
        if self.names_hidden() {
            hidden_names_hint(ui);
            self.permission_row(ui);
        }
        ui.add_space(6.0);

        match self.view {
            View::Map => self.map_view(ui, settings, inventory),
            View::Scan => self.scan_view(ui, settings),
            View::Link => self.link_view(ui, settings),
            View::Analyze => self.analyze_view(ui, settings),
            View::Monitor => self.monitor_view(ui, settings),
        }
        Action::None
    }

    fn map_view(
        &mut self,
        ui: &mut egui::Ui,
        settings: &Settings,
        inventory: &Option<IfaceReport>,
    ) {
        let mut refresh = false;
        ui.horizontal_wrapped(|ui| {
            widgets::heading(ui, "Your network");
            let running = self.link_job.as_ref().map(|j| j.running()).unwrap_or(false)
                || self.scan_job.as_ref().map(|j| j.running()).unwrap_or(false)
                || self.hosts_job.as_ref().map(|j| j.running()).unwrap_or(false);
            if running {
                ui.spinner();
                ui.label(
                    egui::RichText::new("looking around...")
                        .size(11.0)
                        .color(widgets::MUTED),
                );
            } else if ui.button("Refresh").clicked() {
                refresh = true;
            }
            ui.separator();
            ui.label("clients from a monitor capture");
            ui.add(
                egui::TextEdit::singleline(&mut self.survey_path)
                    .desired_width(200.0)
                    .hint_text("optional air.pcap"),
            );
            if ui.button("Load").clicked() {
                self.load_survey(settings);
            }
        });
        if refresh {
            self.refresh_map(settings);
        }

        let link = self.link_report.clone().unwrap_or_default();
        ui.add_space(4.0);
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                widgets::signal_gauge(ui, link.signal_dbm, link.snr_db, 190.0);
                if let Some(signal) = link.signal_dbm {
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(widgets::signal_advice(signal))
                            .size(11.0)
                            .color(widgets::signal_color(signal)),
                    );
                }
            });
            ui.add_space(10.0);
            ui.vertical(|ui| {
                if link.connected || link.signal_dbm.is_some() {
                    ui.label(
                        egui::RichText::new(link.display_ssid()).strong().size(18.0),
                    );
                    egui::Grid::new("map_link")
                        .num_columns(2)
                        .spacing([14.0, 2.0])
                        .show(ui, |ui| {
                            kv(ui, "access point", &link.bssid);
                            kv(
                                ui,
                                "band / channel",
                                format!(
                                    "{} GHz / {}",
                                    link.band,
                                    widgets::fmt_opt(link.channel)
                                ),
                            );
                            kv(ui, "tx rate", &link.tx_bitrate);
                            if let Some(station) = &link.station {
                                kv(
                                    ui,
                                    "tx retries",
                                    format!("{:.1}%", station.retry_pct.unwrap_or(0.0)),
                                );
                            }
                        });
                } else {
                    ui.label(
                        egui::RichText::new("Not associated with a network")
                            .color(widgets::WARN),
                    );
                }
                if let Some(hosts) = &self.hosts_report {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "{} device(s) found on the LAN",
                            hosts.hosts.len()
                        ))
                        .size(12.0),
                    );
                }
                if let Some(survey) = &self.survey_report {
                    ui.label(
                        egui::RichText::new(format!(
                            "{} AP(s) and {} station(s) from the capture",
                            survey.access_points.len(),
                            survey.clients.len()
                        ))
                        .size(12.0),
                    );
                }
            });
        });

        ui.add_space(8.0);
        let map = netmap::build(&netmap::MapInputs {
            link: self.link_report.as_ref(),
            scan: self.scan_report.as_ref(),
            hosts: self.hosts_report.as_ref(),
            inventory: inventory.as_ref(),
            survey: self.survey_report.as_ref(),
            max_other_aps: 5,
            max_hosts: 8,
        });
        let hovered = netmap::draw(ui, &map, 380.0);
        if let Some(id) = hovered {
            if let Some(node) = map.node(&id) {
                ui.label(
                    egui::RichText::new(format!("{} - {}", node.label, node.detail))
                        .size(11.0)
                        .color(widgets::MUTED),
                );
            }
        } else {
            ui.label(
                egui::RichText::new(
                    "M this Mac   A access point   G gateway   c wireless client   \
                     h device on the LAN   -- dashed: exact attachment unknown",
                )
                .size(11.0)
                .color(widgets::MUTED),
            );
        }
        job_footer(ui, &self.hosts_job, &self.hosts_error);
        job_footer(ui, &self.survey_job, &self.survey_error);
    }

    fn scan_view(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal(|ui| {
            widgets::heading(ui, "Networks in range");
            if run_controls(ui, &self.scan_job, "Scan") {
                self.start_scan(settings);
            }
            ui.separator();
            ui.label("sort by");
            for (sort, label) in [
                (SortBy::Signal, "signal"),
                (SortBy::Channel, "channel"),
                (SortBy::Ssid, "name"),
            ] {
                if ui.selectable_label(self.sort == sort, label).clicked() {
                    self.sort = sort;
                }
            }
        });

        if let Some(report) = &self.scan_report {
            let mut networks: Vec<&Bss> = report.networks.iter().collect();
            match self.sort {
                SortBy::Signal => networks.sort_by(|a, b| {
                    b.signal_dbm
                        .unwrap_or(-999.0)
                        .partial_cmp(&a.signal_dbm.unwrap_or(-999.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                }),
                SortBy::Channel => {
                    networks.sort_by_key(|n| (n.band.clone(), n.channel.unwrap_or(0)))
                }
                SortBy::Ssid => networks.sort_by_key(|n| n.ssid.to_lowercase()),
            }
            ui.label(
                egui::RichText::new(format!(
                    "{} BSS via {}",
                    report.networks.len(),
                    report.source
                ))
                .size(11.0)
                .color(widgets::MUTED),
            );
            ui.add_space(4.0);
            egui::Grid::new("wifi_networks")
                .num_columns(9)
                .spacing([12.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    header_row(
                        ui,
                        &[
                            "ssid", "signal", "band", "ch", "width", "util", "sta", "std",
                            "security",
                        ],
                    );
                    for net in networks {
                        let mut name = egui::RichText::new(net.display_ssid());
                        if net.associated {
                            name = name.color(widgets::ACCENT).strong();
                        }
                        ui.label(name).on_hover_text(&net.bssid);
                        widgets::signal_bar(ui, net.signal_dbm, 90.0);
                        ui.monospace(&net.band);
                        ui.monospace(widgets::fmt_opt(net.channel));
                        ui.monospace(match net.width_mhz {
                            Some(width) => format!("{width}"),
                            None => "-".into(),
                        });
                        ui.monospace(match net.utilization_pct {
                            Some(util) => format!("{util:.0}%"),
                            None => "-".into(),
                        });
                        ui.monospace(widgets::fmt_opt(net.stations));
                        ui.label(
                            egui::RichText::new(net.standards.join(","))
                                .size(11.0)
                                .color(widgets::MUTED),
                        );
                        let security = net.security.join(", ");
                        let open = security.contains("open");
                        ui.label(
                            egui::RichText::new(security)
                                .size(11.0)
                                .color(if open { widgets::WARN } else { widgets::MUTED }),
                        );
                        ui.end_row();
                    }
                });
        } else if self.scan_job.is_none() {
            ui.weak("Scan to list every access point in range with its signal, channel and load.");
        }
        ui.add_space(6.0);
        job_footer(ui, &self.scan_job, &self.scan_error);
    }

    fn link_view(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal(|ui| {
            widgets::heading(ui, "Current association");
            if run_controls(ui, &self.link_job, "Refresh") {
                self.start_link(settings);
            }
        });
        if let Some(link) = &self.link_report {
            if !link.connected && link.signal_dbm.is_none() {
                ui.colored_label(widgets::WARN, "Not associated with any network.");
            } else {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(link.display_ssid()).strong().size(20.0),
                        );
                        access_point_row(ui, link);
                    });
                    ui.add_space(20.0);
                    ui.vertical(|ui| {
                        if let Some(signal) = link.signal_dbm {
                            ui.label(
                                egui::RichText::new(format!("{signal:.0} dBm"))
                                    .size(24.0)
                                    .strong()
                                    .color(widgets::signal_color(signal)),
                            );
                            ui.label(
                                egui::RichText::new(&link.rating)
                                    .color(widgets::signal_color(signal)),
                            );
                            widgets::signal_bar(ui, Some(signal), 180.0);
                        }
                    });
                });
                ui.add_space(8.0);
                egui::Grid::new("link_detail")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        kv(
                            ui,
                            "band / channel",
                            format!("{} GHz / {}", link.band, widgets::fmt_opt(link.channel)),
                        );
                        kv(ui, "frequency", format!("{} MHz", widgets::fmt_opt(link.freq)));
                        kv(ui, "noise floor", widgets::fmt_opt_f(link.noise_dbm, 0));
                        let snr = link.snr_db;
                        ui.label(egui::RichText::new("SNR").color(widgets::MUTED));
                        match snr {
                            Some(snr) => {
                                let color = if snr < 15.0 {
                                    widgets::CRIT
                                } else if snr < 25.0 {
                                    widgets::WARN
                                } else {
                                    widgets::OK
                                };
                                ui.colored_label(color, format!("{snr:.0} dB"));
                            }
                            None => {
                                ui.monospace("-");
                            }
                        }
                        ui.end_row();
                        kv(ui, "tx bitrate", &link.tx_bitrate);
                        kv(ui, "rx bitrate", &link.rx_bitrate);
                        if let Some(station) = &link.station {
                            let retry = station.retry_pct.unwrap_or(0.0);
                            ui.label(egui::RichText::new("tx retries").color(widgets::MUTED));
                            ui.colored_label(
                                if retry > 15.0 { widgets::WARN } else { widgets::MUTED },
                                format!(
                                    "{} ({retry:.1}%)",
                                    widgets::fmt_opt(station.tx_retries)
                                ),
                            );
                            ui.end_row();
                            kv(
                                ui,
                                "tx failures",
                                format!(
                                    "{} ({:.1}%)",
                                    widgets::fmt_opt(station.tx_failed),
                                    station.fail_pct.unwrap_or(0.0)
                                ),
                            );
                            if let Some(connected) = station.connected_time {
                                kv(ui, "connected for", format!("{connected} s"));
                            }
                        }
                        if let Some(stats) = &link.proc_stats {
                            kv(
                                ui,
                                "missed beacons",
                                widgets::fmt_opt(stats.missed_beacons),
                            );
                        }
                    });
            }
        } else if self.link_job.is_none() {
            ui.weak("Shows RSSI, noise floor, SNR, negotiated bitrate and retry counters.");
        }
        ui.add_space(6.0);
        job_footer(ui, &self.link_job, &self.link_error);
    }

    /// Fill in the names macOS blanked, from CoreWLAN inside this process.
    ///
    /// The CLI cannot do this however it is run: it reaches the names through
    /// `system_profiler` and `wdutil`, Apple-signed binaries that macOS holds
    /// responsible for themselves, so nettool.app's Location Services grant
    /// never reaches them. Asked from in here, the same grant applies.
    fn name_the_hidden(&mut self) {
        if !self.names_hidden() {
            return;
        }
        let found = macwifi::scan();
        let mine = macwifi::link();
        if found.is_empty() && mine.is_none() {
            return;
        }

        for report in [self.link_report.as_mut()].into_iter().flatten() {
            name_link(report, mine.as_ref());
        }
        if let Some(report) = self.scan_report.as_mut() {
            self.names_recovered = macwifi::fill_names(&mut report.networks, &found) > 0;
        }
        if let Some(report) = self.analyze_report.as_mut() {
            let filled = macwifi::fill_names(&mut report.networks, &found);
            name_link(&mut report.current, mine.as_ref());
            // The per-channel table carries its own copy of the loudest name.
            let names: Vec<(i64, String)> = report
                .networks
                .iter()
                .filter(|n| !n.ssid.is_empty())
                .filter_map(|n| n.channel.map(|c| (c, n.ssid.clone())))
                .collect();
            for band in report.report.bands.values_mut() {
                for (channel, info) in band.channels.iter_mut() {
                    if info.strongest_ssid.starts_with("(hidden") {
                        if let Some((_, name)) = names.iter().find(|(c, _)| c == channel) {
                            info.strongest_ssid = name.clone();
                        }
                    }
                }
            }
            self.names_recovered |= filled > 0;
        }
    }

    /// True while we are still waiting for an answer to the system prompt.
    fn permission_pending(&self) -> bool {
        self.permission_deadline.is_some()
    }

    /// Watch for the user answering the prompt.
    ///
    /// Taking a callback would mean defining an Objective-C delegate class at
    /// runtime, so instead read the status back each frame until it moves off
    /// "not determined".
    fn poll_permission(&mut self) -> bool {
        let Some(deadline) = self.permission_deadline else {
            return false;
        };
        if let Some(status) = maclocation::status() {
            if status != maclocation::NOT_DETERMINED {
                self.permission_status = Some(status);
                self.permission_deadline = None;
                return true;
            }
        }
        if Instant::now() >= deadline {
            self.permission_deadline = None;
            self.permission_error =
                Some("no answer to the location prompt - it never appeared".into());
            return true;
        }
        false
    }

    /// Ask CoreLocation from inside this process.
    ///
    /// Not by running the CLI: macOS only prompts a process whose own bundle
    /// declares NSLocationWhenInUseUsageDescription, and a spawned `python3` has
    /// no bundle at all - such a request is discarded in silence, which is
    /// exactly the "nothing happened" this replaces.
    fn request_location(&mut self, ctx: &egui::Context) {
        self.permission_error = None;
        if !maclocation::can_prompt() {
            self.permission_error = Some(
                "this copy is not running from nettool.app, so macOS will not show a \
                 location prompt - open /Applications/nettool.app instead"
                    .into(),
            );
            return;
        }
        match maclocation::request() {
            Some(status) if maclocation::granted(status) => {
                self.permission_status = Some(status);
            }
            Some(status) => {
                self.permission_status = Some(status);
                // The answer lands on a later frame, once the prompt is dismissed.
                self.permission_deadline = Some(Instant::now() + Duration::from_secs(60));
                ctx.request_repaint_after(Duration::from_millis(250));
            }
            None => {
                self.permission_error =
                    Some("CoreLocation is unavailable on this system".into());
            }
        }
    }

    /// The one control that can change the permission, and what came of pressing it.
    ///
    /// macOS lists an app under Location Services only once that app has asked,
    /// so until this button has run there is nothing for the user to go and tick.
    /// Only reached when a result actually came back blanked, which only macOS
    /// does - so it needs no platform check of its own.
    fn permission_row(&mut self, ui: &mut egui::Ui) {
        let waiting = self.permission_pending();
        ui.horizontal_wrapped(|ui| {
            if waiting {
                ui.spinner();
                ui.label(
                    egui::RichText::new("waiting for the macOS prompt...")
                        .size(11.0)
                        .color(widgets::MUTED),
                );
            } else if ui
                .button("Ask macOS for permission")
                .on_hover_text(
                    "Shows the system location prompt. macOS asks only once - after that \
                     the answer is changed in System Settings.",
                )
                .clicked()
            {
                let ctx = ui.ctx().clone();
                self.request_location(&ctx);
            }
            if let Some(status) = self.permission_status {
                if maclocation::granted(status) {
                    ui.colored_label(widgets::OK, "granted - scan again to see the names");
                } else if status == maclocation::DENIED {
                    ui.colored_label(
                        widgets::WARN,
                        "denied earlier, so macOS will not ask again - turn nettool on in \
                         System Settings > Privacy & Security > Location Services",
                    );
                } else if !waiting {
                    ui.colored_label(
                        widgets::WARN,
                        format!("still {}", maclocation::status_name(status)),
                    );
                }
            }
            if let Some(err) = self.permission_error.as_ref() {
                ui.colored_label(widgets::CRIT, err);
            }
        });
    }

    /// True once something we have actually fetched came back with a blanked name.
    fn names_hidden(&self) -> bool {
        let link = self.link_report.as_ref().map(|l| l.redacted).unwrap_or(false);
        // Deliberately the rows themselves, not the report's summary flag: once
        // CoreWLAN has named them the hint has nothing left to explain.
        let analyze = self
            .analyze_report
            .as_ref()
            .map(|r| r.current.redacted || r.networks.iter().any(|n| n.redacted))
            .unwrap_or(false);
        let scan = self
            .scan_report
            .as_ref()
            .map(|r| r.networks.iter().any(|n| n.redacted))
            .unwrap_or(false);
        link || analyze || scan
    }

    fn analyze_view(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        let mut run = false;
        ui.horizontal(|ui| {
            widgets::heading(ui, "Interference and channel load");
            run = run_controls(ui, &self.analyze_job, "Analyze");
        });
        if run {
            self.start_analyze(settings);
        }
        let Some(report) = self.analyze_report.as_ref() else {
            if self.analyze_job.is_none() {
                ui.weak(
                    "Scans the band, weighs every neighbour by overlap, signal and airtime, \
                     then recommends a channel and explains what is hurting the link.",
                );
            }
            job_footer(ui, &self.analyze_job, &self.analyze_error);
            return;
        };

        let current = &report.current;
        if current.connected || current.signal_dbm.is_some() {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "{} on channel {}",
                        current.display_ssid(),
                        widgets::fmt_opt(current.channel)
                    ))
                    .strong(),
                );
                if let Some(signal) = current.signal_dbm {
                    ui.colored_label(
                        widgets::signal_color(signal),
                        format!("{signal:.0} dBm ({})", current.rating),
                    );
                }
                if let Some(snr) = current.snr_db {
                    ui.label(format!("SNR {snr:.0} dB"));
                }
            });
            access_point_row(ui, current);
            ui.add_space(4.0);
        }

        for (band, band_report) in &report.report.bands {
            let current_channel = if current.band == *band { current.channel } else { None };
            let best = band_report.best_channel;
            ui.label(
                egui::RichText::new(format!(
                    "{band} GHz - {} BSS",
                    band_report.bss_count
                ))
                .strong(),
            );
            let items: Vec<BarChartItem> = band_report
                .congestion_score
                .iter()
                .map(|(channel, score)| {
                    let is_current = current_channel == Some(*channel);
                    let is_best = best == Some(*channel);
                    BarChartItem {
                        label: channel.to_string(),
                        value: *score,
                        color: if is_current {
                            widgets::WARN
                        } else if is_best {
                            widgets::OK
                        } else {
                            egui::Color32::from_gray(90)
                        },
                        marker: if is_current {
                            Some("you")
                        } else if is_best {
                            Some("best")
                        } else {
                            None
                        },
                    }
                })
                .collect();
            widgets::bar_chart(ui, &items, 120.0);
            if let (Some(best), Some(score)) = (best, band_report.best_score) {
                let note = report
                    .report
                    .recommendations
                    .get(band)
                    .map(|r| r.note.clone())
                    .unwrap_or_default();
                ui.label(
                    egui::RichText::new(format!(
                        "suggested channel {best} (load score {score:.2}) - {note}"
                    ))
                    .color(widgets::OK)
                    .size(12.0),
                );
            }
            egui::CollapsingHeader::new(format!("channels in use on {band} GHz"))
                .id_salt(format!("chan_{band}"))
                .show(ui, |ui| {
                    egui::Grid::new(format!("chan_table_{band}"))
                        .num_columns(6)
                        .spacing([14.0, 3.0])
                        .striped(true)
                        .show(ui, |ui| {
                            header_row(
                                ui,
                                &["ch", "bss", "overlapping", "strongest", "ssid", "util"],
                            );
                            for (channel, info) in &band_report.channels {
                                ui.monospace(channel.to_string());
                                ui.monospace(info.bss.to_string());
                                ui.monospace(info.overlapping.to_string());
                                ui.monospace(widgets::fmt_opt_f(info.strongest_dbm, 0));
                                ui.label(&info.strongest_ssid);
                                ui.monospace(match info.utilization_pct {
                                    Some(util) => format!("{util:.0}%"),
                                    None => "-".into(),
                                });
                                ui.end_row();
                            }
                        });
                });
            ui.add_space(8.0);
        }

        if !report.survey.is_empty() {
            widgets::heading(ui, "Airtime survey");
            survey_table(ui, &report.survey);
            ui.label(
                egui::RichText::new(
                    "\"other\" is airtime the radio saw as busy but could not attribute to our \
                     own traffic: non-Wi-Fi interference or distant co-channel APs.",
                )
                .size(11.0)
                .color(widgets::MUTED),
            );
            ui.add_space(8.0);
        }

        widgets::heading(ui, "Findings");
        for (severity, message) in &report.report.findings {
            ui.horizontal_top(|ui| {
                widgets::severity_badge(ui, severity);
                ui.label(message);
            });
        }
        ui.add_space(6.0);
        job_footer(ui, &self.analyze_job, &self.analyze_error);
    }

    fn monitor_view(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal(|ui| {
            widgets::heading(ui, "Signal over time");
            ui.label("sample every");
            ui.add(
                egui::DragValue::new(&mut self.monitor_interval)
                    .speed(0.1)
                    .range(0.5..=30.0)
                    .suffix(" s"),
            );
            if run_controls(ui, &self.monitor_job, "Start") {
                self.start_monitor(settings);
            }
            if stop_button(ui, &self.monitor_job) {
                if let Some(job) = self.monitor_job.as_mut() {
                    job.cancel();
                }
            }
        });
        ui.label(
            egui::RichText::new(
                "Walk the area while this runs: a large swing on one BSSID is multipath or a \
                 duty-cycled interferer, a changing BSSID is roaming.",
            )
            .size(11.0)
            .color(widgets::MUTED),
        );
        ui.add_space(6.0);
        widgets::signal_history(ui, &self.history, 180.0);
        ui.add_space(6.0);

        let stats = summarize(&self.history);
        egui::Grid::new("monitor_stats")
            .num_columns(2)
            .spacing([16.0, 3.0])
            .show(ui, |ui| {
                kv(ui, "samples", self.history.len().to_string());
                kv(ui, "average", widgets::fmt_opt_f(stats.avg, 1));
                kv(
                    ui,
                    "min / max",
                    format!(
                        "{} / {}",
                        widgets::fmt_opt_f(stats.min, 0),
                        widgets::fmt_opt_f(stats.max, 0)
                    ),
                );
                kv(ui, "swing", widgets::fmt_opt_f(stats.swing, 1));
                if let Some(sample) = &self.last_sample {
                    kv(ui, "network", sample.display_ssid());
                    ui.label(egui::RichText::new("access point").color(widgets::MUTED));
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(sample.display_bssid())
                                .monospace()
                                .size(12.0),
                        );
                        if !sample.bssid_vendor.is_empty() {
                            ui.label(
                                egui::RichText::new(&sample.bssid_vendor)
                                    .size(11.0)
                                    .color(widgets::MUTED),
                            );
                        }
                    });
                    ui.end_row();
                    kv(ui, "tx bitrate", &sample.tx_bitrate);
                }
                if self.seen_bssids.len() > 1 {
                    ui.label(egui::RichText::new("roaming").color(widgets::MUTED));
                    ui.vertical(|ui| {
                        ui.colored_label(
                            widgets::WARN,
                            format!("moved between {} APs", self.seen_bssids.len()),
                        );
                        // Which ones, in the order we met them - a roam to a
                        // weaker AP looks exactly like interference until you
                        // can see the MAC change.
                        for (index, bssid) in self.seen_bssids.iter().enumerate() {
                            let mark = if Some(bssid)
                                == self.last_sample.as_ref().map(|s| &s.bssid)
                            {
                                "now"
                            } else {
                                "   "
                            };
                            ui.label(
                                egui::RichText::new(format!("{mark} {}. {bssid}", index + 1))
                                    .monospace()
                                    .size(11.0)
                                    .color(widgets::MUTED),
                            );
                        }
                    });
                    ui.end_row();
                }
            });
        if let Some(swing) = stats.swing {
            if swing > 15.0 {
                ui.add_space(4.0);
                ui.colored_label(
                    widgets::WARN,
                    format!("signal swings by {swing:.0} dB - unstable link"),
                );
            }
        }
        ui.add_space(6.0);
        job_footer(ui, &self.monitor_job, &self.monitor_error);
    }
}

fn survey_table(ui: &mut egui::Ui, survey: &[SurveyEntry]) {
    egui::Grid::new("survey")
        .num_columns(8)
        .spacing([12.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            header_row(
                ui,
                &["ch", "freq", "band", "in use", "noise", "busy", "our rx/tx", "other"],
            );
            for entry in survey.iter().filter(|e| e.busy_pct.is_some()) {
                ui.monospace(widgets::fmt_opt(entry.channel));
                ui.monospace(widgets::fmt_opt(entry.freq));
                ui.monospace(&entry.band);
                ui.label(if entry.in_use { "yes" } else { "" });
                ui.monospace(widgets::fmt_opt(entry.noise_dbm));
                let busy = entry.busy_pct.unwrap_or(0.0);
                ui.colored_label(
                    if busy > 70.0 {
                        widgets::CRIT
                    } else if busy > 40.0 {
                        widgets::WARN
                    } else {
                        widgets::OK
                    },
                    format!("{busy:.0}%"),
                );
                ui.monospace(format!(
                    "{:.0}% / {:.0}%",
                    entry.rx_pct.unwrap_or(0.0),
                    entry.tx_pct.unwrap_or(0.0)
                ));
                let other = entry.interference_pct.unwrap_or(0.0);
                ui.colored_label(
                    if other > 20.0 { widgets::WARN } else { widgets::MUTED },
                    format!("{other:.0}%"),
                );
                ui.end_row();
            }
        });
}

pub struct HistoryStats {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub avg: Option<f64>,
    pub swing: Option<f64>,
}

/// Min/max/mean/swing of a signal history - the numbers that say whether a link is stable.
pub fn summarize(history: &[f64]) -> HistoryStats {
    if history.is_empty() {
        return HistoryStats {
            min: None,
            max: None,
            avg: None,
            swing: None,
        };
    }
    let min = history.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = history.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    HistoryStats {
        min: Some(min),
        max: Some(max),
        avg: Some(history.iter().sum::<f64>() / history.len() as f64),
        swing: Some(max - min),
    }
}

/// Poll a one-shot job and decode its JSON into `slot` when it finishes.
fn poll_into<T: serde::de::DeserializeOwned>(
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

/// Give our own association its name back, if CoreWLAN could see it.
fn name_link(link: &mut WifiLink, mine: Option<&macwifi::Neighbour>) {
    let Some(mine) = mine else {
        return;
    };
    if link.ssid.is_empty() && !mine.ssid.is_empty() {
        link.ssid = mine.ssid.clone();
        link.redacted = false;
    }
    if link.bssid.is_empty() && !mine.bssid.is_empty() {
        link.bssid = mine.bssid.clone();
    }
}

/// The access point this link is on: its MAC, who made it, and a click to copy.
///
/// On a site with more than one AP the BSSID is the answer to "which box am I
/// actually on" - roaming to a worse one looks identical to interference until
/// you can see it change.
fn access_point_row(ui: &mut egui::Ui, link: &WifiLink) {
    ui.horizontal_wrapped(|ui| {
        ui.label(
            egui::RichText::new("access point")
                .size(11.0)
                .color(widgets::MUTED),
        );
        let mac = link.display_bssid();
        let response = ui.label(egui::RichText::new(mac).monospace().size(12.0));
        if !link.bssid.is_empty() {
            let response = response.on_hover_text("click to copy");
            if response.clicked() {
                ui.ctx().copy_text(link.bssid.clone());
            }
        }
        if !link.bssid_vendor.is_empty() {
            ui.label(
                egui::RichText::new(&link.bssid_vendor)
                    .size(11.0)
                    .color(widgets::MUTED),
            );
        }
    });
}
