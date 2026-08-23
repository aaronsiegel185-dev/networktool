//! Application shell: tab bar, shared interface inventory, settings and status bar.

use eframe::egui;

use crate::model::IfaceReport;
use crate::runner::{args, Job, Settings};
use crate::ui::widgets;
use crate::ui::{
    capture::CaptureTab, discover::DiscoverTab, lldp::LldpTab, mirror::MirrorTab,
    overview::OverviewTab, scan::ScanTab, wifi::View as WifiView, wifi::WifiTab, Action, Tab,
};

/// What the window should show when it opens.
#[derive(Debug, Clone, Default)]
pub struct Startup {
    pub tab: Tab,
    pub wifi_view: Option<WifiView>,
    /// Run the opening tab's primary action straight away.
    pub autorun: bool,
    /// Save a PNG after this many seconds and exit (documentation / CI aid).
    pub screenshot: Option<(String, f32)>,
}

pub struct App {
    pub settings: Settings,
    tab: Tab,
    inventory: Option<IfaceReport>,
    inventory_job: Option<Job>,
    inventory_error: Option<String>,
    show_settings: bool,
    status: String,
    overview: OverviewTab,
    discover: DiscoverTab,
    scan: ScanTab,
    lldp: LldpTab,
    capture: CaptureTab,
    mirror: MirrorTab,
    wifi: WifiTab,
    base_command: String,
    /// Dev/documentation aid: capture the window to a PNG after a few frames.
    pub screenshot: Option<ScreenshotJob>,
}

pub struct ScreenshotJob {
    pub path: String,
    pub capture_at: std::time::Instant,
    pub requested: bool,
}

impl App {
    pub fn new(settings: Settings, startup: Startup) -> Self {
        let base_command = settings.base.join(" ");
        let mut wifi = WifiTab::default();
        if let Some(view) = startup.wifi_view {
            wifi.set_view(view);
        }
        let mut app = Self {
            settings,
            tab: startup.tab,
            inventory: None,
            inventory_job: None,
            inventory_error: None,
            show_settings: false,
            status: "ready".to_string(),
            overview: OverviewTab::default(),
            discover: DiscoverTab::default(),
            scan: ScanTab::default(),
            lldp: LldpTab::default(),
            capture: CaptureTab::default(),
            mirror: MirrorTab::default(),
            wifi,
            base_command,
            screenshot: startup.screenshot.map(|(path, delay)| ScreenshotJob {
                path,
                capture_at: std::time::Instant::now()
                    + std::time::Duration::from_secs_f32(delay),
                requested: false,
            }),
        };
        app.refresh_inventory();
        if startup.autorun {
            app.autorun();
        }
        app
    }

    /// Kick off the current tab's primary action - used by `--autorun` so the window
    /// opens with results already on screen.
    pub fn autorun(&mut self) {
        let settings = self.settings.clone();
        match self.tab {
            Tab::Overview => self.overview.autorun(&settings),
            Tab::Discover => self.discover.autorun(&settings),
            Tab::Scan => self.scan.autorun(&settings),
            Tab::Lldp => self.lldp.autorun(&settings),
            Tab::Capture => self.capture.autorun(&settings),
            Tab::Mirror => self.mirror.autorun(&settings),
            Tab::Wifi => self.wifi.autorun(&settings),
        }
    }

    pub fn refresh_inventory(&mut self) {
        self.inventory_job = Some(Job::spawn(
            &self.settings,
            "iface",
            args(&["iface", "-a", "--json"]),
        ));
    }

    fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(job) = self.inventory_job.as_mut() {
            if job.poll() && !job.running() {
                match job.parse_json::<IfaceReport>() {
                    Some(Ok(report)) => {
                        self.status = format!("{} interfaces", report.interfaces.len());
                        self.inventory = Some(report);
                        self.inventory_error = None;
                    }
                    Some(Err(err)) => {
                        self.inventory_error = Some(err);
                        self.status = "could not read interfaces".into();
                    }
                    None => {}
                }
                changed = true;
            }
        }
        changed |= self.overview.tick();
        changed |= self.discover.tick();
        changed |= self.scan.tick();
        changed |= self.lldp.tick();
        changed |= self.capture.tick();
        changed |= self.mirror.tick();
        changed |= self.wifi.tick();
        changed
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::None => {}
            Action::RefreshInterfaces => self.refresh_inventory(),
            Action::ScanTarget(target) => {
                self.scan.set_target(target);
                self.tab = Tab::Scan;
            }
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("tabs").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("nettool").strong().size(17.0));
                ui.add_space(10.0);
                for tab in Tab::ALL {
                    if ui
                        .selectable_label(self.tab == tab, tab.title())
                        .clicked()
                    {
                        self.tab = tab;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Settings").clicked() {
                        self.show_settings = !self.show_settings;
                    }
                    if self.settings.use_sudo {
                        ui.colored_label(widgets::WARN, "sudo");
                    }
                });
            });
            ui.add_space(4.0);
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(&self.status)
                        .size(11.0)
                        .color(widgets::MUTED),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(&self.base_command)
                            .monospace()
                            .size(11.0)
                            .color(widgets::MUTED),
                    );
                    if let Some(err) = &self.inventory_error {
                        ui.colored_label(widgets::CRIT, err);
                    }
                });
            });
            ui.add_space(2.0);
        });
    }

    fn settings_window(&mut self, ui: &mut egui::Ui) {
        if !self.show_settings {
            return;
        }
        let mut open = self.show_settings;
        egui::Window::new("Settings")
            .open(&mut open)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                ui.label("How the GUI invokes nettool:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.base_command)
                        .desired_width(320.0)
                        .hint_text("nettool  |  python3 -m nettool"),
                );
                ui.horizontal(|ui| {
                    if ui.button("Apply").clicked() {
                        self.settings.base = self
                            .base_command
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect();
                        if self.settings.base.is_empty() {
                            self.settings.base = vec!["nettool".to_string()];
                            self.base_command = "nettool".to_string();
                        }
                        self.refresh_inventory();
                    }
                    if ui.button("Auto-detect").clicked() {
                        let use_sudo = self.settings.use_sudo;
                        self.settings = Settings::detect();
                        self.settings.use_sudo = use_sudo;
                        self.base_command = self.settings.base.join(" ");
                        self.refresh_inventory();
                    }
                });
                ui.add_space(6.0);
                ui.checkbox(
                    &mut self.settings.use_sudo,
                    "run via sudo -n (needed for capture, LLDP, ARP sweep)",
                );
                ui.label(
                    egui::RichText::new(
                        "sudo -n never prompts: configure NOPASSWD, or start the GUI with sudo.",
                    )
                    .size(11.0)
                    .color(widgets::MUTED),
                );
                if let Some(dir) = &self.settings.working_dir {
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(format!("working directory: {dir}"))
                            .size(11.0)
                            .color(widgets::MUTED),
                    );
                }
            });
        self.show_settings = open;
    }

    fn handle_screenshot(&mut self, ui: &mut egui::Ui) {
        let Some(job) = self.screenshot.as_mut() else {
            return;
        };
        let ctx = ui.ctx().clone();
        if std::time::Instant::now() < job.capture_at {
            ctx.request_repaint();
            return;
        }
        if !job.requested {
            job.requested = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            ctx.request_repaint();
            return;
        }
        let image = ctx.input(|input| {
            input.events.iter().find_map(|event| match event {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = image {
            let path = job.path.clone();
            let width = image.width() as u32;
            let height = image.height() as u32;
            let pixels: Vec<u8> = image.as_raw().to_vec();
            match image::RgbaImage::from_raw(width, height, pixels) {
                Some(buffer) => match buffer.save(&path) {
                    Ok(()) => eprintln!("screenshot written to {path}"),
                    Err(err) => eprintln!("could not write {path}: {err}"),
                },
                None => eprintln!("unexpected screenshot buffer size"),
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint();
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.tick() {
            ui.ctx().request_repaint();
        }
        // Jobs stream output between frames; keep a slow heartbeat so timers tick.
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(200));

        self.top_bar(ui);
        self.status_bar(ui);
        self.settings_window(ui);

        let settings = self.settings.clone();
        let inventory = &self.inventory;
        let action = egui::CentralPanel::default()
            .show(ui, |ui| {
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.tab {
                        Tab::Overview => self.overview.ui(ui, &settings, inventory),
                        Tab::Discover => self.discover.ui(ui, &settings, inventory),
                        Tab::Scan => self.scan.ui(ui, &settings, inventory),
                        Tab::Lldp => self.lldp.ui(ui, &settings, inventory),
                        Tab::Capture => self.capture.ui(ui, &settings, inventory),
                        Tab::Mirror => self.mirror.ui(ui, &settings, inventory),
                        Tab::Wifi => self.wifi.ui(ui, &settings, inventory),
                    })
                    .inner
            })
            .inner;
        self.apply(action);
        self.handle_screenshot(ui);
    }
}
