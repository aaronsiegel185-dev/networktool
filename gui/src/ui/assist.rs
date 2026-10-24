//! Assist - a ticket, the machine's own measurements, and a local model.
//!
//! Like every other tab, this runs the CLI and renders what comes back; the
//! model is never spoken to from here. That keeps one implementation of the
//! privacy guarantee rather than two, and means the terminal and the app
//! cannot disagree about where data went.

use eframe::egui;
use std::path::{Path, PathBuf};

use super::widgets;
use super::{job_footer, poll_into, Action};
use crate::model::{AssistDoctor, AssistTicket, TicketList};
use crate::runner::{args, Job, JobMode, Settings};

#[derive(Default)]
pub struct AssistTab {
    title: String,
    body: String,
    question: String,
    /// Dropped files not yet attached - shown as thumbnails so the wrong one is
    /// obvious before it goes anywhere.
    pending: Vec<PathBuf>,

    ticket: Option<AssistTicket>,
    ticket_id: Option<String>,
    /// Loading a ticket is its own job: it deserializes a record, where `job`
    /// below carries the model's answer as loose text while it arrives.
    show_job: Option<Job>,
    ticket_error: Option<String>,
    /// Set when a command finished and the record on disk has moved on.
    needs_reload: bool,
    /// Set when the user asks for a new ticket, so landing on the tab opens the
    /// most recent one but pressing New still gets them an empty form.
    composing: bool,

    list_job: Option<Job>,
    list: Option<TicketList>,
    list_error: Option<String>,

    doctor_job: Option<Job>,
    doctor: Option<AssistDoctor>,
    doctor_error: Option<String>,

    job: Option<Job>,
    error: Option<String>,
    /// What the model has said so far on this turn, as it arrives.
    streaming: String,
    lines_seen: usize,
}

impl AssistTab {
    pub fn tick(&mut self) -> bool {
        let mut changed = poll_into(&mut self.list_job, &mut self.list,
                                           &mut self.list_error);
        changed |= poll_into(&mut self.doctor_job, &mut self.doctor,
                                    &mut self.doctor_error);
        changed |= poll_into(&mut self.show_job, &mut self.ticket,
                                    &mut self.ticket_error);
        if let Some(job) = self.job.as_mut() {
            if job.poll() {
                changed = true;
                while self.lines_seen < job.lines.len() {
                    self.streaming.push_str(&job.lines[self.lines_seen]);
                    self.streaming.push('\n');
                    self.lines_seen += 1;
                }
                if !job.running() {
                    self.error = job
                        .result
                        .as_ref()
                        .filter(|result| !result.ok())
                        .map(|result| result.error_text());
                    // Spawning needs Settings, which the UI pass has; ask for
                    // the reload there rather than threading it through here.
                    self.needs_reload = self.error.is_none();
                }
            }
        }
        changed
    }

    fn busy(&self) -> bool {
        self.job.as_ref().map(|job| job.running()).unwrap_or(false)
    }

    // --- actions ---------------------------------------------------------

    fn run(&mut self, settings: &Settings, label: &str, argv: Vec<String>) {
        self.error = None;
        self.streaming.clear();
        self.lines_seen = 0;
        self.job = Some(Job::spawn_mode(settings, label, argv, JobMode::Once));
    }

    fn refresh_list(&mut self, settings: &Settings) {
        self.list_error = None;
        self.list_job = Some(Job::spawn(&settings.assist(), "assist list",
                                        args(&["list", "--json"])));
    }

    fn refresh_doctor(&mut self, settings: &Settings) {
        self.doctor_error = None;
        self.doctor_job = Some(Job::spawn(&settings.assist(), "assist doctor",
                                          args(&["doctor", "--json"])));
    }

    /// Reloading through the CLI keeps the record on disk as the single source
    /// of truth, rather than a copy in the app drifting from it.
    fn reload(&mut self, settings: &Settings) {
        self.needs_reload = false;
        self.streaming.clear();
        self.lines_seen = 0;
        self.refresh_list(settings);
        match self.ticket_id.clone() {
            // A new ticket has no id yet: the refreshed listing is newest-first,
            // so the auto-open below lands on the one just created.
            None => self.composing = false,
            Some(id) => self.load(settings, &id),
        }
    }

    /// Fetch the record for a ticket that is already open.
    fn load(&mut self, settings: &Settings, id: &str) {
        self.ticket_error = None;
        self.show_job = Some(Job::spawn(&settings.assist(), "assist show",
                                        args(&["show", id, "--json"])));
    }

    fn open(&mut self, settings: &Settings, id: &str) {
        self.ticket_id = Some(id.to_string());
        self.ticket = None;
        self.error = None;
        self.composing = false;
        self.streaming.clear();
        self.lines_seen = 0;
        self.load(settings, id);
    }
}

impl AssistTab {
    pub fn ui(&mut self, ui: &mut egui::Ui, settings: &Settings) -> Action {
        self.take_dropped_files(ui.ctx());

        if self.doctor.is_none() && self.doctor_job.is_none() {
            self.refresh_doctor(settings);
        }
        if self.needs_reload {
            self.reload(settings);
        }
        if self.list.is_none() && self.list_job.is_none() {
            self.refresh_list(settings);
        }
        // Arriving on the tab with work already in flight should show that work,
        // not an empty form: the listing is newest-first.
        if self.ticket_id.is_none() && !self.composing {
            if let Some(newest) = self.list.as_ref().and_then(|l| l.tickets.first()) {
                let id = newest.id.clone();
                self.open(settings, &id);
            }
        }

        self.privacy_banner(ui, settings);
        ui.separator();

        egui::Panel::left("assist_tickets")
            .resizable(true)
            .default_size(230.0)
            .show(ui, |ui| self.ticket_list(ui, settings));

        self.workspace(ui, settings);
        Action::None
    }

    /// Where the model runs, and whether anything leaves - said before a ticket
    /// is written rather than buried in a settings pane.
    fn privacy_banner(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal_wrapped(|ui| {
            widgets::heading(ui, "Assist");
            match self.doctor.as_ref() {
                Some(doctor) => {
                    let leaves = doctor.egress.leaves_machine;
                    ui.colored_label(
                        if leaves { widgets::WARN } else { widgets::OK },
                        if leaves {
                            format!("sent to {} on your network", doctor.egress.host)
                        } else {
                            "nothing leaves this machine".to_string()
                        },
                    );
                    ui.label(
                        egui::RichText::new(&doctor.endpoint)
                            .monospace()
                            .size(11.0)
                            .color(widgets::MUTED),
                    );
                    if doctor.server != "reachable" {
                        ui.colored_label(widgets::CRIT, "model server not running");
                        if let Some(detail) = doctor.server_error.as_ref() {
                            ui.label(
                                egui::RichText::new(detail)
                                    .size(11.0)
                                    .color(widgets::MUTED),
                            )
                            .on_hover_text("Start it with: ollama serve");
                        }
                    }
                    for missing in &doctor.missing_models {
                        ui.colored_label(widgets::WARN, format!("pull {missing}"));
                    }
                }
                None => {
                    ui.spinner();
                    ui.label("checking where the model runs...");
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Recheck").clicked() {
                    self.refresh_doctor(settings);
                }
            });
        });
    }

    fn ticket_list(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal(|ui| {
            widgets::heading(ui, "Tickets");
            if ui.button("New").clicked() {
                self.composing = true;
                self.ticket_id = None;
                self.ticket = None;
                self.streaming.clear();
            }
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            let entries = self.list.as_ref().map(|l| l.tickets.clone()).unwrap_or_default();
            if entries.is_empty() {
                ui.weak("No tickets yet. Describe a problem on the right.");
            }
            for entry in entries {
                let selected = self.ticket_id.as_deref() == Some(entry.id.as_str());
                let response = ui.selectable_label(selected, {
                    let mut text = egui::RichText::new(&entry.title).size(12.0);
                    if selected {
                        text = text.strong();
                    }
                    text
                });
                ui.label(
                    egui::RichText::new(format!(
                        "{}  ·  {}  ·  {}",
                        &entry.created.get(..10).unwrap_or(&entry.created),
                        plural(entry.messages, "message"),
                        plural(entry.attachments, "file")
                    ))
                    .size(10.0)
                    .color(widgets::MUTED),
                );
                if response.clicked() {
                    self.open(settings, &entry.id);
                }
                ui.add_space(4.0);
            }
        });
    }

    fn workspace(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            match self.ticket_id.clone() {
                None => self.new_ticket_form(ui, settings),
                Some(id) => self.conversation(ui, settings, &id),
            }
            self.dropped_files(ui);
            if !self.streaming.is_empty() {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(&self.streaming).monospace().size(12.0));
            }
            job_footer(ui, &self.job, &self.error);
        });
    }

    fn new_ticket_form(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        widgets::heading(ui, "What is going wrong?");
        ui.add(
            egui::TextEdit::singleline(&mut self.title)
                .desired_width(f32::INFINITY)
                .hint_text("one line: Wi-Fi drops every afternoon"),
        );
        ui.add_space(4.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.body)
                .desired_width(f32::INFINITY)
                .desired_rows(5)
                .hint_text(
                    "Anything that might matter: when it started, what changed, \
                     what you have already tried.",
                ),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let ready = !self.title.trim().is_empty() && !self.busy();
            if ui
                .add_enabled(ready, egui::Button::new("Start and ask"))
                .on_hover_text(
                    "Gathers what this machine reports - interfaces, DNS, Wi-Fi, \
                     interference - and puts the lot to the local model.",
                )
                .clicked()
            {
                let mut argv = vec![
                    "new".to_string(),
                    self.title.clone(),
                    "-b".to_string(),
                    self.body.clone(),
                    "--ask".to_string(),
                ];
                for path in &self.pending {
                    argv.push("-a".to_string());
                    argv.push(path.to_string_lossy().to_string());
                }
                self.run(&settings.assist(), "assist new", argv);
                self.pending.clear();
            }
            ui.label(
                egui::RichText::new("drop screenshots or a screen recording anywhere here")
                    .size(11.0)
                    .color(widgets::MUTED),
            );
        });
    }

    fn conversation(&mut self, ui: &mut egui::Ui, settings: &Settings, id: &str) {
        if let Some(ticket) = self.ticket.clone() {
            widgets::heading(ui, &ticket.title);
            if !ticket.body.is_empty() {
                ui.label(&ticket.body);
            }
            ui.add_space(6.0);
            for message in &ticket.messages {
                let is_user = message.role == "user";
                ui.label(
                    egui::RichText::new(if is_user { "you" } else { "assist" })
                        .size(11.0)
                        .strong()
                        .color(if is_user { widgets::MUTED } else { widgets::ACCENT }),
                );
                ui.label(egui::RichText::new(&message.text).size(13.0));
                ui.add_space(8.0);
            }
            if !ticket.attachments.is_empty() {
                ui.separator();
                ui.label(
                    egui::RichText::new("attached")
                        .size(11.0)
                        .color(widgets::MUTED),
                );
                ui.horizontal_wrapped(|ui| {
                    for entry in &ticket.attachments {
                        ui.vertical(|ui| {
                            ui.set_width(170.0);
                            // The evidence itself, not just its filename: a
                            // screenshot is the thing worth recognising here.
                            if is_image(Path::new(&entry.path)) {
                                ui.add(
                                    egui::Image::new(format!("file://{}", entry.path))
                                        // Scale from the image's own size, not a
                                        // fraction of the space it happens to sit in.
                                        .fit_to_original_size(1.0)
                                        .max_size(egui::vec2(160.0, 110.0))
                                        .corner_radius(3.0),
                                );
                            } else {
                                ui.label(egui::RichText::new("▶").size(28.0));
                            }
                            ui.label(egui::RichText::new(&entry.stored).size(10.0));
                            let detail = if entry.note.is_empty() {
                                format!("{}  ·  {}", entry.kind, bytes_human(entry.bytes))
                            } else {
                                format!("{}  ·  {}", entry.kind, entry.note)
                            };
                            ui.label(
                                egui::RichText::new(detail).size(10.0).color(widgets::MUTED),
                            );
                        });
                        ui.add_space(10.0);
                    }
                });
            }
        } else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("opening...");
            });
        }

        ui.separator();
        ui.add(
            egui::TextEdit::multiline(&mut self.question)
                .desired_width(f32::INFINITY)
                .desired_rows(2)
                .hint_text("ask a follow-up"),
        );
        ui.horizontal(|ui| {
            let ready = !self.question.trim().is_empty() && !self.busy();
            if ui.add_enabled(ready, egui::Button::new("Ask")).clicked() {
                let question = self.question.clone();
                self.run(&settings.assist(), "assist ask",
                         args(&["ask", id, &question]));
                self.question.clear();
            }
            if !self.pending.is_empty()
                && ui
                    .add_enabled(!self.busy(),
                                 egui::Button::new(format!("Attach {}", self.pending.len())))
                    .clicked()
            {
                let mut argv = vec!["attach".to_string(), id.to_string()];
                argv.extend(self.pending.iter().map(|p| p.to_string_lossy().to_string()));
                self.run(&settings.assist(), "assist attach", argv);
                self.pending.clear();
            }
        });
    }

    // --- dropped files ---------------------------------------------------

    fn take_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect()
        });
        self.pending.extend(dropped);
    }

    fn dropped_files(&mut self, ui: &mut egui::Ui) {
        if self.pending.is_empty() {
            return;
        }
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(format!("{} file(s) to attach", self.pending.len()))
                .size(11.0)
                .color(widgets::MUTED),
        );
        let mut remove = None;
        ui.horizontal_wrapped(|ui| {
            for (index, path) in self.pending.iter().enumerate() {
                ui.vertical(|ui| {
                    // A thumbnail, so the wrong screenshot is obvious before it
                    // is attached rather than after.
                    ui.set_width(150.0);
                    if is_image(path) {
                        ui.add(
                            egui::Image::new(format!("file://{}", path.display()))
                                .fit_to_original_size(1.0)
                                .max_size(egui::vec2(140.0, 100.0))
                                .corner_radius(3.0),
                        );
                    } else {
                        ui.label(egui::RichText::new("▶ video").size(20.0));
                    }
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    ui.label(egui::RichText::new(name).size(10.0).color(widgets::MUTED));
                    if ui.small_button("remove").clicked() {
                        remove = Some(index);
                    }
                });
            }
        });
        if let Some(index) = remove {
            self.pending.remove(index);
        }
    }
}

fn is_image(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .as_deref(),
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp")
    )
}

/// "1 file", "2 files" - the count reads as prose rather than a field dump.
fn plural(count: i64, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// A size a person can judge at a glance, rather than a raw byte count.
fn bytes_human(bytes: i64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
