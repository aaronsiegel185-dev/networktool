//! Assist - a notebook, the files it is grounded in, and a local model.
//!
//! Three panels: the notebooks on the left, the sources on the right, and the
//! conversation between them. The sources panel is not a detail view - it is
//! the control over what the model is told, so it sits beside the conversation
//! rather than behind a button.
//!
//! Like every Network Tool tab, this runs the CLI and renders what comes back;
//! the model is never spoken to from here. That keeps one implementation of the
//! privacy guarantee rather than two, and means the terminal and the app cannot
//! disagree about where data went.

use eframe::egui;
use std::path::{Path, PathBuf};

use super::widgets;
use super::{job_footer, poll_into, Action};
use crate::model::{AssistDoctor, Notebook, NotebookList, Source};
use crate::runner::{args, Job, JobMode, Settings};

#[derive(Default)]
pub struct AssistTab {
    title: String,
    body: String,
    question: String,
    /// Dropped files not yet added - shown as thumbnails so the wrong one is
    /// obvious before it goes anywhere.
    pending: Vec<PathBuf>,

    notebook: Option<Notebook>,
    notebook_id: Option<String>,
    /// Loading a notebook is its own job: it deserializes a record, where `job`
    /// below carries the model's answer as loose text while it arrives.
    show_job: Option<Job>,
    notebook_error: Option<String>,
    /// Set when a command finished and the record on disk has moved on.
    needs_reload: bool,
    /// Set when the user asks for a new notebook, so landing on the section
    /// opens the most recent one but pressing New still gets an empty form.
    composing: bool,

    list_job: Option<Job>,
    list: Option<NotebookList>,
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
        let mut changed = poll_into(&mut self.list_job, &mut self.list, &mut self.list_error);
        changed |= poll_into(&mut self.doctor_job, &mut self.doctor, &mut self.doctor_error);
        changed |= poll_into(
            &mut self.show_job,
            &mut self.notebook,
            &mut self.notebook_error,
        );
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

    /// A line for the status bar, so the Assist section reports on itself
    /// rather than leaving Network Tool's interface count on screen.
    pub fn status(&self) -> String {
        let notebooks = self
            .list
            .as_ref()
            .map(|l| l.notebooks.len() as i64)
            .unwrap_or(0);
        match self.notebook.as_ref() {
            Some(notebook) => {
                let on = notebook.sources.iter().filter(|s| s.enabled).count() as i64;
                format!(
                    "{} · {} of {} in play",
                    plural(notebooks, "notebook"),
                    plural(on, "source"),
                    notebook.sources.len()
                )
            }
            None => plural(notebooks, "notebook"),
        }
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
        self.list_job = Some(Job::spawn(
            &settings.assist(),
            "assist list",
            args(&["list", "--json"]),
        ));
    }

    fn refresh_doctor(&mut self, settings: &Settings) {
        self.doctor_error = None;
        self.doctor_job = Some(Job::spawn(
            &settings.assist(),
            "assist doctor",
            args(&["doctor", "--json"]),
        ));
    }

    /// Reloading through the CLI keeps the record on disk as the single source
    /// of truth, rather than a copy in the app drifting from it.
    fn reload(&mut self, settings: &Settings) {
        self.needs_reload = false;
        self.streaming.clear();
        self.lines_seen = 0;
        self.refresh_list(settings);
        match self.notebook_id.clone() {
            // A new notebook has no id yet: the refreshed listing is
            // newest-first, so the auto-open below lands on the one just made.
            None => self.composing = false,
            Some(id) => self.load(settings, &id),
        }
    }

    fn load(&mut self, settings: &Settings, id: &str) {
        self.notebook_error = None;
        self.show_job = Some(Job::spawn(
            &settings.assist(),
            "assist show",
            args(&["show", id, "--json"]),
        ));
    }

    fn open(&mut self, settings: &Settings, id: &str) {
        self.notebook_id = Some(id.to_string());
        self.notebook = None;
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
        // Arriving with work already in flight should show that work, not an
        // empty form: the listing is newest-first.
        if self.notebook_id.is_none() && !self.composing {
            if let Some(newest) = self.list.as_ref().and_then(|l| l.notebooks.first()) {
                let id = newest.id.clone();
                self.open(settings, &id);
            }
        }

        self.privacy_banner(ui, settings);
        ui.separator();

        egui::Panel::left("assist_notebooks")
            .resizable(true)
            .default_size(240.0)
            .show(ui, |ui| self.notebook_list(ui, settings));

        // Sources sit beside the conversation, not behind it: they are the
        // control over what the model is told.
        if self.notebook_id.is_some() {
            egui::Panel::right("assist_sources")
                .resizable(true)
                .default_size(300.0)
                .show(ui, |ui| self.sources_panel(ui, settings));
        }

        self.workspace(ui, settings);
        Action::None
    }

    /// Where the model runs, and whether anything leaves - said before a
    /// notebook is written rather than buried in a settings pane.
    fn privacy_banner(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal_wrapped(|ui| {
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
                            ui.label(egui::RichText::new(detail).size(11.0).color(widgets::MUTED))
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

    fn notebook_list(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal(|ui| {
            widgets::heading(ui, "Notebooks");
            if ui.button("New").clicked() {
                self.composing = true;
                self.notebook_id = None;
                self.notebook = None;
                self.streaming.clear();
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("assist_notebook_list")
            .show(ui, |ui| {
                let entries = self
                    .list
                    .as_ref()
                    .map(|l| l.notebooks.clone())
                    .unwrap_or_default();
                if entries.is_empty() {
                    ui.weak("No notebooks yet. Describe a problem on the right.");
                }
                for entry in entries {
                    let selected = self.notebook_id.as_deref() == Some(entry.id.as_str());
                    let response = ui.selectable_label(selected, {
                        let mut text = egui::RichText::new(&entry.title).size(12.0);
                        if selected {
                            text = text.strong();
                        }
                        text
                    });
                    // Say how many sources are actually in play, not just how
                    // many exist: "3/7" is the fact that changes the answer.
                    let sources = if entry.sources_on == entry.sources {
                        plural(entry.sources, "source")
                    } else {
                        format!("{}/{} sources", entry.sources_on, entry.sources)
                    };
                    // Month and day only: the year is almost always this one,
                    // and the full date pushed this line onto two.
                    let when = entry.created.get(5..10).unwrap_or("");
                    ui.label(
                        egui::RichText::new(format!(
                            "{}  ·  {}  ·  {}",
                            when,
                            plural(entry.messages, "message"),
                            sources
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

    // --- sources ---------------------------------------------------------

    fn sources_panel(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        ui.horizontal(|ui| {
            widgets::heading(ui, "Sources");
            if !self.pending.is_empty() {
                let label = format!("Add {}", self.pending.len());
                if ui
                    .add_enabled(!self.busy(), egui::Button::new(label))
                    .clicked()
                {
                    self.add_pending(settings);
                }
            }
        });
        ui.label(
            egui::RichText::new(
                "what the model is told. Drop pcaps, logs, configs, screenshots \
                 or a screen recording anywhere here.",
            )
            .size(10.0)
            .color(widgets::MUTED),
        );
        ui.add_space(4.0);

        let sources: Vec<Source> = self
            .notebook
            .as_ref()
            .map(|n| n.sources.clone())
            .unwrap_or_default();
        if sources.is_empty() && self.pending.is_empty() {
            ui.weak("Nothing yet. The model only knows what this machine reports.");
        }

        let mut toggle: Option<(String, bool)> = None;
        let mut remove: Option<String> = None;
        egui::ScrollArea::vertical()
            .id_salt("assist_sources")
            .show(ui, |ui| {
                for source in &sources {
                    // Frames belong to their recording and are switched with
                    // it; listing them all would bury everything else.
                    if source.parent.is_some() {
                        continue;
                    }
                    let mut on = source.enabled;
                    ui.horizontal_top(|ui| {
                        if ui
                            .checkbox(&mut on, "")
                            .on_hover_text("Off keeps the file but stops sending it")
                            .changed()
                        {
                            toggle = Some((source.stored.clone(), on));
                        }
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(kind_label(&source.kind))
                                        .size(9.0)
                                        .color(widgets::ACCENT),
                                );
                                ui.label(egui::RichText::new(&source.stored).size(11.0));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .small_button("x")
                                            .on_hover_text("Delete this source and \
                                                            anything sampled from it")
                                            .clicked()
                                        {
                                            remove = Some(source.stored.clone());
                                        }
                                    },
                                );
                            });
                            let detail = if source.note.is_empty() {
                                bytes_human(source.bytes)
                            } else {
                                format!("{}  ·  {}", source.note, bytes_human(source.bytes))
                            };
                            ui.label(egui::RichText::new(detail).size(10.0).color(widgets::MUTED));
                            if is_image(Path::new(&source.path)) {
                                ui.add(
                                    egui::Image::new(format!("file://{}", source.path))
                                        .fit_to_original_size(1.0)
                                        .max_size(egui::vec2(150.0, 100.0))
                                        .corner_radius(3.0),
                                );
                            }
                            let frames = sources
                                .iter()
                                .filter(|other| {
                                    other.parent.as_deref() == Some(source.stored.as_str())
                                })
                                .count();
                            if frames > 0 {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "+ {} sampled from it",
                                        plural(frames as i64, "frame")
                                    ))
                                    .size(10.0)
                                    .color(widgets::MUTED),
                                );
                            }
                        });
                    });
                    ui.add_space(6.0);
                }
                self.pending_thumbnails(ui);
            });

        if let Some((name, on)) = toggle {
            let flag = if on { "--on" } else { "--off" };
            if let Some(id) = self.notebook_id.clone() {
                self.run(
                    &settings.assist(),
                    "assist sources",
                    args(&["sources", &id, flag, &name]),
                );
            }
        }
        if let Some(name) = remove {
            if let Some(id) = self.notebook_id.clone() {
                self.run(
                    &settings.assist(),
                    "assist sources",
                    args(&["sources", &id, "--remove", &name]),
                );
            }
        }
    }

    fn add_pending(&mut self, settings: &Settings) {
        let Some(id) = self.notebook_id.clone() else {
            return;
        };
        let mut argv = vec!["add".to_string(), id];
        argv.extend(self.pending.iter().map(|p| p.to_string_lossy().to_string()));
        self.run(&settings.assist(), "assist add", argv);
        self.pending.clear();
    }

    /// Files dropped but not yet added, as thumbnails where they are images.
    fn pending_thumbnails(&mut self, ui: &mut egui::Ui) {
        if self.pending.is_empty() {
            return;
        }
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} waiting to be added", self.pending.len()))
                .size(10.0)
                .color(widgets::WARN),
        );
        let mut remove = None;
        for (index, path) in self.pending.iter().enumerate() {
            ui.horizontal_top(|ui| {
                if is_image(path) {
                    ui.add(
                        egui::Image::new(format!("file://{}", path.display()))
                            .fit_to_original_size(1.0)
                            .max_size(egui::vec2(60.0, 45.0))
                            .corner_radius(3.0),
                    );
                }
                ui.vertical(|ui| {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    ui.label(egui::RichText::new(name).size(10.0));
                    if ui.small_button("remove").clicked() {
                        remove = Some(index);
                    }
                });
            });
        }
        if let Some(index) = remove {
            self.pending.remove(index);
        }
    }

    fn take_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect()
        });
        for path in dropped {
            if !self.pending.contains(&path) {
                self.pending.push(path);
            }
        }
    }

    // --- the conversation ------------------------------------------------

    fn workspace(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        egui::ScrollArea::vertical()
            .id_salt("assist_workspace")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                match self.notebook_id.clone() {
                    None => self.new_notebook_form(ui, settings),
                    Some(id) => self.conversation(ui, settings, &id),
                }
                if !self.streaming.is_empty() {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(&self.streaming).size(13.0));
                }
                job_footer(ui, &self.job, &self.error);
            });
    }

    fn new_notebook_form(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        widgets::heading(ui, "What is going wrong?");
        ui.add(
            egui::TextEdit::singleline(&mut self.title)
                .desired_width(f32::INFINITY)
                .hint_text("one line: Wi-Fi drops every afternoon"),
        );
        ui.add(
            egui::TextEdit::multiline(&mut self.body)
                .desired_width(f32::INFINITY)
                .desired_rows(4)
                .hint_text(
                    "Anything that might matter: when it started, what changed, \
                     what you have already tried.",
                ),
        );
        ui.horizontal(|ui| {
            let ready = !self.title.trim().is_empty() && !self.busy();
            if ui
                .add_enabled(ready, egui::Button::new("Start and ask"))
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
                self.title.clear();
                self.body.clear();
            }
            ui.label(
                egui::RichText::new("files you drop are added as sources")
                    .size(11.0)
                    .color(widgets::MUTED),
            );
        });
    }

    fn conversation(&mut self, ui: &mut egui::Ui, settings: &Settings, id: &str) {
        if let Some(notebook) = self.notebook.clone() {
            widgets::heading(ui, &notebook.title);
            if !notebook.body.is_empty() {
                ui.label(&notebook.body);
            }
            ui.add_space(6.0);
            for message in &notebook.messages {
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
                self.run(
                    &settings.assist(),
                    "assist ask",
                    args(&["ask", id, &question]),
                );
                self.question.clear();
            }
            if let Some(notebook) = self.notebook.as_ref() {
                let on = notebook.sources.iter().filter(|s| s.enabled).count();
                ui.label(
                    egui::RichText::new(format!(
                        "answering from {}",
                        plural(on as i64, "source")
                    ))
                    .size(11.0)
                    .color(widgets::MUTED),
                );
            }
        });
    }
}

/// A short tag for the source list. The kinds the CLI emits are already short
/// words; this only shortens the two that are not.
fn kind_label(kind: &str) -> &str {
    match kind {
        "screenshot" => "shot",
        "recording" => "video",
        other => other,
    }
}

fn is_image(path: &Path) -> bool {
    matches!(
        path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .as_deref(),
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp")
    )
}

/// "1 source", "2 sources" - the count reads as prose rather than a field dump.
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
