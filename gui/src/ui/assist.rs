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
use crate::model::{AssistDoctor, Client, ClientList, Notebook, NotebookList, Source};
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

    /// Clients, for grouping the list and for the client editor.
    clients_job: Option<Job>,
    clients: Option<ClientList>,
    clients_error: Option<String>,
    /// Set when a client, rather than a notebook, is what is open.
    client_id: Option<String>,
    client: Option<Client>,
    client_job: Option<Job>,
    client_error: Option<String>,
    /// The client editor's own fields.
    fact_label: String,
    fact_value: String,
    notes_draft: String,
    /// Which client the notes draft belongs to, so switching clients does not
    /// carry one client's half-written notes onto another.
    notes_for: Option<String>,
    new_client_name: String,
    /// Which client a new notebook will be filed under.
    file_under: Option<String>,
    /// A notebook or client named on the command line, opened on the first
    /// frame once Settings are in hand.
    pending_open: Option<(bool, String)>,

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
    /// Open this notebook (or client) on the first frame, rather than the
    /// most recent one.
    pub fn open_at(&mut self, id: &str, is_client: bool) {
        self.pending_open = Some((is_client, id.to_string()));
    }

    pub fn tick(&mut self) -> bool {
        let mut changed = poll_into(&mut self.list_job, &mut self.list, &mut self.list_error);
        changed |= poll_into(&mut self.doctor_job, &mut self.doctor, &mut self.doctor_error);
        changed |= poll_into(
            &mut self.show_job,
            &mut self.notebook,
            &mut self.notebook_error,
        );
        changed |= poll_into(&mut self.clients_job, &mut self.clients, &mut self.clients_error);
        changed |= poll_into(&mut self.client_job, &mut self.client, &mut self.client_error);
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

    fn refresh_clients(&mut self, settings: &Settings) {
        self.clients_error = None;
        self.clients_job = Some(Job::spawn(
            &settings.assist(),
            "assist client list",
            args(&["client", "list", "--json"]),
        ));
    }

    fn load_client(&mut self, settings: &Settings, id: &str) {
        self.client_error = None;
        self.client_job = Some(Job::spawn(
            &settings.assist(),
            "assist client show",
            args(&["client", "show", id, "--json"]),
        ));
    }

    /// Open a client in the centre pane instead of a notebook.
    fn open_client(&mut self, settings: &Settings, id: &str) {
        self.client_id = Some(id.to_string());
        self.notebook_id = None;
        self.notebook = None;
        self.composing = false;
        self.client = None;
        self.error = None;
        self.streaming.clear();
        self.lines_seen = 0;
        // Notes are edited as a whole, so the draft belongs to one client.
        self.notes_draft.clear();
        self.notes_for = None;
        self.load_client(settings, id);
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
        self.refresh_clients(settings);
        if let Some(id) = self.client_id.clone() {
            self.load_client(settings, &id);
            return;
        }
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
        self.client_id = None;
        self.client = None;
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
        if self.clients.is_none() && self.clients_job.is_none() {
            self.refresh_clients(settings);
        }
        if let Some((is_client, id)) = self.pending_open.take() {
            if is_client {
                self.open_client(settings, &id);
            } else {
                self.open(settings, &id);
            }
        }
        // Arriving with work already in flight should show that work, not an
        // empty form: the listing is newest-first.
        if self.notebook_id.is_none() && self.client_id.is_none() && !self.composing {
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
        // control over what the model is told. The client editor has its own
        // source list in the middle, so it does not want this one as well.
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
                self.client_id = None;
                self.client = None;
                self.notebook = None;
                self.streaming.clear();
            }
        });

        let entries = self
            .list
            .as_ref()
            .map(|l| l.notebooks.clone())
            .unwrap_or_default();
        let clients = self
            .clients
            .as_ref()
            .map(|c| c.clients.clone())
            .unwrap_or_default();

        let mut open_notebook: Option<String> = None;
        let mut open_client: Option<String> = None;
        egui::ScrollArea::vertical()
            .id_salt("assist_notebook_list")
            .show(ui, |ui| {
                if entries.is_empty() && clients.is_empty() {
                    ui.weak("No notebooks yet. Describe a problem on the right.");
                }

                // A client heading, then that client's notebooks under it. A
                // flat list of fifty tickets across eight clients is not a list
                // anyone can read.
                for client in &clients {
                    let selected = self.client_id.as_deref() == Some(client.id.as_str());
                    let mut text = egui::RichText::new(&client.name).size(12.0);
                    if selected {
                        text = text.strong();
                    }
                    if ui
                        .selectable_label(selected, text.color(widgets::ACCENT))
                        .on_hover_text("What is permanently true about their setup")
                        .clicked()
                    {
                        open_client = Some(client.id.clone());
                    }
                    let mut about = vec![plural(client.facts, "fact")];
                    if client.sources > 0 {
                        about.push(plural(client.sources, "file"));
                    }
                    ui.label(
                        egui::RichText::new(format!("   {}", about.join("  ·  ")))
                            .size(9.0)
                            .color(widgets::MUTED),
                    );
                    let theirs: Vec<_> = entries
                        .iter()
                        .filter(|entry| entry.client == client.id)
                        .collect();
                    if theirs.is_empty() {
                        ui.label(
                            egui::RichText::new("   no notebooks yet")
                                .size(10.0)
                                .color(widgets::MUTED),
                        );
                    }
                    for entry in theirs {
                        if self.notebook_row(ui, entry, true) {
                            open_notebook = Some(entry.id.clone());
                        }
                    }
                    ui.add_space(8.0);
                }

                // Unfiled last: it is the pile to work through, not the filing.
                let loose: Vec<_> = entries
                    .iter()
                    .filter(|entry| entry.client.is_empty())
                    .collect();
                if !loose.is_empty() {
                    if !clients.is_empty() {
                        ui.label(
                            egui::RichText::new("No client")
                                .size(12.0)
                                .color(widgets::MUTED),
                        );
                    }
                    for entry in loose {
                        if self.notebook_row(ui, entry, !clients.is_empty()) {
                            open_notebook = Some(entry.id.clone());
                        }
                    }
                }

                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_client_name)
                            .desired_width(130.0)
                            .hint_text("new client"),
                    );
                    let ready = !self.new_client_name.trim().is_empty() && !self.busy();
                    if ui.add_enabled(ready, egui::Button::new("Add")).clicked() {
                        let name = self.new_client_name.clone();
                        self.run(
                            &settings.assist(),
                            "assist client new",
                            args(&["client", "new", &name]),
                        );
                        self.new_client_name.clear();
                    }
                });
            });

        if let Some(id) = open_client {
            self.open_client(settings, &id);
        }
        if let Some(id) = open_notebook {
            self.open(settings, &id);
        }
    }

    /// One row in the notebook list. Returns true when it was clicked.
    fn notebook_row(
        &self,
        ui: &mut egui::Ui,
        entry: &crate::model::NotebookSummary,
        indent: bool,
    ) -> bool {
        let pad = if indent { "   " } else { "" };
        let selected = self.notebook_id.as_deref() == Some(entry.id.as_str());
        let mut text = egui::RichText::new(format!("{pad}{}", entry.title)).size(12.0);
        if selected {
            text = text.strong();
        }
        let clicked = ui.selectable_label(selected, text).clicked();
        // Say how many sources are actually in play, not just how many exist:
        // "3/7" is the fact that changes the answer.
        let sources = if entry.sources_on == entry.sources {
            plural(entry.sources, "source")
        } else {
            format!("{}/{} sources", entry.sources_on, entry.sources)
        };
        // Month and day only: the year is almost always this one, and the full
        // date pushed this line onto two.
        let when = entry.created.get(5..10).unwrap_or("");
        ui.label(
            egui::RichText::new(format!(
                "{pad}{}  ·  {}  ·  {}",
                when,
                plural(entry.messages, "message"),
                sources
            ))
            .size(10.0)
            .color(widgets::MUTED),
        );
        ui.add_space(4.0);
        clicked
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
                self.inherited_sources(ui);
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

    /// What the client contributes to this notebook, shown but not editable
    /// here: it belongs to every notebook for them, so switching it off from
    /// one ticket would quietly change the others. The client editor is one
    /// click away for that.
    fn inherited_sources(&mut self, ui: &mut egui::Ui) {
        let Some(client) = self
            .notebook
            .as_ref()
            .and_then(|n| n.client_detail.as_ref())
        else {
            return;
        };
        let on: Vec<&Source> = client
            .sources
            .iter()
            .filter(|source| source.enabled && source.parent.is_none())
            .collect();
        let facts: usize = client.grouped_facts.iter().map(|g| g.values.len()).sum();
        if on.is_empty() && facts == 0 && client.notes.is_empty() {
            return;
        }
        ui.separator();
        ui.label(
            egui::RichText::new(format!("also sent, from {}", client.name))
                .size(10.0)
                .color(widgets::MUTED),
        );
        if facts > 0 {
            ui.label(
                egui::RichText::new(format!("  {} about their setup", plural(facts as i64, "fact")))
                    .size(10.0)
                    .color(widgets::MUTED),
            );
        }
        if !client.notes.is_empty() {
            ui.label(
                egui::RichText::new("  their notes")
                    .size(10.0)
                    .color(widgets::MUTED),
            );
        }
        for source in on {
            ui.label(
                egui::RichText::new(format!("  {}  {}", kind_label(&source.kind), source.stored))
                    .size(10.0)
                    .color(widgets::MUTED),
            );
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
                match (self.client_id.clone(), self.notebook_id.clone()) {
                    (Some(id), _) => self.client_editor(ui, settings, &id),
                    (None, Some(id)) => self.conversation(ui, settings, &id),
                    (None, None) => self.new_notebook_form(ui, settings),
                }
                if !self.streaming.is_empty() {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(&self.streaming).size(13.0));
                }
                job_footer(ui, &self.job, &self.error);
            });
    }

    /// What is permanently true about a client, and the files kept on file for
    /// them. Everything here reaches every notebook filed under them, so it is
    /// edited where that is obvious rather than buried in a dialog.
    fn client_editor(&mut self, ui: &mut egui::Ui, settings: &Settings, id: &str) {
        let Some(client) = self.client.clone() else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("opening...");
            });
            job_footer(ui, &self.job, &self.error);
            return;
        };

        widgets::heading(ui, &client.name);
        ui.label(
            egui::RichText::new(
                "Standing context. This reaches every notebook filed under them, \
                 marked as background rather than as something measured today.",
            )
            .size(11.0)
            .color(widgets::MUTED),
        );
        ui.add_space(8.0);

        // --- facts ---
        let mut forget: Option<(String, String)> = None;
        if client.grouped_facts.is_empty() {
            ui.weak("Nothing written down yet. Firewall addresses, server names, \
                     subnets, the ISP - whatever you would otherwise have to \
                     remember every time.");
        }
        egui::Grid::new("assist_client_facts")
            .num_columns(2)
            .spacing([14.0, 4.0])
            .striped(true)
            .show(ui, |ui| {
                for group in &client.grouped_facts {
                    ui.label(egui::RichText::new(&group.label).size(12.0).strong());
                    ui.vertical(|ui| {
                        for value in &group.values {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(value).size(12.0).monospace());
                                if ui.small_button("x").clicked() {
                                    forget = Some((group.label.clone(), value.clone()));
                                }
                            });
                        }
                    });
                    ui.end_row();
                }
            });
        if let Some((label, value)) = forget {
            self.run(
                &settings.assist(),
                "assist client set",
                args(&["client", "set", id, "--forget", &format!("{label}={value}")]),
            );
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.fact_label)
                    .desired_width(130.0)
                    .hint_text("firewall"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.fact_value)
                    .desired_width(200.0)
                    .hint_text("203.0.113.1"),
            );
            let ready = !self.fact_label.trim().is_empty()
                && !self.fact_value.trim().is_empty()
                && !self.busy();
            if ui.add_enabled(ready, egui::Button::new("Record")).clicked() {
                let pair = format!("{}={}", self.fact_label.trim(), self.fact_value.trim());
                self.run(
                    &settings.assist(),
                    "assist client set",
                    args(&["client", "set", id, "--fact", &pair]),
                );
                // The label stays: people enter several values under one label
                // far more often than they enter one and move on.
                self.fact_value.clear();
            }
            ui.label(
                egui::RichText::new("a label can hold several values")
                    .size(10.0)
                    .color(widgets::MUTED),
            );
        });

        // --- notes ---
        ui.add_space(10.0);
        ui.label(egui::RichText::new("Notes").size(12.0).strong());
        if self.notes_for.as_deref() != Some(id) {
            self.notes_draft = client.notes.clone();
            self.notes_for = Some(id.to_string());
        }
        ui.add(
            egui::TextEdit::multiline(&mut self.notes_draft)
                .desired_width(f32::INFINITY)
                .desired_rows(4)
                .hint_text("Anything that does not fit a label."),
        );
        let dirty = self.notes_draft != client.notes;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(dirty && !self.busy(), egui::Button::new("Save notes"))
                .clicked()
            {
                let notes = self.notes_draft.clone();
                self.run(
                    &settings.assist(),
                    "assist client set",
                    args(&["client", "set", id, "--notes", &notes]),
                );
            }
            if dirty {
                ui.label(
                    egui::RichText::new("unsaved")
                        .size(10.0)
                        .color(widgets::WARN),
                );
            }
        });

        // --- files kept on file ---
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Kept on file").size(12.0).strong());
            if !self.pending.is_empty() {
                let label = format!("Add {}", self.pending.len());
                if ui
                    .add_enabled(!self.busy(), egui::Button::new(label))
                    .clicked()
                {
                    let mut argv = vec![
                        "client".to_string(),
                        "add".to_string(),
                        id.to_string(),
                    ];
                    argv.extend(self.pending.iter().map(|p| p.to_string_lossy().to_string()));
                    self.run(&settings.assist(), "assist client add", argv);
                    self.pending.clear();
                }
            }
        });
        ui.label(
            egui::RichText::new(
                "Reference material - a network diagram, a firewall export, an \
                 asset list. Drop files anywhere here.",
            )
            .size(10.0)
            .color(widgets::MUTED),
        );
        if client.sources.is_empty() && self.pending.is_empty() {
            ui.weak("Nothing on file.");
        }
        let mut toggle: Option<(String, bool)> = None;
        let mut remove: Option<String> = None;
        for source in &client.sources {
            if source.parent.is_some() {
                continue;
            }
            let mut on = source.enabled;
            ui.horizontal(|ui| {
                if ui
                    .checkbox(&mut on, "")
                    .on_hover_text("Off keeps the file but stops sending it")
                    .changed()
                {
                    toggle = Some((source.stored.clone(), on));
                }
                ui.label(
                    egui::RichText::new(kind_label(&source.kind))
                        .size(9.0)
                        .color(widgets::ACCENT),
                );
                ui.label(egui::RichText::new(&source.stored).size(11.0));
                ui.label(
                    egui::RichText::new(&source.note)
                        .size(10.0)
                        .color(widgets::MUTED),
                );
                if ui.small_button("x").clicked() {
                    remove = Some(source.stored.clone());
                }
            });
        }
        self.pending_thumbnails(ui);
        if let Some((name, on)) = toggle {
            let flag = if on { "--on" } else { "--off" };
            self.run(
                &settings.assist(),
                "assist client sources",
                args(&["client", "sources", id, flag, &name]),
            );
        }
        if let Some(name) = remove {
            self.run(
                &settings.assist(),
                "assist client sources",
                args(&["client", "sources", id, "--remove", &name]),
            );
        }

        // --- their notebooks ---
        let theirs: Vec<_> = self
            .list
            .as_ref()
            .map(|l| l.notebooks.iter().filter(|n| n.client == id).cloned().collect())
            .unwrap_or_default();
        ui.add_space(10.0);
        ui.label(
            egui::RichText::new(format!(
                "{} for this client",
                plural(theirs.len() as i64, "notebook")
            ))
            .size(12.0)
            .strong(),
        );
        let mut open = None;
        for entry in &theirs {
            if ui
                .selectable_label(false, egui::RichText::new(&entry.title).size(12.0))
                .clicked()
            {
                open = Some(entry.id.clone());
            }
        }
        ui.horizontal(|ui| {
            if ui.button("New notebook for them").clicked() {
                self.composing = true;
                self.file_under = Some(id.to_string());
                self.client_id = None;
                self.notebook_id = None;
            }
        });
        if let Some(id) = open {
            self.open(settings, &id);
        }

        job_footer(ui, &self.job, &self.error);
    }

    fn new_notebook_form(&mut self, ui: &mut egui::Ui, settings: &Settings) {
        widgets::heading(ui, "What is going wrong?");
        let clients = self
            .clients
            .as_ref()
            .map(|c| c.clients.clone())
            .unwrap_or_default();
        if !clients.is_empty() {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("for").size(12.0).color(widgets::MUTED));
                let chosen = self
                    .file_under
                    .as_ref()
                    .and_then(|id| clients.iter().find(|c| &c.id == id))
                    .map(|c| c.name.clone())
                    .unwrap_or_else(|| "no client".to_string());
                egui::ComboBox::from_id_salt("assist_file_under")
                    .selected_text(chosen)
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(self.file_under.is_none(), "no client")
                            .clicked()
                        {
                            self.file_under = None;
                        }
                        for client in &clients {
                            let picked = self.file_under.as_deref() == Some(&client.id);
                            if ui.selectable_label(picked, &client.name).clicked() {
                                self.file_under = Some(client.id.clone());
                            }
                        }
                    });
                if self.file_under.is_some() {
                    ui.label(
                        egui::RichText::new("their standing context comes with it")
                            .size(10.0)
                            .color(widgets::MUTED),
                    );
                }
            });
        }
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
                if let Some(client) = self.file_under.clone() {
                    argv.push("--client".to_string());
                    argv.push(client);
                }
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
            if let Some(client) = notebook.client_detail.as_ref() {
                let client_id = client.id.clone();
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("for")
                            .size(11.0)
                            .color(widgets::MUTED),
                    );
                    if ui
                        .link(egui::RichText::new(&client.name).size(11.0))
                        .on_hover_text("Open their standing context")
                        .clicked()
                    {
                        self.open_client(settings, &client_id);
                    }
                });
            }
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
