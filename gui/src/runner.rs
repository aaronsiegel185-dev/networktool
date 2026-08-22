//! Running `nettool` as a child process without blocking the UI thread.
//!
//! Every command runs on a worker thread that streams stdout back over a channel, so
//! long jobs (a 60 second capture, a /24 port scan) stay responsive and cancellable.

use serde::de::DeserializeOwned;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How to invoke nettool: either the installed `nettool` binary or `python3 -m nettool`,
/// optionally through `sudo` for the raw-socket features.
#[derive(Debug, Clone)]
pub struct Settings {
    pub base: Vec<String>,
    pub use_sudo: bool,
    pub working_dir: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            base: vec!["nettool".to_string()],
            use_sudo: false,
            working_dir: None,
        }
    }
}

impl Settings {
    /// Find a working nettool: the CLI on PATH first, then `python3 -m nettool` from
    /// the repository checkout next to this binary.
    pub fn detect() -> Self {
        let mut settings = Self::default();
        if probe(&["nettool".into()], None) {
            return settings;
        }
        let python = vec!["python3".to_string(), "-m".to_string(), "nettool".to_string()];
        for dir in candidate_dirs() {
            if probe(&python, Some(&dir)) {
                settings.base = python;
                settings.working_dir = Some(dir);
                return settings;
            }
        }
        if probe(&python, None) {
            settings.base = python;
        }
        settings
    }

    /// Full argv for a command, including any sudo prefix.
    pub fn argv(&self, args: &[String]) -> Vec<String> {
        let mut argv: Vec<String> = Vec::new();
        if self.use_sudo {
            argv.push("sudo".to_string());
            argv.push("-n".to_string());
        }
        argv.extend(self.base.iter().cloned());
        argv.extend(args.iter().cloned());
        argv
    }

    /// The command as the user would type it - shown in the UI so nothing is hidden.
    pub fn command_line(&self, args: &[String]) -> String {
        self.argv(args).join(" ")
    }
}

fn candidate_dirs() -> Vec<String> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        // target/{debug,release}/nettool-gui -> repo root is three levels up.
        let mut path = exe.clone();
        for _ in 0..4 {
            if let Some(parent) = path.parent() {
                path = parent.to_path_buf();
                if path.join("nettool").join("cli.py").exists() {
                    dirs.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("nettool").join("cli.py").exists() {
            dirs.push(cwd.to_string_lossy().to_string());
        }
        if let Some(parent) = cwd.parent() {
            if parent.join("nettool").join("cli.py").exists() {
                dirs.push(parent.to_string_lossy().to_string());
            }
        }
    }
    dirs
}

fn probe(base: &[String], dir: Option<&str>) -> bool {
    let mut cmd = Command::new(&base[0]);
    cmd.args(&base[1..])
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    matches!(cmd.status(), Ok(status) if status.success())
}

#[derive(Debug, Clone)]
pub struct JobResult {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl JobResult {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// The most useful error text we can show: nettool's stderr, else the exit code.
    pub fn error_text(&self) -> String {
        let stderr = self.stderr.trim();
        if !stderr.is_empty() {
            return stderr.to_string();
        }
        match self.code {
            Some(code) => format!("command exited with status {code}"),
            None => "command was terminated".to_string(),
        }
    }
}

enum JobEvent {
    Line(String),
    Finished(JobResult),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobMode {
    /// Run once and finish.
    Once,
    /// Re-run on an interval until cancelled (used for live Wi-Fi sampling).
    Repeat(Duration),
}

/// A running (or finished) nettool invocation.
pub struct Job {
    pub label: String,
    pub command_line: String,
    pub started: Instant,
    pub lines: Vec<String>,
    pub result: Option<JobResult>,
    pub cancelled: bool,
    rx: Receiver<JobEvent>,
    child: Arc<Mutex<Option<Child>>>,
    stop: Arc<AtomicBool>,
    finished: bool,
}

impl Job {
    pub fn spawn(settings: &Settings, label: impl Into<String>, args: Vec<String>) -> Self {
        Self::spawn_mode(settings, label, args, JobMode::Once)
    }

    pub fn spawn_mode(
        settings: &Settings,
        label: impl Into<String>,
        args: Vec<String>,
        mode: JobMode,
    ) -> Self {
        let argv = settings.argv(&args);
        let command_line = argv.join(" ");
        let working_dir = settings.working_dir.clone();
        let (tx, rx) = channel();
        let child_slot: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));

        let thread_child = Arc::clone(&child_slot);
        let thread_stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut aggregate_out;
            let mut aggregate_err;
            let mut last_code;
            loop {
                let mut command = Command::new(&argv[0]);
                command
                    .args(&argv[1..])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .stdin(Stdio::null());
                if let Some(dir) = &working_dir {
                    command.current_dir(dir);
                }
                let mut child = match command.spawn() {
                    Ok(child) => child,
                    Err(err) => {
                        let _ = tx.send(JobEvent::Finished(JobResult {
                            code: None,
                            stdout: String::new(),
                            stderr: format!("could not run {}: {err}", argv[0]),
                        }));
                        return;
                    }
                };
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                if let Ok(mut slot) = thread_child.lock() {
                    *slot = Some(child);
                }

                // stderr is drained on its own thread so a chatty command cannot
                // deadlock by filling the pipe buffer while we read stdout.
                let err_handle = std::thread::spawn(move || {
                    let mut buf = String::new();
                    if let Some(mut stderr) = stderr {
                        let _ = stderr.read_to_string(&mut buf);
                    }
                    buf
                });

                let mut this_run = String::new();
                if let Some(stdout) = stdout {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        match line {
                            Ok(line) => {
                                this_run.push_str(&line);
                                this_run.push('\n');
                                if mode == JobMode::Once {
                                    let _ = tx.send(JobEvent::Line(line));
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                let err_text = err_handle.join().unwrap_or_default();
                let code = {
                    let mut slot = thread_child.lock().ok();
                    match slot.as_mut().and_then(|s| s.as_mut()) {
                        Some(child) => child.wait().ok().and_then(|s| s.code()),
                        None => None,
                    }
                };
                if let Ok(mut slot) = thread_child.lock() {
                    *slot = None;
                }
                aggregate_out = this_run.clone();
                aggregate_err = err_text;
                last_code = code;

                match mode {
                    JobMode::Once => break,
                    JobMode::Repeat(interval) => {
                        // One JSON document per sample, newline-free, as a single line.
                        let _ = tx.send(JobEvent::Line(this_run.replace('\n', " ")));
                        let deadline = Instant::now() + interval;
                        while Instant::now() < deadline {
                            if thread_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        if thread_stop.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }
            let _ = tx.send(JobEvent::Finished(JobResult {
                code: last_code,
                stdout: aggregate_out,
                stderr: aggregate_err,
            }));
        });

        Self {
            label: label.into(),
            command_line,
            started: Instant::now(),
            lines: Vec::new(),
            result: None,
            cancelled: false,
            rx,
            child: child_slot,
            stop,
            finished: false,
        }
    }

    /// Drain pending events. Returns true when anything changed this frame.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        loop {
            match self.rx.try_recv() {
                Ok(JobEvent::Line(line)) => {
                    if self.lines.len() >= 5000 {
                        self.lines.drain(0..1000);
                    }
                    self.lines.push(line);
                    changed = true;
                }
                Ok(JobEvent::Finished(result)) => {
                    self.result = Some(result);
                    self.finished = true;
                    changed = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if !self.finished {
                        self.finished = true;
                        changed = true;
                    }
                    break;
                }
            }
        }
        if self.cancelled && self.running() {
            // The worker may have held the lock last frame; keep trying.
            self.kill_child();
        }
        changed
    }

    pub fn running(&self) -> bool {
        !self.finished
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.stop.store(true, Ordering::Relaxed);
        self.kill_child();
    }

    fn kill_child(&self) {
        if let Ok(mut slot) = self.child.try_lock() {
            if let Some(child) = slot.as_mut() {
                let _ = child.kill();
            }
        }
    }

    /// Parse the accumulated stdout as JSON once the job has finished.
    pub fn parse_json<T: DeserializeOwned>(&self) -> Option<Result<T, String>> {
        let result = self.result.as_ref()?;
        if result.stdout.trim().is_empty() {
            return Some(Err(result.error_text()));
        }
        match serde_json::from_str::<T>(&result.stdout) {
            Ok(value) => Some(Ok(value)),
            Err(err) => {
                if !result.ok() {
                    Some(Err(result.error_text()))
                } else {
                    Some(Err(format!("could not read nettool output: {err}")))
                }
            }
        }
    }
}

/// True when this process already has root, so the UI can stop nagging about sudo.
/// Reads /proc/self/status rather than pulling in libc for one call.
pub fn running_as_root() -> bool {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .map(|euid| euid == "0")
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Turn `&["scan", "10.0.0.1"]` into owned args - keeps call sites readable.
pub fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}
