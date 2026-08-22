//! Command construction, subprocess streaming and cancellation.

use nettool_gui::runner::{args, running_as_root, Job, JobMode, Settings};
use std::time::{Duration, Instant};

fn python(script: &str) -> Settings {
    Settings {
        base: vec!["python3".into(), "-c".into(), script.into()],
        use_sudo: false,
        working_dir: None,
    }
}

fn wait_for(job: &mut Job, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while job.running() && Instant::now() < deadline {
        job.poll();
        std::thread::sleep(Duration::from_millis(20));
    }
    job.poll();
}

#[test]
fn builds_plain_argv() {
    let settings = Settings {
        base: vec!["nettool".into()],
        use_sudo: false,
        working_dir: None,
    };
    assert_eq!(
        settings.argv(&args(&["scan", "10.0.0.1", "--json"])),
        vec!["nettool", "scan", "10.0.0.1", "--json"]
    );
}

#[test]
fn prefixes_sudo_without_prompting() {
    let settings = Settings {
        base: vec!["python3".into(), "-m".into(), "nettool".into()],
        use_sudo: true,
        working_dir: None,
    };
    let argv = settings.argv(&args(&["capture", "-i", "eth0"]));
    assert_eq!(
        argv,
        vec!["sudo", "-n", "python3", "-m", "nettool", "capture", "-i", "eth0"]
    );
}

#[test]
fn streams_stdout_lines() {
    let settings = python("print('one'); print('two'); print('three')");
    let mut job = Job::spawn(&settings, "lines", Vec::new());
    wait_for(&mut job, Duration::from_secs(20));
    assert!(!job.running());
    assert_eq!(job.lines, vec!["one", "two", "three"]);
    assert!(job.result.as_ref().unwrap().ok());
}

#[test]
fn parses_json_output() {
    #[derive(serde::Deserialize)]
    struct Payload {
        packets: u64,
        name: String,
    }
    let settings = python(r#"print('{"packets": 7, "name": "eth0"}')"#);
    let mut job = Job::spawn(&settings, "json", Vec::new());
    wait_for(&mut job, Duration::from_secs(20));
    let payload: Payload = job.parse_json().unwrap().unwrap();
    assert_eq!(payload.packets, 7);
    assert_eq!(payload.name, "eth0");
}

#[test]
fn surfaces_stderr_when_the_command_fails() {
    let settings = python("import sys; sys.stderr.write('error: no such interface\\n'); sys.exit(2)");
    let mut job = Job::spawn(&settings, "fail", Vec::new());
    wait_for(&mut job, Duration::from_secs(20));
    let result = job.result.as_ref().unwrap();
    assert!(!result.ok());
    assert_eq!(result.code, Some(2));
    assert!(result.error_text().contains("no such interface"));

    let parsed: Option<Result<serde_json::Value, String>> = job.parse_json();
    let err = parsed.unwrap().unwrap_err();
    assert!(err.contains("no such interface"), "{err}");
}

#[test]
fn reports_a_missing_binary_instead_of_panicking() {
    let settings = Settings {
        base: vec!["definitely-not-a-real-binary-xyz".into()],
        use_sudo: false,
        working_dir: None,
    };
    let mut job = Job::spawn(&settings, "missing", Vec::new());
    wait_for(&mut job, Duration::from_secs(10));
    assert!(!job.running());
    let text = job.result.as_ref().unwrap().error_text();
    assert!(text.contains("could not run"), "{text}");
}

#[test]
fn cancel_stops_a_long_running_command() {
    let settings = python("import time; time.sleep(120)");
    let mut job = Job::spawn(&settings, "sleep", Vec::new());
    std::thread::sleep(Duration::from_millis(300));
    assert!(job.running());
    job.cancel();
    wait_for(&mut job, Duration::from_secs(15));
    assert!(!job.running(), "cancelled job should finish promptly");
    assert!(job.cancelled);
}

#[test]
fn repeat_mode_samples_until_stopped() {
    let settings = python(r#"print('{"signal_dbm": -55}')"#);
    let mut job = Job::spawn_mode(
        &settings,
        "monitor",
        Vec::new(),
        JobMode::Repeat(Duration::from_millis(150)),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while job.lines.len() < 3 && Instant::now() < deadline {
        job.poll();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(job.lines.len() >= 3, "expected repeated samples");
    assert!(job.lines[0].contains("signal_dbm"));
    job.cancel();
    wait_for(&mut job, Duration::from_secs(10));
    assert!(!job.running());
}

#[test]
fn root_detection_matches_the_environment() {
    // Whatever the answer, it must not panic and must agree with /proc.
    let detected = running_as_root();
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let euid = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("1000")
            .to_string();
        assert_eq!(detected, euid == "0");
    }
}
