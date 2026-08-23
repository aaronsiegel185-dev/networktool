//! Pure presentation logic: thresholds, colours and formatting.

use nettool_gui::ui::widgets::*;
use nettool_gui::ui::wifi::summarize;
use nettool_gui::ui::Tab;

#[test]
fn severity_colours_are_distinct_and_stable() {
    assert_eq!(severity_color("ok"), OK);
    assert_eq!(severity_color("info"), INFO);
    assert_eq!(severity_color("warn"), WARN);
    assert_eq!(severity_color("critical"), CRIT);
    assert_eq!(severity_color("nonsense"), MUTED);
    assert_eq!(severity_label("critical"), "FAIL");
    assert_eq!(severity_label("ok"), "OK");
}

#[test]
fn signal_colour_follows_the_rating_thresholds() {
    assert_eq!(signal_color(-45.0), OK);
    assert_eq!(signal_color(-60.0), OK);
    assert_eq!(signal_color(-70.0), WARN);
    assert_eq!(signal_color(-85.0), CRIT);
    // -67 dBm is the voice/video floor: it must not be painted "good".
    assert_ne!(signal_color(-67.0), OK);
}

#[test]
fn signal_fraction_is_clamped() {
    assert_eq!(signal_fraction(-90.0), 0.0);
    assert_eq!(signal_fraction(-30.0), 1.0);
    assert_eq!(signal_fraction(-120.0), 0.0);
    assert_eq!(signal_fraction(0.0), 1.0);
    assert!((signal_fraction(-60.0) - 0.5).abs() < 0.001);
}

#[test]
fn port_states_are_colour_coded() {
    assert_eq!(port_state_color("open"), OK);
    assert_eq!(port_state_color("open|filtered"), WARN);
    assert_eq!(port_state_color("filtered"), INFO);
    assert_eq!(port_state_color("closed"), MUTED);
}

#[test]
fn formats_sizes_and_durations() {
    assert_eq!(fmt_bytes(0), "0 B");
    assert_eq!(fmt_bytes(512), "512 B");
    assert_eq!(fmt_bytes(2048), "2.0 KiB");
    assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.0 MiB");
    assert_eq!(fmt_secs(0.51), "510 ms");
    assert_eq!(fmt_secs(4.0), "4.0 s");
    assert_eq!(fmt_secs(125.0), "2m 05s");
    assert_eq!(fmt_opt(Some(6)), "6");
    assert_eq!(fmt_opt::<i64>(None), "-");
    assert_eq!(fmt_opt_f(Some(-47.4), 0), "-47");
    assert_eq!(fmt_opt_f(None, 2), "-");
}

#[test]
fn summarises_signal_history() {
    let stats = summarize(&[-50.0, -60.0, -55.0, -70.0]);
    assert_eq!(stats.min, Some(-70.0));
    assert_eq!(stats.max, Some(-50.0));
    assert_eq!(stats.swing, Some(20.0));
    assert!((stats.avg.unwrap() - -58.75).abs() < 0.001);

    let empty = summarize(&[]);
    assert!(empty.min.is_none() && empty.avg.is_none() && empty.swing.is_none());

    let single = summarize(&[-42.0]);
    assert_eq!(single.swing, Some(0.0));
    assert_eq!(single.avg, Some(-42.0));
}

#[test]
fn every_tab_has_a_title() {
    // Overview, Discover, Scan, LLDP, Capture, Mirror, Wi-Fi
    assert_eq!(Tab::ALL.len(), 7);
    for tab in Tab::ALL {
        assert!(!tab.title().is_empty());
    }
    assert_eq!(Tab::default(), Tab::Overview);
}
