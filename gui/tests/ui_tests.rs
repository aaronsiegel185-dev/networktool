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
    // Overview, Discover, Scan, LLDP, Capture, Mirror, Analyse, Wi-Fi
    assert_eq!(Tab::ALL.len(), 8);
    for tab in Tab::ALL {
        assert!(!tab.title().is_empty());
    }
    assert_eq!(Tab::default(), Tab::Overview);
}

#[test]
fn the_skin_toggles_and_names_what_pressing_it_does() {
    use nettool_gui::ui::theme::Skin;

    assert_eq!(Skin::default(), Skin::Dark);
    assert!(!Skin::Dark.is_hacker());
    assert!(Skin::Hacker.is_hacker());
    assert_eq!(Skin::Dark.toggled(), Skin::Hacker);
    assert_eq!(Skin::Hacker.toggled(), Skin::Dark);
    // The button says where it goes, not where it is.
    assert_eq!(Skin::Dark.button_label(), "hacker mode");
    assert_eq!(Skin::Hacker.button_label(), "normal mode");
}

#[test]
fn strong_text_stays_legible_in_both_skins() {
    use nettool_gui::ui::theme::Skin;

    // egui takes ordinary text from widgets.noninteractive and *strong* text
    // from widgets.active. A dark colour on the latter looks like a sensible
    // choice for a pressed button and silently turns every heading in the app
    // invisible, which is exactly what it did.
    for skin in [Skin::Dark, Skin::Hacker] {
        let visuals = skin.visuals();
        let background = visuals.panel_fill;
        for (name, colour) in [
            ("body", visuals.widgets.noninteractive.fg_stroke.color),
            ("strong", visuals.widgets.active.fg_stroke.color),
        ] {
            let contrast = luminance(colour) - luminance(background);
            assert!(
                contrast > 0.25,
                "{name} text in {skin:?} is only {contrast:.2} brighter than the \
                 background it sits on",
            );
        }
    }
}

#[test]
fn hacker_mode_is_green_on_black_and_nothing_else_changes_meaning() {
    use nettool_gui::ui::theme::Skin;

    let hacker = Skin::Hacker.visuals();
    assert!(luminance(hacker.panel_fill) < 0.1, "the background is black");
    assert!(is_greenish(Skin::Hacker.foreground()), "the text is green");

    // Severity has to survive the theme: three colours that mean three things
    // cannot all become green, or a critical finding reads as a passing one.
    // What matters is that they stay apart and stay readable, not that they
    // match any particular shade.
    let warn = hacker.warn_fg_color;
    let error = hacker.error_fg_color;
    assert_ne!(warn, error, "warning and error must not be the same colour");
    for (name, colour) in [("warn", warn), ("error", error)] {
        assert!(
            !is_greenish(colour),
            "{name} is green enough to be mistaken for ordinary text",
        );
        assert!(
            luminance(colour) - luminance(hacker.panel_fill) > 0.25,
            "{name} is not readable on the background",
        );
    }
}

/// Whether a colour would read as the theme's phosphor rather than as a warning.
fn is_greenish(colour: eframe::egui::Color32) -> bool {
    let [r, g, b, _] = colour.to_array();
    g as u16 > r as u16 + 40 && g as u16 > b as u16 + 40
}

/// Rough perceived brightness, 0 (black) to 1 (white).
fn luminance(colour: eframe::egui::Color32) -> f32 {
    let [r, g, b, _] = colour.to_array();
    (0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32) / 255.0
}
