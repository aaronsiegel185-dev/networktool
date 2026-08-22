//! Small painted widgets and formatting helpers shared by the tabs.

use eframe::egui;

pub const OK: egui::Color32 = egui::Color32::from_rgb(102, 187, 106);
pub const INFO: egui::Color32 = egui::Color32::from_rgb(120, 170, 235);
pub const WARN: egui::Color32 = egui::Color32::from_rgb(240, 180, 70);
pub const CRIT: egui::Color32 = egui::Color32::from_rgb(235, 90, 90);
pub const MUTED: egui::Color32 = egui::Color32::from_rgb(150, 150, 155);
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(110, 195, 255);

/// Colour for a nettool severity string (`ok` / `info` / `warn` / `critical`).
pub fn severity_color(severity: &str) -> egui::Color32 {
    match severity {
        "ok" => OK,
        "info" => INFO,
        "warn" => WARN,
        "critical" => CRIT,
        _ => MUTED,
    }
}

pub fn severity_label(severity: &str) -> &'static str {
    match severity {
        "ok" => "OK",
        "info" => "INFO",
        "warn" => "WARN",
        "critical" => "FAIL",
        _ => "-",
    }
}

/// Colour for an RSSI value, matching nettool's rating thresholds.
pub fn signal_color(dbm: f64) -> egui::Color32 {
    if dbm >= -60.0 {
        OK
    } else if dbm >= -67.0 {
        egui::Color32::from_rgb(180, 200, 90)
    } else if dbm >= -72.0 {
        WARN
    } else {
        CRIT
    }
}

/// RSSI mapped to 0..1 for bar widths (-90 dBm empty, -30 dBm full).
pub fn signal_fraction(dbm: f64) -> f32 {
    (((dbm + 90.0) / 60.0) as f32).clamp(0.0, 1.0)
}

pub fn port_state_color(state: &str) -> egui::Color32 {
    if state.starts_with("open|") {
        WARN
    } else if state.starts_with("open") {
        OK
    } else if state == "filtered" {
        INFO
    } else {
        MUTED
    }
}

pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
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

pub fn fmt_secs(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0} ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{secs:.1} s")
    } else {
        format!("{}m {:02}s", (secs as u64) / 60, (secs as u64) % 60)
    }
}

pub fn fmt_opt<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
}

pub fn fmt_opt_f(value: Option<f64>, decimals: usize) -> String {
    match value {
        Some(v) => format!("{v:.*}", decimals),
        None => "-".into(),
    }
}

/// A coloured severity chip, e.g. `[WARN]`.
pub fn severity_badge(ui: &mut egui::Ui, severity: &str) {
    let color = severity_color(severity);
    let text = severity_label(severity);
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        egui::FontId::monospace(11.0),
        color,
    );
    let size = egui::vec2(galley.size().x + 12.0, galley.size().y + 4.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, 3.0, color.gamma_multiply(0.18));
    ui.painter().rect_stroke(
        rect,
        3.0,
        egui::Stroke::new(1.0, color.gamma_multiply(0.6)),
        egui::StrokeKind::Inside,
    );
    ui.painter().galley(
        rect.center() - galley.size() / 2.0,
        galley,
        color,
    );
    response.on_hover_text(severity);
}

/// Horizontal signal-strength bar with the dBm value alongside.
pub fn signal_bar(ui: &mut egui::Ui, dbm: Option<f64>, width: f32) {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 14.0), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 2.0, egui::Color32::from_gray(45));
    if let Some(dbm) = dbm {
        let fraction = signal_fraction(dbm);
        let filled = egui::Rect::from_min_size(
            rect.min,
            egui::vec2(rect.width() * fraction, rect.height()),
        );
        painter.rect_filled(filled, 2.0, signal_color(dbm));
        painter.text(
            rect.right_center() - egui::vec2(4.0, 0.0),
            egui::Align2::RIGHT_CENTER,
            format!("{dbm:.0}"),
            egui::FontId::monospace(10.0),
            egui::Color32::from_gray(230),
        );
        response.on_hover_text(format!("{dbm:.0} dBm ({}%)", (fraction * 100.0) as i32));
    } else {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "-",
            egui::FontId::monospace(10.0),
            MUTED,
        );
    }
}

/// A vertical bar chart: used for per-channel congestion scores.
pub struct BarChartItem {
    pub label: String,
    pub value: f64,
    pub color: egui::Color32,
    pub marker: Option<&'static str>,
}

pub fn bar_chart(ui: &mut egui::Ui, items: &[BarChartItem], height: f32) {
    if items.is_empty() {
        ui.weak("no data");
        return;
    }
    let width = ui.available_width().max(240.0);
    let (rect, _response) =
        ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let max = items
        .iter()
        .map(|i| i.value)
        .fold(0.0_f64, f64::max)
        .max(0.001);
    // Headroom at the top for the "you"/"best" markers, and a strip at the bottom
    // for the channel labels.
    let plot = egui::Rect::from_min_max(
        rect.min + egui::vec2(0.0, 16.0),
        rect.max - egui::vec2(0.0, 18.0),
    );
    let slot = plot.width() / items.len() as f32;
    let bar_width = (slot * 0.62).clamp(4.0, 46.0);
    for (index, item) in items.iter().enumerate() {
        let centre_x = plot.left() + slot * (index as f32 + 0.5);
        let fraction = (item.value / max) as f32;
        let bar_height = (plot.height() * fraction).max(1.0);
        let bar = egui::Rect::from_min_max(
            egui::pos2(centre_x - bar_width / 2.0, plot.bottom() - bar_height),
            egui::pos2(centre_x + bar_width / 2.0, plot.bottom()),
        );
        painter.rect_filled(bar, 2.0, item.color);
        painter.text(
            egui::pos2(centre_x, rect.bottom() - 8.0),
            egui::Align2::CENTER_CENTER,
            &item.label,
            egui::FontId::monospace(10.0),
            egui::Color32::from_gray(200),
        );
        if item.value > 0.0 {
            // Tall bars would push their label into the marker strip, so label inside.
            let inside = fraction > 0.8;
            painter.text(
                egui::pos2(centre_x, bar.top() + if inside { 7.0 } else { -6.0 }),
                egui::Align2::CENTER_CENTER,
                format!("{:.1}", item.value),
                egui::FontId::monospace(9.0),
                if inside {
                    egui::Color32::from_gray(20)
                } else {
                    egui::Color32::from_gray(190)
                },
            );
        }
        if let Some(marker) = item.marker {
            painter.text(
                egui::pos2(centre_x, rect.top()),
                egui::Align2::CENTER_TOP,
                marker,
                egui::FontId::monospace(9.0),
                ACCENT,
            );
        }
    }
    painter.line_segment(
        [plot.left_bottom(), plot.right_bottom()],
        egui::Stroke::new(1.0, egui::Color32::from_gray(70)),
    );
}

/// A time-series line chart for signal history (values in dBm).
pub fn signal_history(ui: &mut egui::Ui, samples: &[f64], height: f32) {
    let width = ui.available_width().max(240.0);
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 3.0, egui::Color32::from_gray(28));
    let (low, high) = (-95.0_f64, -25.0_f64);
    for level in [-30.0, -50.0, -67.0, -80.0] {
        let y = rect.bottom() - ((level - low) / (high - low)) as f32 * rect.height();
        painter.line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            egui::Stroke::new(1.0, egui::Color32::from_gray(48)),
        );
        painter.text(
            egui::pos2(rect.left() + 3.0, y),
            egui::Align2::LEFT_BOTTOM,
            format!("{level:.0}"),
            egui::FontId::monospace(9.0),
            egui::Color32::from_gray(110),
        );
    }
    if samples.is_empty() {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "waiting for samples",
            egui::FontId::proportional(12.0),
            MUTED,
        );
        return;
    }
    let visible: &[f64] = if samples.len() > 240 {
        &samples[samples.len() - 240..]
    } else {
        samples
    };
    let step = if visible.len() > 1 {
        rect.width() / (visible.len() - 1) as f32
    } else {
        0.0
    };
    let point_at = |index: usize, value: f64| {
        let clamped = value.clamp(low, high);
        egui::pos2(
            rect.left() + step * index as f32,
            rect.bottom() - ((clamped - low) / (high - low)) as f32 * rect.height(),
        )
    };
    let points: Vec<egui::Pos2> = visible
        .iter()
        .enumerate()
        .map(|(i, v)| point_at(i, *v))
        .collect();
    for pair in points.windows(2) {
        painter.line_segment([pair[0], pair[1]], egui::Stroke::new(1.5, ACCENT));
    }
    if let (Some(last), Some(value)) = (points.last(), visible.last()) {
        painter.circle_filled(*last, 3.0, signal_color(*value));
        painter.text(
            egui::pos2(rect.right() - 6.0, rect.top() + 6.0),
            egui::Align2::RIGHT_TOP,
            format!("{value:.0} dBm"),
            egui::FontId::monospace(12.0),
            signal_color(*value),
        );
    }
    response.on_hover_text(format!("{} samples", samples.len()));
}

/// Key/value row inside an `egui::Grid`.
pub fn kv(ui: &mut egui::Ui, key: &str, value: impl Into<String>) {
    ui.label(egui::RichText::new(key).color(MUTED));
    ui.monospace(value.into());
    ui.end_row();
}

pub fn heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(2.0);
    ui.label(egui::RichText::new(text).strong().size(15.0));
    ui.add_space(2.0);
}

/// Column header row for the hand-rolled tables.
pub fn header_row(ui: &mut egui::Ui, columns: &[&str]) {
    for column in columns {
        ui.label(
            egui::RichText::new(*column)
                .color(MUTED)
                .size(11.0)
                .strong(),
        );
    }
    ui.end_row();
}
