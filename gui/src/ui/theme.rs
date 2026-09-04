//! Two looks: the ordinary dark one, and hacker mode.
//!
//! Hacker mode is green phosphor on black - the look of a VT220 that has been
//! left on too long. It is entirely cosmetic and changes nothing about what the
//! app measures or reports.
//!
//! The severity colours are the one thing it does not tint. Green, amber and red
//! have to stay distinguishable from each other and from ordinary text, and a
//! screen where everything is green is a screen where a critical finding looks
//! like a passing one. A real amber terminal had the same three-colour problem
//! and solved it the same way.

use eframe::egui;

/// Phosphor green, at the brightnesses a terminal actually used.
pub const PHOSPHOR: egui::Color32 = egui::Color32::from_rgb(0, 255, 102);
pub const PHOSPHOR_DIM: egui::Color32 = egui::Color32::from_rgb(0, 170, 68);
pub const PHOSPHOR_FAINT: egui::Color32 = egui::Color32::from_rgb(0, 90, 40);
const VOID: egui::Color32 = egui::Color32::from_rgb(4, 10, 6);
const PANEL: egui::Color32 = egui::Color32::from_rgb(8, 18, 11);
const RAISED: egui::Color32 = egui::Color32::from_rgb(14, 30, 18);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Skin {
    #[default]
    Dark,
    Hacker,
}

impl Skin {
    pub fn is_hacker(self) -> bool {
        self == Skin::Hacker
    }

    pub fn toggled(self) -> Self {
        match self {
            Skin::Dark => Skin::Hacker,
            Skin::Hacker => Skin::Dark,
        }
    }

    /// What the toggle should say to describe what pressing it does.
    pub fn button_label(self) -> &'static str {
        match self {
            Skin::Dark => "hacker mode",
            Skin::Hacker => "normal mode",
        }
    }

    /// Text colour for anything the app does not colour deliberately.
    pub fn foreground(self) -> egui::Color32 {
        match self {
            Skin::Dark => egui::Color32::from_rgb(220, 220, 225),
            Skin::Hacker => PHOSPHOR,
        }
    }

    /// Secondary text - the same relationship to the foreground in both skins.
    pub fn muted(self) -> egui::Color32 {
        match self {
            Skin::Dark => egui::Color32::from_rgb(150, 150, 155),
            Skin::Hacker => PHOSPHOR_DIM,
        }
    }

    pub fn accent(self) -> egui::Color32 {
        match self {
            Skin::Dark => egui::Color32::from_rgb(110, 195, 255),
            Skin::Hacker => PHOSPHOR,
        }
    }

    pub fn visuals(self) -> egui::Visuals {
        match self {
            Skin::Dark => egui::Visuals::dark(),
            Skin::Hacker => hacker_visuals(),
        }
    }
}

fn hacker_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = VOID;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = egui::Color32::BLACK;
    visuals.faint_bg_color = PANEL;
    visuals.code_bg_color = PANEL;
    visuals.window_stroke = egui::Stroke::new(1.0, PHOSPHOR_FAINT);
    visuals.selection.bg_fill = PHOSPHOR_FAINT;
    visuals.selection.stroke = egui::Stroke::new(1.0, PHOSPHOR);
    visuals.hyperlink_color = PHOSPHOR;
    visuals.warn_fg_color = egui::Color32::from_rgb(240, 180, 70);
    visuals.error_fg_color = egui::Color32::from_rgb(235, 90, 90);

    // A terminal has no shadows and no rounded corners.
    visuals.window_shadow = egui::epaint::Shadow::NONE;
    visuals.popup_shadow = egui::epaint::Shadow::NONE;
    visuals.window_corner_radius = egui::CornerRadius::ZERO;
    visuals.menu_corner_radius = egui::CornerRadius::ZERO;

    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = egui::CornerRadius::ZERO;
        widget.fg_stroke = egui::Stroke::new(1.0, PHOSPHOR);
        widget.bg_stroke = egui::Stroke::new(1.0, PHOSPHOR_FAINT);
    }
    // Then the differences that make a control look pressable: the resting
    // state is the background, and touching it lights it up.
    //
    // Both fg_strokes below stay bright, and neither is decorative. egui takes
    // ordinary text from noninteractive and *strong* text from active, so a
    // dark colour on either does not tint a button - it makes every heading in
    // the app illegible.
    visuals.widgets.noninteractive.bg_fill = VOID;
    visuals.widgets.noninteractive.weak_bg_fill = VOID;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, PHOSPHOR);
    visuals.widgets.inactive.bg_fill = RAISED;
    visuals.widgets.inactive.weak_bg_fill = PANEL;
    visuals.widgets.hovered.bg_fill = PHOSPHOR_FAINT;
    visuals.widgets.hovered.weak_bg_fill = PHOSPHOR_FAINT;
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, PHOSPHOR);
    visuals.widgets.active.bg_fill = PHOSPHOR_FAINT;
    visuals.widgets.active.weak_bg_fill = PHOSPHOR_FAINT;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, PHOSPHOR);
    visuals.widgets.open.bg_fill = RAISED;

    visuals
}

/// Put a skin on, including the font change that does most of the work.
pub fn apply(ctx: &egui::Context, skin: Skin) {
    ctx.set_visuals(skin.visuals());
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        // Monospace everywhere is what actually sells it - the colour alone
        // just looks like a dark theme with an unusual accent.
        let family = if skin.is_hacker() {
            egui::FontFamily::Monospace
        } else {
            egui::FontFamily::Proportional
        };
        for (text_style, font) in style.text_styles.iter_mut() {
            if *text_style != egui::TextStyle::Monospace {
                font.family = family.clone();
            }
        }
    });
}

/// Where the choice is remembered between launches.
///
/// A single line in the user's config directory rather than anything grander:
/// it is one boolean, and losing it costs a button press.
fn skin_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                let home = std::path::PathBuf::from(home);
                if cfg!(target_os = "macos") {
                    home.join("Library/Application Support")
                } else {
                    home.join(".config")
                }
            })
        })?;
    Some(base.join("nettool").join("skin"))
}

pub fn load_skin() -> Skin {
    let Some(path) = skin_path() else {
        return Skin::Dark;
    };
    match std::fs::read_to_string(path) {
        Ok(text) if text.trim() == "hacker" => Skin::Hacker,
        _ => Skin::Dark,
    }
}

pub fn save_skin(skin: Skin) {
    let Some(path) = skin_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Best effort: a read-only home directory should not stop the app working.
    let _ = std::fs::write(path, if skin.is_hacker() { "hacker" } else { "dark" });
}
