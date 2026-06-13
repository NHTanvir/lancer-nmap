//! Modern light / dark theming (palette, rounding, spacing), persisted via
//! eframe storage.

use eframe::egui::{self, Color32, Margin, Rounding, Stroke};
use serde::{Deserialize, Serialize};

// ── Palette (Tokyo-night inspired) ────────────────────────────────────────
pub const BG: Color32 = Color32::from_rgb(0x1a, 0x1b, 0x26);
pub const BG_PANEL: Color32 = Color32::from_rgb(0x16, 0x17, 0x20);
pub const BG_CARD: Color32 = Color32::from_rgb(0x24, 0x28, 0x3b);
pub const BG_WIDGET: Color32 = Color32::from_rgb(0x2c, 0x31, 0x48);
pub const BG_HOVER: Color32 = Color32::from_rgb(0x3b, 0x42, 0x61);
pub const TEXT: Color32 = Color32::from_rgb(0xc0, 0xca, 0xf5);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x7a, 0x84, 0xb0);
pub const ACCENT: Color32 = Color32::from_rgb(0x7a, 0xa2, 0xf7);
pub const GREEN: Color32 = Color32::from_rgb(0x9e, 0xce, 0x6a);
pub const RED: Color32 = Color32::from_rgb(0xf7, 0x76, 0x8e);
pub const ORANGE: Color32 = Color32::from_rgb(0xe0, 0xaf, 0x68);
pub const CYAN: Color32 = Color32::from_rgb(0x7d, 0xcf, 0xff);

/// Colour for a port-state string (`open`, `closed`, `filtered`, …).
pub fn state_color(state: &str) -> Color32 {
    match state {
        s if s.starts_with("open") => GREEN,
        s if s.contains("filtered") => ORANGE,
        "closed" => RED,
        _ => TEXT_DIM,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum Theme {
    Light,
    #[default]
    Dark,
    System,
}

impl Theme {
    /// Apply both the colour visuals and the spacing/rounding/font style.
    pub fn apply(self, ctx: &egui::Context) {
        use egui::{FontFamily, FontId, TextStyle};
        let mut style = (*ctx.style()).clone();
        style.visuals = self.visuals();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.menu_margin = Margin::same(8.0);
        style.spacing.window_margin = Margin::same(10.0);
        style.spacing.interact_size.y = 26.0;
        style.spacing.scroll.bar_width = 9.0;
        style.text_styles = [
            (TextStyle::Heading, FontId::new(19.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.5, FontFamily::Monospace)),
            (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        ]
        .into();
        ctx.set_style(style);
    }

    pub fn visuals(self) -> egui::Visuals {
        match self {
            Theme::Light => light_visuals(),
            _ => dark_visuals(),
        }
    }
}

fn dark_visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    let r = Rounding::same(7.0);
    v.panel_fill = BG;
    v.window_fill = BG_CARD;
    v.window_rounding = Rounding::same(11.0);
    v.window_stroke = Stroke::new(1.0, Color32::from_rgb(0x2a, 0x2e, 0x44));
    v.extreme_bg_color = BG_PANEL;
    v.faint_bg_color = Color32::from_rgb(0x20, 0x24, 0x36);
    v.code_bg_color = BG_PANEL;
    v.override_text_color = Some(TEXT);
    v.hyperlink_color = ACCENT;
    v.selection.bg_fill = Color32::from_rgb(0x33, 0x46, 0x7c);
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = BG;
    w.noninteractive.rounding = r;
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
    w.inactive.bg_fill = BG_WIDGET;
    w.inactive.weak_bg_fill = BG_WIDGET;
    w.inactive.rounding = r;
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    w.hovered.bg_fill = BG_HOVER;
    w.hovered.weak_bg_fill = BG_HOVER;
    w.hovered.rounding = r;
    w.hovered.fg_stroke = Stroke::new(1.4, Color32::WHITE);
    w.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.bg_fill = ACCENT;
    w.active.weak_bg_fill = ACCENT;
    w.active.rounding = r;
    w.active.fg_stroke = Stroke::new(1.5, Color32::BLACK);
    v
}

fn light_visuals() -> egui::Visuals {
    let mut v = egui::Visuals::light();
    let r = Rounding::same(7.0);
    v.panel_fill = Color32::from_rgb(0xf4, 0xf5, 0xfa);
    v.window_rounding = Rounding::same(11.0);
    v.window_fill = Color32::WHITE;
    v.extreme_bg_color = Color32::from_rgb(0xea, 0xec, 0xf4);
    v.selection.bg_fill = Color32::from_rgb(0xbe, 0xd2, 0xff);
    let w = &mut v.widgets;
    for ws in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        ws.rounding = r;
    }
    v
}
