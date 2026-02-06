//! Light / dark / system theming persisted via eframe's storage.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum Theme {
    Light,
    #[default]
    Dark,
    System,
}

impl Theme {
    pub fn visuals(self) -> egui::Visuals {
        match self {
            Theme::Light => egui::Visuals::light(),
            Theme::Dark => egui::Visuals::dark(),
            Theme::System => egui::Visuals::dark(),
        }
    }
}
