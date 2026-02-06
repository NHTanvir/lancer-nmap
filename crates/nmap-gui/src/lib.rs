//! nmap-gui — the eframe / egui front-end for lancer-nmap.

pub mod app;
pub mod panels;
pub mod state;
pub mod theme;

pub use app::App;

/// Open the GUI window. Blocking until the user quits.
pub fn launch() -> anyhow::Result<()> {
    use eframe::egui::ViewportBuilder;
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("lancer-nmap"),
        persist_window: true,
        ..Default::default()
    };
    eframe::run_native(
        "lancer-nmap",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe failed: {e}"))?;
    Ok(())
}
