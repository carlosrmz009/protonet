pub mod network_panel;
pub mod red_alert;
pub mod scanner_panel;
pub mod theme;
pub mod topology;

#[allow(unused_imports)]
pub use network_panel::{render_network_panel, NetworkState};
#[allow(unused_imports)]
pub use red_alert::render_red_alert_screen;
#[allow(unused_imports)]
pub use scanner_panel::{
    create_sample_threat_file, handle_file_chosen, render_scanner_panel, ScannerState,
};
#[allow(unused_imports)]
pub use theme::{apply_theme, setup_fonts, ThemeColors};
#[allow(unused_imports)]
pub use topology::{render_topology_window, TopologyState};

pub fn get_app_icon() -> std::sync::Arc<egui::IconData> {
    let icon_png = include_bytes!("../../starchild.png");
    let icon_image = image::load_from_memory(icon_png)
        .expect("Failed to load starchild.png icon")
        .to_rgba8();
    let (icon_w, icon_h) = (icon_image.width(), icon_image.height());
    std::sync::Arc::new(egui::IconData {
        rgba: icon_image.into_raw(),
        width: icon_w,
        height: icon_h,
    })
}
