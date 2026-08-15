#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod p2p;
mod ui;

pub use protonet::{identity, network, protocol, signature, storage};

use app::ProtonetApp;
use eframe::NativeOptions;
use egui::ViewportBuilder;
use p2p::P2pEngine;
use signature::SharedSignatureDb;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

fn main() -> eframe::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let network_config = crate::network::NetworkConfig::production_default()
        .expect("Failed to resolve Protonet application data paths");
    let shared_db = SharedSignatureDb::new(network_config.database_path.clone());
    let (event_tx, event_rx) = P2pEngine::event_channel();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to initialize Tokio runtime");

    let p2p_handle = rt
        .block_on(async { P2pEngine::spawn(network_config, shared_db.clone(), event_tx).await })
        .expect("Failed to start secure P2P engine");
    info!(
        "Protonet secure P2P identity: {}",
        p2p_handle
            .local_peer_id()
            .map(|peer| peer.to_string())
            .unwrap_or_else(|| "initializing".to_owned())
    );

    let native_options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_title("Protonet")
            .with_inner_size([1100.0, 750.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(crate::ui::get_app_icon()),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
            present_mode: eframe::egui_wgpu::wgpu::PresentMode::AutoVsync,
            desired_maximum_frame_latency: Some(2),
            ..Default::default()
        },
        ..Default::default()
    };

    eframe::run_native(
        "protonet",
        native_options,
        Box::new(|cc| {
            let app = ProtonetApp::new(cc, p2p_handle, shared_db, event_rx);
            Box::new(app)
        }),
    )
}
