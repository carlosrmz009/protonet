#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod p2p;
mod signature;
mod ui;

use app::ProtonetApp;
use eframe::NativeOptions;
use egui::ViewportBuilder;
use p2p::{P2pEngine, P2pEvent};
use signature::SharedSignatureDb;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

fn main() -> eframe::Result<()> {
    // 1. Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // 2. Generate untraceable ephemeral cryptographic Node ID (RFC 8439 / zero metadata leakage)
    let node_id = crate::p2p::ProtonetCrypto::generate_ephemeral_id();
    info!(
        "Initializing Protonet Maximum Security True-P2P Node: {}",
        node_id
    );

    // 3. Initialize signature database
    let db_path = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("protonet_signatures.json");
    let shared_db = SharedSignatureDb::new(db_path);

    // 4. Create async channel for P2P -> GUI event notifications
    let (event_tx, event_rx) = mpsc::unbounded_channel::<P2pEvent>();

    // 5. Build Tokio runtime and spawn P2P Engine
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to initialize Tokio runtime");

    let p2p_handle = rt
        .block_on(async { P2pEngine::spawn(node_id.clone(), shared_db.clone(), event_tx).await })
        .expect("Failed to bind P2P engine");

    // 6. Launch Native Windows eframe Application
    let native_options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_title("Protonet")
            .with_inner_size([1100.0, 750.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(crate::ui::get_app_icon()),
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
