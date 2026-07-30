use crate::p2p::{P2pCommand, P2pHandle};
use crate::signature::{compute_file_hashes_and_meta, FileSignature, SharedSignatureDb};
use crate::ui::theme::ThemeColors;
use egui::{Color32, Frame, RichText, Rounding, Stroke, Vec2};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Default)]
pub struct ScannerState {
    pub last_scanned_file: Option<PathBuf>,
    pub last_action_msg: Option<String>,
    pub is_last_flagged_by_us: bool,
}

#[allow(dead_code)]
pub fn render_scanner_panel(
    ui: &mut egui::Ui,
    shared_db: &SharedSignatureDb,
    p2p_handle: &P2pHandle,
    state: &mut ScannerState,
    active_threat_alert: &mut Option<FileSignature>,
) {
    ui.vertical(|ui| {
        let banner_frame = Frame::none()
            .fill(ThemeColors::BG_ELEVATED)
            .stroke(Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED))
            .rounding(Rounding::same(8.0))
            .inner_margin(20.0);

        banner_frame.show(ui, |ui| {
            ui.heading(
                RichText::new("protonet file scanner")
                    .strong()
                    .size(22.0)
                    .color(Color32::WHITE),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Pick any file to generate its signature, flag it, and broadcast across the network.")
                    .color(ThemeColors::TEXT_MUTED)
                    .size(14.0),
            );
        });

        ui.add_space(24.0);

        ui.horizontal(|ui| {
            let btn_size = Vec2::new(190.0, 42.0);

            let choose_btn = egui::Button::new(
                RichText::new("📂 Choose File...")
                    .strong()
                    .size(15.0)
                    .color(Color32::WHITE),
            )
            .fill(ThemeColors::ACCENT_CYAN.linear_multiply(0.8))
            .rounding(Rounding::same(6.0))
            .min_size(btn_size);

            if ui.add_sized(btn_size, choose_btn).clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    let mut dummy_logs = Vec::new();
                    handle_file_chosen(
                        path,
                        shared_db,
                        p2p_handle,
                        state,
                        active_threat_alert,
                        &mut dummy_logs,
                    );
                }
            }

            ui.add_space(12.0);

            let demo_btn_size = Vec2::new(230.0, 42.0);
            let demo_btn = egui::Button::new(
                RichText::new("🛠 Create Sample Threat File (Demo)")
                    .size(13.0)
                    .color(ThemeColors::TEXT_PRIMARY),
            )
            .fill(ThemeColors::BG_CARD)
            .stroke(Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED))
            .rounding(Rounding::same(6.0))
            .min_size(demo_btn_size);

            if ui.add_sized(demo_btn_size, demo_btn).clicked() {
                let mut dummy_logs = Vec::new();
                create_sample_threat_file(state, &mut dummy_logs);
            }
        });

        ui.add_space(30.0);

        if let Some(msg) = &state.last_action_msg {
            let status_color = if state.is_last_flagged_by_us {
                ThemeColors::ACCENT_EMERALD
            } else {
                ThemeColors::ACCENT_CYAN
            };

            let card_frame = Frame::none()
                .fill(ThemeColors::BG_CARD)
                .stroke(Stroke::new(1.5_f32, status_color))
                .rounding(Rounding::same(8.0))
                .inner_margin(18.0);

            card_frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("✔ NETWORK STATUS:")
                            .strong()
                            .size(14.0)
                            .color(status_color),
                    );
                    ui.label(
                        RichText::new(msg)
                            .strong()
                            .size(14.0)
                            .color(Color32::WHITE),
                    );
                });
            });
        }
    });
}

pub fn handle_file_chosen(
    path: PathBuf,
    shared_db: &SharedSignatureDb,
    p2p_handle: &P2pHandle,
    state: &mut ScannerState,
    active_threat_alert: &mut Option<FileSignature>,
    logs: &mut Vec<String>,
) {
    state.last_scanned_file = Some(path.clone());

    let (sha256, blake3, file_name, size) = match compute_file_hashes_and_meta(&path) {
        Ok(res) => res,
        Err(e) => {
            let msg = format!("error hashing file: {}", e);
            state.last_action_msg = Some(msg.clone());
            logs.push(format!("sys  :: {}", msg));
            state.is_last_flagged_by_us = false;
            return;
        }
    };
    let hash_hex = crate::signature::hasher::hex(&blake3);

    logs.push(format!("scan :: checking file '{}'", file_name));
    logs.push(format!("hash :: blake3={}", hash_hex));

    if let Some(existing_sig) = shared_db.is_flagged(&hash_hex) {
        *active_threat_alert = Some(existing_sig.clone());
        let msg = format!(
            "file '{}' matched FLAGGED threat signature from peer {}!",
            file_name, existing_sig.flagged_by_peer
        );
        state.last_action_msg = Some(msg.clone());
        logs.push(format!(
            "alert:: flagged match detected! by {}",
            existing_sig.flagged_by_peer
        ));
        state.is_last_flagged_by_us = false;
    } else {
        match p2p_handle.cmd_tx.try_send(P2pCommand::PublishFile {
            sha256,
            blake3,
            file_size: size,
            file_name: Some(file_name.clone()),
        }) {
            Ok(()) => {
                let msg = format!(
                    "tagged '{}' as FLAGGED! blake3 signature broadcasted to {} peers.",
                    file_name,
                    p2p_handle.peer_count()
                );
                state.last_action_msg = Some(msg.clone());
                logs.push(format!("p2p  :: {}", msg));
                state.is_last_flagged_by_us = true;
            }
            Err(e) => {
                let msg = format!("failed to queue signed record: {}", e);
                state.last_action_msg = Some(msg.clone());
                logs.push(format!("sys  :: {}", msg));
                state.is_last_flagged_by_us = false;
            }
        }
    }
}

pub fn create_sample_threat_file(state: &mut ScannerState, logs: &mut Vec<String>) {
    let demo_path = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("sample_threat.bin");

    match File::create(&demo_path) {
        Ok(mut f) => {
            let payload = b"PROTONET-TRUE-P2P-DEMONSTRATION-THREAT-PAYLOAD-V1\n";
            if let Err(e) = f.write_all(payload) {
                let msg = format!("failed to write demo file: {}", e);
                state.last_action_msg = Some(msg.clone());
                logs.push(format!("sys  :: {}", msg));
            } else {
                let msg = format!("created demo file at {}", demo_path.display());
                state.last_action_msg = Some(msg.clone());
                logs.push(format!("demo :: {}", msg));
                state.is_last_flagged_by_us = false;
            }
        }
        Err(e) => {
            let msg = format!("failed to create demo file: {}", e);
            state.last_action_msg = Some(msg.clone());
            logs.push(format!("sys  :: {}", msg));
        }
    }
}
