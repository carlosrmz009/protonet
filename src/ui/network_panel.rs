use crate::p2p::{P2pCommand, P2pHandle};
use crate::signature::SharedSignatureDb;
use crate::ui::theme::ThemeColors;
use egui::{Color32, Frame, RichText, Rounding, Stroke};
use std::net::SocketAddr;

#[allow(dead_code)]
pub struct NetworkState {
    pub remote_peer_input: String,
    pub connect_error: Option<String>,
    pub gossip_logs: Vec<String>,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self {
            remote_peer_input: String::new(),
            connect_error: None,
            gossip_logs: Vec::new(),
        }
    }
}

#[allow(dead_code)]
pub fn render_network_panel(
    ui: &mut egui::Ui,
    shared_db: &SharedSignatureDb,
    p2p_handle: &P2pHandle,
    state: &mut NetworkState,
) {
    ui.vertical(|ui| {
        // 1. Top WAN / Remote Peer Connection Bar
        let connect_frame = Frame::none()
            .fill(ThemeColors::BG_CARD)
            .stroke(Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED))
            .rounding(Rounding::same(8.0))
            .inner_margin(16.0);

        connect_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("🌐  CONNECT TO REMOTE PEER (IP:PORT):")
                        .strong()
                        .size(14.0)
                        .color(ThemeColors::TEXT_PRIMARY),
                );

                ui.add_space(8.0);

                let text_edit = egui::TextEdit::singleline(&mut state.remote_peer_input)
                    .desired_width(180.0)
                    .text_color(Color32::WHITE);
                ui.add(text_edit);

                if ui
                    .button(RichText::new("Connect Peer").strong().size(13.0))
                    .clicked()
                {
                    match state.remote_peer_input.trim().parse::<SocketAddr>() {
                        Ok(addr) => {
                            let _ = p2p_handle.cmd_tx.try_send(P2pCommand::ConnectRemote(addr));
                            state.connect_error = None;
                        }
                        Err(_) => {
                            state.connect_error =
                                Some("Invalid SocketAddr format. Example: 127.0.0.1:7778".to_string());
                        }
                    }
                }

                ui.add_space(16.0);

                if ui
                    .button(RichText::new("⚡ Force Sync DB").size(13.0))
                    .clicked()
                {
                    let _ = p2p_handle.cmd_tx.try_send(P2pCommand::RequestSync);
                }
            });

            if let Some(err) = &state.connect_error {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(err)
                        .size(12.0)
                        .color(ThemeColors::ACCENT_DANGER),
                );
            }
        });

        ui.add_space(20.0);

        // 2. Split view: Connected Peers Table (Left) & Active Flagged Signatures Ledger (Right)
        ui.columns(2, |cols| {
            // Left column: Connected Peers
            cols[0].vertical(|ui| {
                let frame = Frame::none()
                    .fill(ThemeColors::BG_CARD)
                    .stroke(Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(16.0);

                frame.show(ui, |ui| {
                    ui.heading(
                        RichText::new("CONNECTED P2P PEERS")
                            .strong()
                            .size(16.0)
                            .color(Color32::WHITE),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Nodes connected via LAN Broadcast or WAN TCP")
                            .size(12.0)
                            .color(ThemeColors::TEXT_MUTED),
                    );
                    ui.add_space(12.0);

                    let peers = p2p_handle.get_peers_info();
                    if peers.is_empty() {
                        ui.label(
                            RichText::new("No active peers. Open another instance on LAN or connect via IP:PORT.")
                                .italics()
                                .size(13.0)
                                .color(ThemeColors::TEXT_MUTED),
                        );
                    } else {
                        for (addr, node_id) in peers {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("🟢")
                                        .size(10.0)
                                        .color(ThemeColors::ACCENT_EMERALD),
                                );
                                ui.label(
                                    RichText::new(format!("{:<15}", node_id))
                                        .strong()
                                        .size(13.0)
                                        .color(Color32::WHITE),
                                );
                                ui.label(
                                    RichText::new(addr.to_string())
                                        .monospace()
                                        .size(12.0)
                                        .color(ThemeColors::TEXT_MUTED),
                                );
                            });
                            ui.add_space(4.0);
                        }
                    }
                });
            });

            // Right column: Synced Signatures Ledger
            cols[1].vertical(|ui| {
                let frame = Frame::none()
                    .fill(ThemeColors::BG_CARD)
                    .stroke(Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(16.0);

                frame.show(ui, |ui| {
                    ui.heading(
                        RichText::new("NETWORK FLAGGED SIGNATURES LEDGER")
                            .strong()
                            .size(16.0)
                            .color(Color32::WHITE),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "{} verified threat signatures synchronized across Protonet",
                            shared_db.count()
                        ))
                        .size(12.0)
                        .color(ThemeColors::ACCENT_CYAN),
                    );
                    ui.add_space(12.0);

                    let signatures = shared_db.get_all_signatures();
                    if signatures.is_empty() {
                        ui.label(
                            RichText::new("No files flagged yet. Use 'Choose file...' to generate signatures.")
                                .italics()
                                .size(13.0)
                                .color(ThemeColors::TEXT_MUTED),
                        );
                    } else {
                        egui::ScrollArea::vertical()
                            .max_height(160.0)
                            .show(ui, |ui| {
                                for sig in signatures {
                                    let item_frame = Frame::none()
                                        .fill(ThemeColors::BG_MAIN)
                                        .rounding(Rounding::same(4.0))
                                        .inner_margin(8.0);
                                    item_frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                RichText::new("🚩")
                                                    .size(12.0)
                                                    .color(ThemeColors::ACCENT_DANGER),
                                            );
                                            ui.label(
                                                RichText::new(&sig.file_name)
                                                    .strong()
                                                    .size(13.0)
                                                    .color(Color32::WHITE),
                                            );
                                            ui.label(
                                                RichText::new(format!(
                                                    "[{}]",
                                                    &sig.blake3_hash[0..8]
                                                ))
                                                .monospace()
                                                .size(11.0)
                                                .color(ThemeColors::ACCENT_DANGER),
                                            );
                                            ui.label(
                                                RichText::new(format!("by {}", sig.flagged_by_peer))
                                                    .size(11.0)
                                                    .color(ThemeColors::TEXT_MUTED),
                                            );
                                        });
                                    });
                                    ui.add_space(4.0);
                                }
                            });
                    }
                });
            });
        });

        ui.add_space(20.0);

        // 3. Real-Time P2P Gossip Event Log
        let log_frame = Frame::none()
            .fill(ThemeColors::BG_CARD)
            .stroke(Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED))
            .rounding(Rounding::same(8.0))
            .inner_margin(16.0);

        log_frame.show(ui, |ui| {
            ui.heading(
                RichText::new("📡  P2P GOSSIP & NETWORK ACTIVITY LOG")
                    .strong()
                    .size(14.0)
                    .color(ThemeColors::TEXT_PRIMARY),
            );
            ui.add_space(8.0);

            egui::ScrollArea::vertical()
                .max_height(140.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if state.gossip_logs.is_empty() {
                        ui.label(
                            RichText::new("Waiting for network events or gossip broadcasts...")
                                .italics()
                                .size(12.0)
                                .color(ThemeColors::TEXT_MUTED),
                        );
                    } else {
                        for log_msg in &state.gossip_logs {
                            ui.label(
                                RichText::new(format!("> {}", log_msg))
                                    .monospace()
                                    .size(12.0)
                                    .color(ThemeColors::TEXT_PRIMARY),
                            );
                        }
                    }
                });
        });
    });
}
