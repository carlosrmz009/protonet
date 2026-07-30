use crate::p2p::{P2pEvent, P2pHandle};
use crate::signature::{FileSignature, SharedSignatureDb};
use crate::ui::{
    apply_theme, handle_file_chosen, render_red_alert_screen, NetworkState, ScannerState,
    ThemeColors,
};
use eframe::App;
use egui::{Align, Color32, Frame, Layout, RichText, Rounding, Stroke, Vec2};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTab {
    Scanner,
    ManageSignatures,
}

pub struct ProtonetApp {
    p2p_handle: P2pHandle,
    shared_db: SharedSignatureDb,
    event_rx: mpsc::Receiver<P2pEvent>,
    scanner_state: ScannerState,
    network_state: NetworkState,
    pub active_threat_alert: Option<FileSignature>,
    pub show_peers_window: bool,
    pub topology_state: crate::ui::TopologyState,
    pub active_tab: AppTab,
    pub show_reset_identity_confirmation: bool,
}

impl ProtonetApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        p2p_handle: P2pHandle,
        shared_db: SharedSignatureDb,
        event_rx: mpsc::Receiver<P2pEvent>,
    ) -> Self {
        apply_theme(&cc.egui_ctx);

        let mut network_state = NetworkState::default();
        network_state.push_log(format!(
            "sys  :: protonet v0.1.0 ({})",
            p2p_handle
                .local_peer_id()
                .map(|peer| peer.to_string())
                .unwrap_or_else(|| "initializing".to_owned())
        ));
        network_state.push_log("lock :: encrypted transport active".to_string());
        network_state
            .push_log("net  :: QUIC preferred; Noise/TCP and encrypted relay fallback".to_owned());
        network_state.push_log(format!(
            "db   :: {} flagged signatures loaded",
            shared_db.count()
        ));
        network_state.push_log("ready!".to_string());

        Self {
            p2p_handle,
            shared_db,
            event_rx,
            scanner_state: ScannerState::default(),
            network_state,
            active_threat_alert: None,
            show_peers_window: true,
            topology_state: crate::ui::TopologyState::default(),
            active_tab: AppTab::Scanner,
            show_reset_identity_confirmation: false,
        }
    }

    fn poll_p2p_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                P2pEvent::Started { peer_id } => {
                    self.network_state.push_log(format!("id   :: {}", peer_id));
                }
                P2pEvent::IdentityReset { peer_id } => {
                    self.network_state
                        .push_log(format!("id   :: identity reset to {}", peer_id));
                }
                P2pEvent::Listening { address } => {
                    self.network_state.push_log(format!("listen:: {}", address));
                }
                P2pEvent::PeerConnected {
                    peer_id,
                    address,
                    directness,
                    transport,
                } => {
                    self.network_state.push_log(format!(
                        "p2p  :: + {} at {} ({:?}, {:?})",
                        peer_id, address, directness, transport
                    ));
                }
                P2pEvent::PeerDisconnected { peer_id } => {
                    self.network_state
                        .push_log(format!("p2p  :: - {}", peer_id));
                }
                P2pEvent::RecordReceived {
                    record_id,
                    from,
                    file_name,
                } => {
                    self.network_state.push_log(format!(
                        "recv :: '{}' [{}] from {}",
                        file_name.unwrap_or_else(|| "unnamed file".to_owned()),
                        short_record_id(&record_id),
                        from
                    ));
                }
                P2pEvent::RecordPublished {
                    record_id,
                    file_name,
                } => self.network_state.push_log(format!(
                    "send :: '{}' [{}]",
                    file_name.unwrap_or_else(|| "unnamed file".to_owned()),
                    short_record_id(&record_id)
                )),
                P2pEvent::SyncStarted { peer_id } => self
                    .network_state
                    .push_log(format!("sync :: started with {}", peer_id)),
                P2pEvent::SyncProgress { peer_id, received } => self
                    .network_state
                    .push_log(format!("sync :: {} records from {}", received, peer_id)),
                P2pEvent::SyncCompleted { peer_id, received } => self.network_state.push_log(
                    format!("sync :: completed with {} ({} new)", peer_id, received),
                ),
                P2pEvent::ProtocolViolation { peer_id, reason } => {
                    self.network_state.push_log(format!(
                        "deny :: {}{}",
                        peer_id.map(|p| format!("{p}: ")).unwrap_or_default(),
                        reason
                    ))
                }
                P2pEvent::ReachabilityChanged { state } => self
                    .network_state
                    .push_log(format!("nat  :: reachability is {:?}", state)),
                P2pEvent::LogMessage(msg) => {
                    self.network_state.push_log(format!("log  :: {}", msg));
                }
            }
        }
    }
}

impl App for ProtonetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_p2p_events();

        if let Some(signature) = self.active_threat_alert.clone() {
            let mut on_dismiss = false;
            render_red_alert_screen(ctx, &signature, &mut on_dismiss);
            if on_dismiss {
                self.active_threat_alert = None;
            }
            return;
        }

        egui::CentralPanel::default()
            .frame(Frame::none().fill(ThemeColors::BG_MAIN).inner_margin(28.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("protonet v0.1.0")
                            .font(ThemeColors::font_bold(32.0))
                            .color(Color32::WHITE),
                    );

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "[peers: {} | flagged: {}]",
                                self.p2p_handle.peer_count(),
                                self.shared_db.count()
                            ))
                            .font(ThemeColors::font_regular(13.0))
                            .color(ThemeColors::TEXT_MUTED),
                        );

                        ui.add_space(16.0);

                        let topology_btn = egui::Button::new(
                            RichText::new("[peers]")
                                .font(ThemeColors::font_regular(13.0))
                                .color(if self.show_peers_window {
                                    ThemeColors::TEXT_PRIMARY
                                } else {
                                    ThemeColors::TEXT_MUTED
                                }),
                        )
                        .fill(ThemeColors::BG_CARD)
                        .frame(false);

                        if ui.add(topology_btn).clicked() {
                            self.show_peers_window = !self.show_peers_window;
                        }

                        ui.add_space(8.0);
                        if ui
                            .button(
                                RichText::new("[reset identity]")
                                    .font(ThemeColors::font_regular(12.0))
                                    .color(ThemeColors::ACCENT_DANGER),
                            )
                            .clicked()
                        {
                            self.show_reset_identity_confirmation = true;
                        }
                    });
                });

                ui.add_space(20.0);

                ui.horizontal(|ui| {
                    let scanner_btn = egui::Button::new(
                        RichText::new("🔍 THREAT SCANNER")
                            .font(ThemeColors::font_bold(14.0))
                            .color(if self.active_tab == AppTab::Scanner {
                                Color32::WHITE
                            } else {
                                ThemeColors::TEXT_MUTED
                            }),
                    )
                    .fill(if self.active_tab == AppTab::Scanner {
                        Color32::from_rgb(45, 45, 55)
                    } else {
                        ThemeColors::BG_CARD
                    })
                    .stroke(Stroke::new(
                        1.0_f32,
                        if self.active_tab == AppTab::Scanner {
                            ThemeColors::ACCENT_CYAN
                        } else {
                            ThemeColors::BORDER_MUTED
                        },
                    ))
                    .rounding(Rounding::same(6.0))
                    .min_size(Vec2::new(180.0, 36.0));

                    if ui.add(scanner_btn).clicked() {
                        self.active_tab = AppTab::Scanner;
                    }

                    ui.add_space(10.0);

                    let manage_btn = egui::Button::new(
                        RichText::new("🗑 MANAGE FLAGGED FILES")
                            .font(ThemeColors::font_bold(14.0))
                            .color(if self.active_tab == AppTab::ManageSignatures {
                                Color32::WHITE
                            } else {
                                ThemeColors::TEXT_MUTED
                            }),
                    )
                    .fill(if self.active_tab == AppTab::ManageSignatures {
                        Color32::from_rgb(45, 45, 55)
                    } else {
                        ThemeColors::BG_CARD
                    })
                    .stroke(Stroke::new(
                        1.0_f32,
                        if self.active_tab == AppTab::ManageSignatures {
                            ThemeColors::ACCENT_CYAN
                        } else {
                            ThemeColors::BORDER_MUTED
                        },
                    ))
                    .rounding(Rounding::same(6.0))
                    .min_size(Vec2::new(220.0, 36.0));

                    if ui.add(manage_btn).clicked() {
                        self.active_tab = AppTab::ManageSignatures;
                    }
                });

                ui.add_space(24.0);

                match self.active_tab {
                    AppTab::Scanner => {
                        let button_width = ui.available_width();
                        let choose_btn = egui::Button::new(
                            RichText::new("choose file...")
                                .font(ThemeColors::font_bold(36.0))
                                .color(Color32::BLACK),
                        )
                        .fill(ThemeColors::NEON_YELLOW)
                        .rounding(Rounding::same(28.0))
                        .min_size(Vec2::new(button_width, 140.0));

                        if ui.add(choose_btn).clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                handle_file_chosen(
                                    path,
                                    &self.shared_db,
                                    &self.p2p_handle,
                                    &mut self.scanner_state,
                                    &mut self.active_threat_alert,
                                    &mut self.network_state.gossip_logs,
                                );
                                let total_peers = self.p2p_handle.peer_count();
                                self.topology_state.trigger_broadcast(total_peers, ctx);
                            }
                        }

                        ui.add_space(24.0);

                        let log_box_frame = Frame::none()
                            .fill(ThemeColors::BG_LOG_BOX)
                            .inner_margin(24.0)
                            .rounding(Rounding::same(4.0));

                        log_box_frame.show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .stick_to_bottom(true)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    for log_line in &self.network_state.gossip_logs {
                                        ui.label(
                                            RichText::new(log_line)
                                                .font(ThemeColors::font_regular(16.0))
                                                .color(Color32::from_rgb(240, 240, 240)),
                                        );
                                        ui.add_space(4.0);
                                    }
                                });
                        });
                    }
                    AppTab::ManageSignatures => {
                        crate::ui::render_manage_signatures_tab(
                            ui,
                            &self.shared_db,
                            &mut self.network_state.gossip_logs,
                        );
                    }
                }
            });

        if self.show_peers_window {
            crate::ui::render_topology_window(
                ctx,
                &mut self.show_peers_window,
                &mut self.topology_state,
                &self.p2p_handle,
            );
        }

        if self.show_reset_identity_confirmation {
            egui::Window::new("Reset Protonet identity")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("This disconnects peers, creates a new PeerId, and clears replay/sequence state.");
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_reset_identity_confirmation = false;
                        }
                        if ui
                            .button(RichText::new("Reset identity").color(ThemeColors::ACCENT_DANGER))
                            .clicked()
                        {
                            let _ = self
                                .p2p_handle
                                .cmd_tx
                                .try_send(crate::p2p::P2pCommand::ResetIdentity);
                            self.show_reset_identity_confirmation = false;
                        }
                    });
                });
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

fn short_record_id(id: &[u8; 32]) -> String {
    id[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}
