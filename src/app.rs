use crate::p2p::{P2pEvent, P2pHandle};
use crate::signature::{FileSignature, SharedSignatureDb};
use crate::ui::{
    apply_theme, handle_file_chosen, render_red_alert_screen, NetworkState, ScannerState,
    ThemeColors,
};
use eframe::App;
use egui::{Align, Color32, Frame, Layout, RichText, Rounding, Vec2};
use tokio::sync::mpsc;

pub struct ProtonetApp {
    p2p_handle: P2pHandle,
    shared_db: SharedSignatureDb,
    event_rx: mpsc::UnboundedReceiver<P2pEvent>,
    scanner_state: ScannerState,
    network_state: NetworkState,
    pub active_threat_alert: Option<FileSignature>,
    pub show_peers_window: bool,
    pub topology_state: crate::ui::TopologyState,
}

impl ProtonetApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        p2p_handle: P2pHandle,
        shared_db: SharedSignatureDb,
        event_rx: mpsc::UnboundedReceiver<P2pEvent>,
    ) -> Self {
        apply_theme(&cc.egui_ctx);

        let mut network_state = NetworkState::default();
        network_state.gossip_logs.push(format!(
            "sys  :: protonet v0.1.0 ({})",
            p2p_handle.node_id
        ));
        network_state.gossip_logs.push(
            "lock :: encrypted transport active".to_string(),
        );
        network_state.gossip_logs.push(format!(
            "udp  :: discovery on port 7777"
        ));
        network_state.gossip_logs.push(format!(
            "tcp  :: listening on port {}",
            p2p_handle.listen_port
        ));
        network_state.gossip_logs.push(format!(
            "db   :: {} flagged signatures loaded",
            shared_db.count()
        ));
        network_state.gossip_logs.push(
            "ready!".to_string(),
        );

        Self {
            p2p_handle,
            shared_db,
            event_rx,
            scanner_state: ScannerState::default(),
            network_state,
            active_threat_alert: None,
            show_peers_window: true,
            topology_state: crate::ui::TopologyState::default(),
        }
    }

    fn poll_p2p_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                P2pEvent::PeerConnected { addr, node_id } => {
                    self.network_state
                        .gossip_logs
                        .push(format!("p2p  :: + connected to peer {} ({})", node_id, addr));
                }
                P2pEvent::PeerDisconnected { addr } => {
                    self.network_state
                        .gossip_logs
                        .push(format!("p2p  :: - peer disconnected: {}", addr));
                }
                P2pEvent::GossipReceived {
                    signature,
                    origin_node,
                } => {
                    self.network_state.gossip_logs.push(format!(
                        "recv :: '{}' flagged by {}",
                        signature.file_name, origin_node
                    ));
                }
                P2pEvent::SyncCompleted {
                    new_signatures_count,
                } => {
                    self.network_state.gossip_logs.push(format!(
                        "sync :: {} new signatures synced",
                        new_signatures_count
                    ));
                }
                P2pEvent::LogMessage(msg) => {
                    self.network_state.gossip_logs.push(format!("log  :: {}", msg));
                }
            }
        }
    }
}

impl App for ProtonetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_p2p_events();

        // 1. Check if we have an ACTIVE FLAGGED THREAT ALERT
        if let Some(signature) = self.active_threat_alert.clone() {
            let mut on_dismiss = false;
            render_red_alert_screen(ctx, &signature, &mut on_dismiss);
            if on_dismiss {
                self.active_threat_alert = None;
            }
            return;
        }

        // 2. Main Retro-Hacker JetBrains Mono Interface
        egui::CentralPanel::default()
            .frame(
                Frame::none()
                    .fill(ThemeColors::BG_MAIN)
                    .inner_margin(28.0),
            )
            .show(ctx, |ui| {
                // --- Top Header Row ---
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("protonet v0.1.0")
                            .font(ThemeColors::font_bold(32.0))
                            .color(Color32::WHITE),
                    );

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        // Status info badge on the far right
                        ui.label(
                            RichText::new(&format!(
                                "[peers: {} | flagged: {}]",
                                self.p2p_handle.peer_count(),
                                self.shared_db.count()
                            ))
                            .font(ThemeColors::font_regular(13.0))
                            .color(ThemeColors::TEXT_MUTED),
                        );

                        ui.add_space(16.0);

                        // Peers Window Toggle
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
                    });
                });

                ui.add_space(28.0);

                // --- The Huge Neon Yellow Action Button ---
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
                        self.topology_state.trigger_broadcast(total_peers);
                    }
                }

                ui.add_space(24.0);

                // --- The Charcoal Grey Log Text Box ---
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
            });

        if self.show_peers_window {
            crate::ui::render_topology_window(
                ctx,
                &mut self.show_peers_window,
                &mut self.topology_state,
                &self.p2p_handle,
            );
        }

        // Repaint periodically so UI updates instantly when P2P events arrive
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
