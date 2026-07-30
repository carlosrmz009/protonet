use crate::network::connection_manager::{Directness, TransportKind};
use crate::p2p::P2pHandle;
use crate::ui::ThemeColors;
use egui::{
    Align2, Color32, Pos2, RichText, Stroke, TextureHandle, TextureOptions, Vec2, ViewportBuilder,
    ViewportClass, ViewportId,
};

pub struct BroadcastAnim {
    pub peer_index: usize,
    pub progress: f32,
    pub speed: f32,
}

#[derive(Default)]
pub struct TopologyState {
    pub texture: Option<TextureHandle>,
    pub active_animations: Vec<BroadcastAnim>,
}

impl TopologyState {
    pub fn get_or_load_texture(&mut self, ctx: &egui::Context) -> TextureHandle {
        if let Some(texture) = &self.texture {
            return texture.clone();
        }
        let png_bytes =
            std::fs::read("peer.png").unwrap_or_else(|_| include_bytes!("../../peer.png").to_vec());
        let image = image::load_from_memory(&png_bytes)
            .expect("Failed to load peer.png")
            .to_rgba8();
        let size = [image.width() as _, image.height() as _];
        let pixels = image.as_flat_samples();
        let handle = ctx.load_texture(
            "peer_logo",
            egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice()),
            TextureOptions::LINEAR,
        );
        self.texture = Some(handle.clone());
        handle
    }

    pub fn trigger_broadcast(&mut self, total_peers: usize, ctx: &egui::Context) {
        for peer_index in 0..total_peers.max(1) {
            self.active_animations.push(BroadcastAnim {
                peer_index,
                progress: 0.0,
                speed: 0.75,
            });
        }
        ctx.request_repaint();
    }
}

pub fn render_topology_window(
    ctx: &egui::Context,
    open: &mut bool,
    state: &mut TopologyState,
    p2p_handle: &P2pHandle,
) {
    let texture = state.get_or_load_texture(ctx);
    let snapshot = p2p_handle.snapshot();
    let viewport_id = ViewportId::from_hash_of("peers_topology_window");
    let viewport_builder = ViewportBuilder::default()
        .with_title("Protonet network")
        .with_inner_size([880.0, 720.0])
        .with_min_inner_size([650.0, 500.0])
        .with_icon(crate::ui::get_app_icon());

    ctx.show_viewport_immediate(viewport_id, viewport_builder, move |ctx, class| {
        if class == ViewportClass::Immediate
            && ctx.input(|input| input.viewport().close_requested())
        {
            *open = false;
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(ThemeColors::BG_MAIN)
                    .inner_margin(16.0),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let connected = !snapshot.peers.is_empty();
                        ui.label(
                            RichText::new(if connected { "● LIVE" } else { "○ WAITING" })
                                .font(ThemeColors::font_bold(14.0))
                                .color(if connected {
                                    ThemeColors::ACCENT_EMERALD
                                } else {
                                    ThemeColors::TEXT_MUTED
                                }),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(format!(
                                "Peer ID: {}",
                                snapshot
                                    .local_peer_id
                                    .map(|peer| peer.to_string())
                                    .unwrap_or_else(|| "initializing".to_owned())
                            ))
                            .monospace()
                            .color(ThemeColors::ACCENT_CYAN),
                        );
                    });
                    ui.add_space(10.0);

                    egui::Grid::new("network_summary")
                        .num_columns(4)
                        .spacing([16.0, 6.0])
                        .show(ui, |ui| {
                            stat(ui, "Reachability", &format!("{:?}", snapshot.reachability));
                            stat(ui, "DHT", &snapshot.dht_status);
                            stat(ui, "Gossip mesh", &snapshot.gossipsub_mesh_size.to_string());
                            stat(ui, "Connected", &snapshot.peers.len().to_string());
                            ui.end_row();
                            stat(
                                ui,
                                "Database",
                                &format!("{} records", snapshot.database_records),
                            );
                            stat(
                                ui,
                                "Persistence queue",
                                &snapshot.persistence_queue_depth.to_string(),
                            );
                            stat(ui, "Replay cache", &snapshot.replay_cache_size.to_string());
                            stat(
                                ui,
                                "CPU / memory",
                                &format!(
                                    "{:.1}% / {} MiB",
                                    snapshot.metrics.process_cpu_percent,
                                    snapshot.metrics.process_memory_bytes / (1024 * 1024)
                                ),
                            );
                            ui.end_row();
                            stat(
                                ui,
                                "Sent / received",
                                &format!(
                                    "{} / {}",
                                    snapshot.metrics.records_sent,
                                    snapshot.metrics.records_received
                                ),
                            );
                            stat(
                                ui,
                                "Duplicates / invalid",
                                &format!(
                                    "{} / {}",
                                    snapshot.metrics.duplicates_ignored,
                                    snapshot.metrics.invalid_rejected
                                ),
                            );
                            stat(
                                ui,
                                "Validation P50/95/99",
                                &format!(
                                    "{} / {} / {} us",
                                    snapshot.metrics.validation_p50_us,
                                    snapshot.metrics.validation_p95_us,
                                    snapshot.metrics.validation_p99_us
                                ),
                            );
                            stat(
                                ui,
                                "Persistence P50/95/99",
                                &format!(
                                    "{} / {} / {} us",
                                    snapshot.metrics.persistence_p50_us,
                                    snapshot.metrics.persistence_p95_us,
                                    snapshot.metrics.persistence_p99_us
                                ),
                            );
                            ui.end_row();
                            stat(
                                ui,
                                "Propagation P50/95/99",
                                &format!(
                                    "{} / {} / {} us",
                                    snapshot.metrics.propagation_p50_us,
                                    snapshot.metrics.propagation_p95_us,
                                    snapshot.metrics.propagation_p99_us
                                ),
                            );
                            stat(
                                ui,
                                "Upload / download",
                                &format!(
                                    "{} / {} B/s",
                                    snapshot.metrics.upload_bytes_per_second,
                                    snapshot.metrics.download_bytes_per_second
                                ),
                            );
                            ui.end_row();
                        });

                    ui.add_space(12.0);
                    ui.label(
                        RichText::new("LISTEN ADDRESSES")
                            .font(ThemeColors::font_bold(13.0))
                            .color(Color32::WHITE),
                    );
                    if snapshot.listen_addresses.is_empty() {
                        ui.label(RichText::new("initializing").color(ThemeColors::TEXT_MUTED));
                    } else {
                        for address in &snapshot.listen_addresses {
                            ui.label(RichText::new(address.to_string()).monospace().size(11.0));
                        }
                    }

                    ui.add_space(14.0);
                    ui.label(
                        RichText::new("AUTHENTICATED PEERS")
                            .font(ThemeColors::font_bold(13.0))
                            .color(Color32::WHITE),
                    );
                    egui::Grid::new("peer_table")
                        .striped(true)
                        .min_col_width(100.0)
                        .show(ui, |ui| {
                            for heading in [
                                "Peer ID",
                                "Connection",
                                "Transport",
                                "RTT",
                                "Records",
                                "Address",
                            ] {
                                ui.label(RichText::new(heading).strong());
                            }
                            ui.end_row();
                            for peer in &snapshot.peers {
                                ui.label(
                                    RichText::new(short_peer(&peer.peer_id.to_string()))
                                        .monospace(),
                                );
                                ui.label(match peer.directness {
                                    Directness::Direct => "Direct",
                                    Directness::Relayed => "Relayed",
                                });
                                ui.label(match peer.transport {
                                    TransportKind::Quic => "QUIC",
                                    TransportKind::TcpNoiseYamux => "TCP + Noise",
                                    TransportKind::CircuitRelay => "Circuit relay",
                                    TransportKind::Unknown => "Unknown",
                                });
                                ui.label(
                                    peer.round_trip_time
                                        .map(|rtt| format!("{} ms", rtt.as_millis()))
                                        .unwrap_or_else(|| "—".to_owned()),
                                );
                                ui.label(peer.records_received.to_string());
                                ui.label(
                                    RichText::new(peer.address.to_string())
                                        .monospace()
                                        .size(10.0),
                                );
                                ui.end_row();
                            }
                        });

                    ui.add_space(16.0);
                    draw_topology(ui, ctx, state, &texture, &snapshot);
                });
            });
    });
}

fn stat(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.label(
            RichText::new(label)
                .size(10.0)
                .color(ThemeColors::TEXT_MUTED),
        );
        ui.label(
            RichText::new(value)
                .size(12.0)
                .color(ThemeColors::TEXT_PRIMARY),
        );
    });
}

fn short_peer(peer: &str) -> String {
    if peer.len() > 16 {
        format!("{}…{}", &peer[..9], &peer[peer.len() - 5..])
    } else {
        peer.to_owned()
    }
}

fn draw_topology(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut TopologyState,
    texture: &TextureHandle,
    snapshot: &crate::network::NetworkSnapshot,
) {
    let canvas_size = Vec2::new(ui.available_width(), 340.0);
    let (rect, _) = ui.allocate_exact_size(canvas_size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 8.0, Color32::WHITE);
    painter.rect_stroke(rect, 8.0, Stroke::new(1.0_f32, Color32::from_gray(200)));
    let center = rect.center();
    let radius = 125.0_f32.min(rect.width() * 0.32);
    let mut peer_positions = Vec::new();
    for (index, peer) in snapshot.peers.iter().enumerate() {
        let angle = -std::f32::consts::FRAC_PI_2
            + index as f32 * (2.0 * std::f32::consts::PI / snapshot.peers.len().max(1) as f32);
        let position = center + Vec2::new(angle.cos() * radius, angle.sin() * radius);
        peer_positions.push(position);
        painter.line_segment(
            [center, position],
            Stroke::new(
                2.0_f32,
                if peer.directness == Directness::Direct {
                    Color32::from_rgb(40, 160, 30)
                } else {
                    Color32::from_rgb(240, 150, 20)
                },
            ),
        );
    }
    let delta = ui.input(|input| input.unstable_dt).min(0.1);
    for animation in &mut state.active_animations {
        let target = peer_positions
            .get(animation.peer_index % peer_positions.len().max(1))
            .copied()
            .unwrap_or(center + Vec2::new(0.0, -120.0));
        animation.progress += delta * animation.speed;
        painter.circle_filled(
            center.lerp(target, animation.progress.clamp(0.0, 1.0)),
            8.0,
            Color32::from_rgb(100, 235, 80),
        );
    }
    state
        .active_animations
        .retain(|animation| animation.progress <= 1.0);
    if !state.active_animations.is_empty() {
        ctx.request_repaint();
    }

    draw_peer_icon(&painter, texture, center, "me");
    for (index, position) in peer_positions.into_iter().enumerate() {
        draw_peer_icon(
            &painter,
            texture,
            position,
            &short_peer(&snapshot.peers[index].peer_id.to_string()),
        );
    }
    if snapshot.peers.is_empty() {
        painter.text(
            center + Vec2::new(0.0, -55.0),
            Align2::CENTER_BOTTOM,
            "no authenticated peers connected",
            ThemeColors::font_regular(13.0),
            Color32::from_gray(140),
        );
    }
}

fn draw_peer_icon(painter: &egui::Painter, texture: &TextureHandle, position: Pos2, label: &str) {
    let icon = egui::Rect::from_center_size(position, Vec2::splat(58.0));
    painter.image(
        texture.id(),
        icon,
        egui::Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
        Color32::WHITE,
    );
    painter.text(
        position + Vec2::new(0.0, 32.0),
        Align2::CENTER_TOP,
        label,
        ThemeColors::font_regular(11.0),
        Color32::BLACK,
    );
}
