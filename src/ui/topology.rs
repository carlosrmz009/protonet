use crate::p2p::P2pHandle;
use crate::ui::ThemeColors;
use egui::{
    Align2, Color32, Pos2, RichText, Stroke, TextureHandle, TextureOptions, Vec2, ViewportBuilder,
    ViewportClass, ViewportId,
};

pub struct BroadcastAnim {
    pub peer_index: usize,
    pub progress: f32, // 0.0 to 1.0
    pub speed: f32,
}

pub struct TopologyState {
    pub texture: Option<TextureHandle>,
    pub active_animations: Vec<BroadcastAnim>,
}

impl Default for TopologyState {
    fn default() -> Self {
        Self {
            texture: None,
            active_animations: Vec::new(),
        }
    }
}

impl TopologyState {
    pub fn get_or_load_texture(&mut self, ctx: &egui::Context) -> TextureHandle {
        if let Some(tex) = &self.texture {
            return tex.clone();
        }

        let png_bytes = match std::fs::read("peer.png") {
            Ok(bytes) => bytes,
            Err(_) => include_bytes!("../../peer.png").to_vec(),
        };

        let image = image::load_from_memory(&png_bytes)
            .expect("Failed to load peer.png")
            .to_rgba8();
        let size = [image.width() as _, image.height() as _];
        let pixels = image.as_flat_samples();
        let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());

        let handle = ctx.load_texture("peer_logo", color_image, TextureOptions::LINEAR);
        self.texture = Some(handle.clone());
        handle
    }

    pub fn trigger_broadcast(&mut self, total_peers: usize, ctx: &egui::Context) {
        let count = total_peers.max(1);
        for i in 0..count {
            self.active_animations.push(BroadcastAnim {
                peer_index: i,
                progress: 0.0,
                speed: 0.75,
            });
        }
        ctx.request_repaint();
        ctx.request_repaint_of(egui::ViewportId::from_hash_of("peers_topology_window"));
    }
}

pub fn render_topology_window(
    ctx: &egui::Context,
    open: &mut bool,
    state: &mut TopologyState,
    p2p_handle: &P2pHandle,
) {
    let texture = state.get_or_load_texture(ctx);

    // Collect only real connected peers
    let peer_names: Vec<String> = p2p_handle
        .get_peers_info()
        .into_iter()
        .map(|(addr, id)| {
            if id.is_empty() || id == "unknown" {
                addr.to_string()
            } else {
                format!("{}\n({})", id, addr.ip())
            }
        })
        .collect();
    let total_peers = peer_names.len();

    let viewport_id = ViewportId::from_hash_of("peers_topology_window");
    let viewport_builder = ViewportBuilder::default()
        .with_title("Peers")
        .with_inner_size([680.0, 580.0])
        .with_min_inner_size([400.0, 350.0])
        .with_icon(crate::ui::get_app_icon());

    ctx.show_viewport_immediate(viewport_id, viewport_builder, move |ctx, class| {
        if class == ViewportClass::Immediate && ctx.input(|i| i.viewport().close_requested()) {
            *open = false;
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(ThemeColors::BG_MAIN)
                    .inner_margin(16.0),
            )
            .show(ctx, |ui| {
                // --- Status Header (read-only) ---
            ui.horizontal(|ui| {
                let status_color = if total_peers > 0 {
                    ThemeColors::ACCENT_EMERALD
                } else {
                    ThemeColors::TEXT_MUTED
                };

                ui.label(
                    RichText::new(if total_peers > 0 {
                        "● LIVE"
                    } else {
                        "○ waiting for peers..."
                    })
                    .font(ThemeColors::font_bold(14.0))
                    .color(status_color),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(&format!("Active Peers: {}", total_peers))
                            .font(ThemeColors::font_bold(14.0))
                            .color(ThemeColors::TEXT_PRIMARY),
                    );
                });
            });

            ui.add_space(10.0);

            // --- White Canvas Map ---
            let available_size = ui.available_size();
            let canvas_size = Vec2::new(available_size.x, available_size.y.max(450.0));
            let (rect, _response) = ui.allocate_exact_size(canvas_size, egui::Sense::hover());

            let painter = ui.painter_at(rect);

            // White background canvas
            painter.rect_filled(rect, 8.0, Color32::WHITE);
            painter.rect_stroke(
                rect,
                8.0,
                Stroke::new(1.0_f32, Color32::from_rgb(200, 200, 200)),
            );

            let center = rect.center();
            let radius = (rect.width().min(rect.height()) * 0.35).min(180.0);

            // Calculate peer positions
            let mut peer_positions = Vec::new();
            for i in 0..total_peers {
                let angle = -std::f32::consts::FRAC_PI_2
                    + (i as f32) * (2.0 * std::f32::consts::PI / (total_peers.max(1) as f32));
                let peer_pos = center + Vec2::new(angle.cos() * radius, angle.sin() * radius);
                peer_positions.push(peer_pos);

                // Draw dashed line from center to peer
                draw_dashed_line(
                    &painter,
                    center,
                    peer_pos,
                    Stroke::new(3.0_f32, Color32::BLACK),
                    10.0,
                    8.0,
                );
            }

            // Animate green flowing circles along the dashed lines
            let dt = ui.input(|i| i.unstable_dt).min(0.1);
            let mut has_active_animation = false;

            for anim in &mut state.active_animations {
                let target_pos = if !peer_positions.is_empty() {
                    peer_positions[anim.peer_index % peer_positions.len()]
                } else {
                    center + Vec2::new(0.0, -140.0)
                };

                if anim.progress <= 1.0 {
                    anim.progress += dt * anim.speed;
                    has_active_animation = true;

                    let circle_pos = center.lerp(target_pos, anim.progress.clamp(0.0, 1.0));

                    // Bright green circle
                    painter.circle_filled(
                        circle_pos,
                        13.0,
                        Color32::from_rgb(100, 235, 80),
                    );
                    painter.circle_stroke(
                        circle_pos,
                        13.0,
                        Stroke::new(2.5_f32, Color32::from_rgb(40, 160, 30)),
                    );
                }
            }

            // Clean up finished animations
            state.active_animations.retain(|a| a.progress <= 1.0);

            if has_active_animation {
                ctx.request_repaint();
            }

            // Draw localhost (me) icon at center
            let center_icon_rect = egui::Rect::from_center_size(center, Vec2::new(76.0, 76.0));
            painter.image(
                texture.id(),
                center_icon_rect,
                egui::Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                Color32::WHITE,
            );

            painter.text(
                center + Vec2::new(0.0, 42.0),
                Align2::CENTER_TOP,
                "localhost",
                ThemeColors::font_regular(16.0),
                Color32::BLACK,
            );
            painter.text(
                center + Vec2::new(0.0, 60.0),
                Align2::CENTER_TOP,
                "(me)",
                ThemeColors::font_regular(16.0),
                Color32::BLACK,
            );

            // Show "no peers connected" text when alone
            if total_peers == 0 {
                painter.text(
                    center + Vec2::new(0.0, -60.0),
                    Align2::CENTER_BOTTOM,
                    "no peers connected",
                    ThemeColors::font_regular(14.0),
                    Color32::from_rgb(160, 160, 160),
                );
            }

            // Draw peer icons & labels
            for (i, &peer_pos) in peer_positions.iter().enumerate() {
                let peer_icon_rect =
                    egui::Rect::from_center_size(peer_pos, Vec2::new(68.0, 68.0));
                painter.image(
                    texture.id(),
                    peer_icon_rect,
                    egui::Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                    Color32::WHITE,
                );

                let label = peer_names
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| format!("peer-{}", i + 1));
                painter.text(
                    peer_pos + Vec2::new(0.0, 38.0),
                    Align2::CENTER_TOP,
                    &label,
                    ThemeColors::font_regular(12.0),
                    Color32::BLACK,
                );
            }
        });
    });
}

fn draw_dashed_line(
    painter: &egui::Painter,
    start: Pos2,
    end: Pos2,
    stroke: Stroke,
    dash_len: f32,
    gap_len: f32,
) {
    let dir = end - start;
    let total_len = dir.length();
    if total_len == 0.0 {
        return;
    }
    let norm = dir / total_len;
    let mut current = 0.0;
    while current < total_len {
        let seg_start = start + norm * current;
        let seg_end = start + norm * (current + dash_len).min(total_len);
        painter.line_segment([seg_start, seg_end], stroke);
        current += dash_len + gap_len;
    }
}
