use crate::signature::FileSignature;
use egui::{Align, Color32, Frame, Layout, RichText, Rounding, Stroke, Vec2};

pub fn render_red_alert_screen(
    ctx: &egui::Context,
    signature: &FileSignature,
    on_dismiss: &mut bool,
) {
    // Force a dramatic vibrant red fill across the central panel
    let red_bg = Color32::from_rgb(45, 10, 12);
    let border_red = Color32::from_rgb(235, 50, 50);

    let frame = Frame::none()
        .fill(red_bg)
        .inner_margin(30.0)
        .stroke(Stroke::new(3.0_f32, border_red));

    egui::CentralPanel::default()
        .frame(frame)
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);

                // Animated pulsing banner
                let time = ctx.input(|i| i.time);
                let pulse = (time * 4.0).sin().abs() as f32;
                let title_color = Color32::from_rgb(
                    255,
                    (60.0 + 80.0 * pulse) as u8,
                    (60.0 + 80.0 * pulse) as u8,
                );

                ui.heading(
                    RichText::new("🚨 FLAGGED 🚨")
                        .size(38.0)
                        .strong()
                        .color(title_color),
                );

                ui.add_space(10.0);
                ui.label(
                    RichText::new("This file has been flagged across the network.")
                        .size(18.0)
                        .color(Color32::from_rgb(240, 180, 180)),
                );

                ui.add_space(30.0);

                // Threat Signature Card
                let card_frame = Frame::none()
                    .fill(Color32::from_rgb(30, 8, 10))
                    .stroke(Stroke::new(1.5_f32, border_red))
                    .rounding(Rounding::same(10.0))
                    .inner_margin(24.0);

                card_frame.show(ui, |ui| {
                    ui.set_max_width(700.0);
                    ui.with_layout(Layout::top_down(Align::LEFT), |ui| {
                        ui.label(
                            RichText::new("SIGNATURE DETAILS")
                                .size(14.0)
                                .strong()
                                .color(border_red),
                        );
                        ui.add_space(12.0);

                        render_field(ui, "STATUS", "FLAGGED");
                        render_field(ui, "FILE NAME", &signature.file_name);
                        render_field(ui, "FILE SIZE", &signature.formatted_size());
                        render_field(ui, "THREAT LEVEL", &signature.threat_level);
                        render_field(ui, "FLAG REASON", &signature.reason);
                        render_field(ui, "FLAGGED BY PEER", &signature.flagged_by_peer);
                        render_field(
                            ui,
                            "FLAGGED TIMESTAMP",
                            &signature.flagged_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        );

                        ui.add_space(10.0);
                        ui.label(RichText::new("BLAKE3 HASH:").strong().size(13.0).color(Color32::WHITE));
                        ui.add_space(4.0);
                        
                        let hex_box = Frame::none()
                            .fill(Color32::from_rgb(15, 5, 6))
                            .rounding(Rounding::same(4.0))
                            .inner_margin(8.0);
                        hex_box.show(ui, |ui| {
                            ui.label(
                                RichText::new(&signature.blake3_hash)
                                    .monospace()
                                    .size(13.0)
                                    .color(Color32::from_rgb(255, 140, 140)),
                            );
                        });
                    });
                });

                ui.add_space(40.0);

                ui.horizontal_top(|ui| {
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        let btn_size = Vec2::new(300.0, 45.0);
                        let dismiss_btn = egui::Button::new(
                            RichText::new("← Dismiss")
                                .strong()
                                .size(15.0)
                                .color(Color32::WHITE),
                        )
                        .fill(Color32::from_rgb(180, 30, 30))
                        .rounding(Rounding::same(8.0))
                        .min_size(btn_size);

                        if ui.add_sized(btn_size, dismiss_btn).clicked() {
                            *on_dismiss = true;
                        }

                        if ui
                            .button(RichText::new("Copy BLAKE3 Hash").size(14.0))
                            .clicked()
                        {
                            ctx.output_mut(|o| {
                                o.copied_text = signature.blake3_hash.clone();
                            });
                        }
                    });
                });
            });
        });

    // Request continuous repaint for smooth pulsing animation
    ctx.request_repaint();
}

fn render_field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.set_min_height(24.0);
        ui.label(
            RichText::new(format!("{:<20}: ", label))
                .strong()
                .size(13.0)
                .color(Color32::from_rgb(200, 160, 160)),
        );
        ui.label(RichText::new(value).size(14.0).color(Color32::WHITE));
    });
}
