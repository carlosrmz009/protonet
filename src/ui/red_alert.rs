use crate::signature::FileSignature;
use egui::{
    Align, Color32, Frame, Layout, RichText, Rounding, Stroke, TextureHandle, TextureOptions, Vec2,
};

fn get_or_load_infected_texture(ctx: &egui::Context) -> Option<TextureHandle> {
    if let Some(tex) = ctx.data_mut(|d| d.get_temp::<TextureHandle>(egui::Id::new("infected_png")))
    {
        return Some(tex);
    }

    let png_bytes = match std::fs::read("infected.png") {
        Ok(bytes) => bytes,
        Err(_) => include_bytes!("../../infected.png").to_vec(),
    };

    if let Ok(image) = image::load_from_memory(&png_bytes) {
        let rgba = image.to_rgba8();
        let size = [rgba.width() as _, rgba.height() as _];
        let pixels = rgba.as_flat_samples();
        let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());
        let handle = ctx.load_texture("infected_logo", color_image, TextureOptions::LINEAR);
        ctx.data_mut(|d| {
            d.insert_temp(egui::Id::new("infected_png"), handle.clone());
        });
        Some(handle)
    } else {
        None
    }
}

pub fn render_red_alert_screen(
    ctx: &egui::Context,
    signature: &FileSignature,
    on_dismiss: &mut bool,
) {
    let red_bg = Color32::from_rgb(20, 5, 8);
    let border_red = Color32::from_rgb(220, 45, 45);

    let frame = Frame::none()
        .fill(red_bg)
        .inner_margin(30.0)
        .stroke(Stroke::new(2.5_f32, border_red));

    egui::CentralPanel::default()
        .frame(frame)
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);

                // Render infected.png prominently
                if let Some(texture) = get_or_load_infected_texture(ctx) {
                    let avail_width = ui.available_width().min(640.0);
                    let aspect = texture.size()[1] as f32 / texture.size()[0].max(1) as f32;
                    let display_size = Vec2::new(avail_width, avail_width * aspect);

                    ui.image((texture.id(), display_size));
                } else {
                    ui.heading(
                        RichText::new("🚨 INFECTED 🚨")
                            .size(44.0)
                            .strong()
                            .color(Color32::from_rgb(255, 60, 60)),
                    );
                }

                ui.add_space(24.0);

                // Quick threat info line
                ui.label(
                    RichText::new(&format!(
                        "FILE INFECTED :: {}   (flagged by {})",
                        signature.file_name, signature.flagged_by_peer
                    ))
                    .font(crate::ui::ThemeColors::font_bold(16.0))
                    .color(Color32::from_rgb(255, 120, 120)),
                );

                ui.add_space(6.0);

                ui.label(
                    RichText::new(&format!("BLAKE3 :: {}", signature.blake3_hash))
                        .font(crate::ui::ThemeColors::font_regular(13.0))
                        .color(Color32::from_rgb(200, 160, 160)),
                );

                ui.add_space(32.0);

                // Dismiss & Copy Buttons
                ui.horizontal_top(|ui| {
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        let btn_size = Vec2::new(240.0, 44.0);
                        let dismiss_btn = egui::Button::new(
                            RichText::new("← Dismiss")
                                .strong()
                                .size(15.0)
                                .color(Color32::WHITE),
                        )
                        .fill(Color32::from_rgb(190, 35, 35))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(240, 80, 80)))
                        .rounding(Rounding::same(8.0))
                        .min_size(btn_size);

                        if ui.add_sized(btn_size, dismiss_btn).clicked() {
                            *on_dismiss = true;
                        }

                        ui.add_space(16.0);

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

    ctx.request_repaint();
}
