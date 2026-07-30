use crate::signature::SharedSignatureDb;
use crate::ui::ThemeColors;
use egui::{Color32, Frame, RichText, Rounding, Stroke, Vec2};

pub fn render_manage_signatures_tab(
    ui: &mut egui::Ui,
    shared_db: &SharedSignatureDb,
    logs: &mut Vec<String>,
) {
    let all_sigs = shared_db.get_all_signatures();
    let count = all_sigs.len();

    let banner_frame = Frame::none()
        .fill(ThemeColors::BG_CARD)
        .stroke(Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED))
        .rounding(Rounding::same(8.0))
        .inner_margin(16.0);

    banner_frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("DATABASE :: FLAGGED FILE SIGNATURES")
                    .font(ThemeColors::font_bold(18.0))
                    .color(ThemeColors::ACCENT_CYAN),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("TOTAL FLAGGED: {}", count))
                        .font(ThemeColors::font_bold(14.0))
                        .color(ThemeColors::ACCENT_EMERALD),
                );
            });
        });
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Below are all file signatures currently tagged as threats in your P2P database. You can remove any entry to restore it to clear status.",
            )
            .font(ThemeColors::font_regular(13.0))
            .color(ThemeColors::TEXT_MUTED),
        );
    });

    ui.add_space(16.0);

    if all_sigs.is_empty() {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("✔ NO FLAGGED SIGNATURES IN DATABASE")
                    .font(ThemeColors::font_bold(20.0))
                    .color(ThemeColors::ACCENT_EMERALD),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Your database is clean. No files have been tagged as threats.")
                    .font(ThemeColors::font_regular(14.0))
                    .color(ThemeColors::TEXT_MUTED),
            );
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(ui.available_width());

            for sig in all_sigs {
                let card_frame = Frame::none()
                    .fill(ThemeColors::BG_CARD)
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(70, 70, 80)))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(16.0);

                card_frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(&sig.file_name)
                                    .font(ThemeColors::font_bold(18.0))
                                    .color(Color32::WHITE),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!("BLAKE3 :: {}", sig.blake3_hash))
                                    .font(ThemeColors::font_regular(12.0))
                                    .color(ThemeColors::ACCENT_CYAN),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!(
                                    "FLAGGED BY :: {}   |   LEVEL :: {}",
                                    sig.flagged_by_peer, sig.threat_level
                                ))
                                .font(ThemeColors::font_regular(12.0))
                                .color(ThemeColors::TEXT_MUTED),
                            );
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let remove_btn = egui::Button::new(
                                RichText::new("🗑 REMOVE")
                                    .font(ThemeColors::font_bold(13.0))
                                    .color(Color32::WHITE),
                            )
                            .fill(Color32::from_rgb(180, 45, 45))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(220, 80, 80)))
                            .rounding(Rounding::same(6.0))
                            .min_size(Vec2::new(100.0, 36.0));

                            if ui.add(remove_btn).clicked() {
                                let hash = sig.blake3_hash.clone();
                                let file_name = sig.file_name.clone();
                                if shared_db.remove_and_save(&hash) {
                                    logs.push(format!(
                                        "db   :: removed signature for file '{}' ({}) from local database",
                                        file_name,
                                        &hash[..8.min(hash.len())]
                                    ));
                                }
                            }
                        });
                    });
                });

                ui.add_space(12.0);
            }
        });
}
