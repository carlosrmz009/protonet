use crate::signature::SharedSignatureDb;
use crate::ui::ThemeColors;
use egui::{Color32, Frame, RichText, Rounding, Stroke, Vec2};

const PAGE_SIZE: usize = 50;

pub struct ManageSignaturesState {
    page: usize,
    total: usize,
    signatures: Vec<crate::signature::FileSignature>,
    dirty: bool,
}

impl Default for ManageSignaturesState {
    fn default() -> Self {
        Self {
            page: 0,
            total: 0,
            signatures: Vec::new(),
            dirty: true,
        }
    }
}

pub fn render_manage_signatures_tab(
    ui: &mut egui::Ui,
    shared_db: &SharedSignatureDb,
    logs: &mut Vec<String>,
    state: &mut ManageSignaturesState,
) {
    if state.dirty {
        state.total = shared_db.count();
        let max_page = state.total.saturating_sub(1) / PAGE_SIZE;
        state.page = state.page.min(max_page);
        state.signatures =
            shared_db.get_signatures_page(state.page.saturating_mul(PAGE_SIZE), PAGE_SIZE);
        state.dirty = false;
    }
    let count = state.total;

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

    ui.horizontal(|ui| {
        if ui
            .add_enabled(state.page > 0, egui::Button::new("Previous"))
            .clicked()
        {
            state.page = state.page.saturating_sub(1);
            state.dirty = true;
        }
        ui.label(format!(
            "Page {} of {}",
            state.page + 1,
            count.saturating_sub(1) / PAGE_SIZE + 1
        ));
        if ui
            .add_enabled(
                (state.page + 1).saturating_mul(PAGE_SIZE) < count,
                egui::Button::new("Next"),
            )
            .clicked()
        {
            state.page = state.page.saturating_add(1);
            state.dirty = true;
        }
        if ui.button("Refresh").clicked() {
            state.dirty = true;
        }
    });

    if state.signatures.is_empty() {
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

            for sig in state.signatures.clone() {
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
                                    state.dirty = true;
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
