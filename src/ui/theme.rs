use egui::{Color32, FontFamily, FontId, Rounding, Stroke, Visuals};

pub struct ThemeColors;

#[allow(dead_code)]
impl ThemeColors {
    // Pitch black main background matching the user screenshot
    pub const BG_MAIN: Color32 = Color32::from_rgb(0, 0, 0);
    // Dark grey background box for log text container
    pub const BG_LOG_BOX: Color32 = Color32::from_rgb(34, 34, 34);
    pub const BG_CARD: Color32 = Color32::from_rgb(26, 26, 26);
    pub const BG_ELEVATED: Color32 = Color32::from_rgb(40, 40, 40);
    pub const BORDER_MUTED: Color32 = Color32::from_rgb(50, 50, 50);

    // Neon Yellow button color matching the user screenshot
    pub const NEON_YELLOW: Color32 = Color32::from_rgb(255, 248, 0);
    pub const NEON_YELLOW_HOVER: Color32 = Color32::from_rgb(255, 255, 60);

    pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(255, 255, 255);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(170, 170, 170);

    pub const ACCENT_CYAN: Color32 = Color32::from_rgb(56, 189, 248);
    pub const ACCENT_EMERALD: Color32 = Color32::from_rgb(46, 200, 70);
    pub const ACCENT_DANGER: Color32 = Color32::from_rgb(255, 50, 50);
    pub const ACCENT_WARNING: Color32 = Color32::from_rgb(255, 200, 0);

    pub fn font_bold(size: f32) -> FontId {
        FontId::new(size, FontFamily::Name("JetBrainsMono-Bold".into()))
    }

    pub fn font_regular(size: f32) -> FontId {
        FontId::new(size, FontFamily::Name("JetBrainsMono-Regular".into()))
    }
}

pub fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    fonts.font_data.insert(
        "JetBrainsMono-Regular".to_owned(),
        egui::FontData::from_static(include_bytes!("../../assets/JetBrainsMono-Regular.ttf")),
    );
    fonts.font_data.insert(
        "JetBrainsMono-Bold".to_owned(),
        egui::FontData::from_static(include_bytes!("../../assets/JetBrainsMono-Bold.ttf")),
    );

    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "JetBrainsMono-Regular".to_owned());

    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "JetBrainsMono-Regular".to_owned());

    fonts.families.insert(
        egui::FontFamily::Name("JetBrainsMono-Bold".into()),
        vec!["JetBrainsMono-Bold".to_owned()],
    );
    fonts.families.insert(
        egui::FontFamily::Name("JetBrainsMono-Regular".into()),
        vec!["JetBrainsMono-Regular".to_owned()],
    );

    ctx.set_fonts(fonts);
}

pub fn apply_theme(ctx: &egui::Context) {
    setup_fonts(ctx);

    let mut visuals = Visuals::dark();

    visuals.panel_fill = ThemeColors::BG_MAIN;
    visuals.window_fill = ThemeColors::BG_CARD;
    visuals.window_stroke = Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED);

    visuals.widgets.noninteractive.bg_fill = ThemeColors::BG_CARD;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, ThemeColors::TEXT_PRIMARY);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED);
    visuals.widgets.noninteractive.rounding = Rounding::same(6.0);

    visuals.widgets.inactive.bg_fill = ThemeColors::BG_CARD;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, ThemeColors::TEXT_PRIMARY);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, ThemeColors::BORDER_MUTED);
    visuals.widgets.inactive.rounding = Rounding::same(6.0);

    visuals.widgets.hovered.bg_fill = ThemeColors::BG_ELEVATED;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, ThemeColors::ACCENT_CYAN);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ThemeColors::ACCENT_CYAN);
    visuals.widgets.hovered.rounding = Rounding::same(6.0);

    visuals.widgets.active.bg_fill = ThemeColors::BG_ELEVATED;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, ThemeColors::TEXT_PRIMARY);
    visuals.widgets.active.bg_stroke = Stroke::new(1.5_f32, ThemeColors::ACCENT_CYAN);
    visuals.widgets.active.rounding = Rounding::same(6.0);

    ctx.set_visuals(visuals);
}
