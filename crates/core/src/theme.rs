use serde::{Deserialize, Serialize};

use crate::model::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Theme {
    pub name: String,
    pub palette: Palette,
    #[serde(default)]
    pub typography: Typography,
    /// Default cover-art generator for this theme; see ART_STYLES.
    #[serde(default = "default_cover_art")]
    pub cover_art: String,
    #[serde(default = "default_art_seed")]
    pub art_seed: u64,
}

pub const ART_STYLES: [&str; 7] =
    ["hexgrid", "circuit", "network", "radar", "binary", "contours", "none"];

fn default_cover_art() -> String {
    "hexgrid".to_string()
}

fn default_art_seed() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Palette {
    pub primary: String,
    pub accent: String,
    pub banner_start: String,
    pub banner_end: String,
    pub ink: String,
    pub muted: String,
    pub stripe: String,
    pub table_border: String,
    pub severity_critical: String,
    pub severity_high: String,
    pub severity_medium: String,
    pub severity_low: String,
    pub severity_info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Typography {
    pub body_font: String,
    pub heading_font: String,
    pub mono_font: String,
    pub base_size: f64,
}

impl Default for Typography {
    fn default() -> Self {
        Typography {
            body_font: "Libertinus Serif".to_string(),
            heading_font: "Libertinus Serif".to_string(),
            mono_font: "DejaVu Sans Mono".to_string(),
            base_size: 10.0,
        }
    }
}

impl Theme {
    pub fn severity_color(&self, severity: Severity) -> &str {
        match severity {
            Severity::Critical => &self.palette.severity_critical,
            Severity::High => &self.palette.severity_high,
            Severity::Medium => &self.palette.severity_medium,
            Severity::Low => &self.palette.severity_low,
            Severity::Informational => &self.palette.severity_info,
        }
    }
}

#[derive(Deserialize)]
struct Collection {
    themes: Vec<Theme>,
}

pub fn builtin_themes() -> Vec<Theme> {
    let collection: Collection = toml::from_str(include_str!("../../../themes/collection.toml"))
        .expect("bundled theme collection is valid TOML");
    collection.themes
}

/// Look a theme up by name, falling back to the first built-in.
pub fn get(name: &str) -> Theme {
    let themes = builtin_themes();
    themes
        .iter()
        .find(|t| t.name.eq_ignore_ascii_case(name))
        .cloned()
        .unwrap_or_else(|| themes.into_iter().next().expect("no built-in themes"))
}
