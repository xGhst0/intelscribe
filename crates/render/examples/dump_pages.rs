//! Dev utility: render the sample engagement and dump page PNGs to
//! target/test-artifacts for visual inspection.
//! Usage: cargo run -p intelscribe-render --example dump_pages [theme] [art]

use base64::Engine as _;
use intelscribe_core::{template, theme};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let theme_name = args.get(1).map(String::as_str).unwrap_or("Harbour Teal");
    let art = args.get(2).map(String::as_str).unwrap_or("auto");

    // Optional 3rd arg: a fixture path. Defaults to the incident demo.
    let engagement: intelscribe_core::model::Engagement = match args.get(3) {
        Some(path) => serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap(),
        None => serde_json::from_str(include_str!("../fixtures/demo_engagement.json")).unwrap(),
    };
    let tpl = template::incident_report();
    let theme = theme::get(theme_name);
    let src = intelscribe_render::build_source(&engagement, &theme, &tpl, art);
    let preview = intelscribe_render::render_preview(&src, 1.4).expect("render");

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-artifacts");
    std::fs::create_dir_all(&dir).unwrap();
    for (i, b64) in preview.pages.iter().enumerate() {
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        std::fs::write(dir.join(format!("page{}.png", i + 1)), bytes).unwrap();
    }
    println!("wrote {} pages for theme '{}' art '{}'", preview.pages.len(), theme.name, art);
}
