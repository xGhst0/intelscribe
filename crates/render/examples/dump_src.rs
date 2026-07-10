//! Print the generated Typst source for a fixture, for debugging.
//! Usage: cargo run -p intelscribe-render --example dump_src -- <fixture.json>

use intelscribe_core::{template, theme};

fn main() {
    let path = std::env::args().nth(1).expect("pass a fixture path");
    let raw = std::fs::read_to_string(&path).unwrap();
    let engagement: intelscribe_core::model::Engagement = serde_json::from_str(&raw).unwrap();
    let tpl = template::incident_report();
    let theme = theme::get("Cobalt Ops");
    let src = intelscribe_render::build_source(&engagement, &theme, &tpl, "auto");
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/pentest-src.typ");
    std::fs::write(&out, &src).unwrap();
    println!("wrote {} ({} bytes)", out.display(), src.len());
}
