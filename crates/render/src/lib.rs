mod art;
mod doc;
mod docx;
mod world;

pub use doc::{build_source, collect_assets};
pub use docx::build_docx;

use base64::Engine as _;
use typst::diag::Warned;
use typst::layout::PagedDocument;

pub struct Preview {
    /// One base64-encoded PNG per page.
    pub pages: Vec<String>,
    pub warnings: Vec<String>,
}

fn compile(
    source: &str,
    assets: Vec<(String, Vec<u8>)>,
) -> Result<(PagedDocument, Vec<String>), String> {
    let world = world::IntelWorld::new(source.to_string(), assets);
    let Warned { output, warnings } = typst::compile::<PagedDocument>(&world);
    let warnings = warnings.iter().map(|w| w.message.to_string()).collect();
    match output {
        Ok(doc) => Ok((doc, warnings)),
        Err(errors) => Err(errors
            .iter()
            .map(|e| e.message.to_string())
            .collect::<Vec<_>>()
            .join("\n")),
    }
}

pub fn render_preview(source: &str, pixels_per_pt: f32) -> Result<Preview, String> {
    render_preview_with_assets(source, Vec::new(), pixels_per_pt)
}

pub fn render_preview_with_assets(
    source: &str,
    assets: Vec<(String, Vec<u8>)>,
    pixels_per_pt: f32,
) -> Result<Preview, String> {
    let (doc, warnings) = compile(source, assets)?;
    let mut pages = Vec::with_capacity(doc.pages.len());
    for page in &doc.pages {
        let pixmap = typst_render::render(page, pixels_per_pt);
        let png = pixmap.encode_png().map_err(|e| e.to_string())?;
        pages.push(base64::engine::general_purpose::STANDARD.encode(png));
    }
    Ok(Preview { pages, warnings })
}

pub fn render_pdf(source: &str) -> Result<Vec<u8>, String> {
    render_pdf_with_assets(source, Vec::new())
}

pub fn render_pdf_with_assets(source: &str, assets: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>, String> {
    let (doc, _warnings) = compile(source, assets)?;
    typst_pdf::pdf(&doc, &typst_pdf::PdfOptions::default()).map_err(|errors| {
        errors
            .iter()
            .map(|e| e.message.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    })
}
