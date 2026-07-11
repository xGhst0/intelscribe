#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use intelscribe_core::autofill::{self, DraftSummary};
use intelscribe_core::model::{Detection, Engagement, Host, Incident, Ioc, TimelineEvent};
use intelscribe_core::{extract, packs, template, theme};
use serde::Serialize;

#[derive(Serialize)]
struct Preview {
    pages: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct ThemeMeta {
    name: String,
    primary: String,
    accent: String,
}

fn build_source(engagement: &Engagement, theme_name: &str, art_style: &str) -> String {
    let theme = theme::get(theme_name);
    let tpl = template::incident_report();
    intelscribe_render::build_source(engagement, &theme, &tpl, art_style)
}

#[tauri::command(rename_all = "snake_case")]
async fn render_preview(
    engagement: Engagement,
    theme_name: String,
    art_style: String,
) -> Result<Preview, String> {
    let source = build_source(&engagement, &theme_name, &art_style);
    let assets = intelscribe_render::collect_assets(&engagement);
    let out = intelscribe_render::render_preview_with_assets(&source, assets, 1.5)?;
    Ok(Preview {
        pages: out.pages,
        warnings: out.warnings,
    })
}

fn export_stem(engagement: &Engagement) -> String {
    let title = sanitize_filename(&engagement.title);
    let client = sanitize_filename(&engagement.client);
    match (title.is_empty(), client.is_empty()) {
        (false, false) => format!("{title} - {client}"),
        (false, true) => title,
        (true, false) => client,
        (true, true) => "report".to_string(),
    }
}

#[tauri::command(rename_all = "snake_case")]
async fn export_pdf(
    engagement: Engagement,
    theme_name: String,
    art_style: String,
) -> Result<String, String> {
    let source = build_source(&engagement, &theme_name, &art_style);
    let assets = intelscribe_render::collect_assets(&engagement);
    let bytes = intelscribe_render::render_pdf_with_assets(&source, assets)?;

    let dir = export_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.pdf", export_stem(&engagement)));
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn export_docx(engagement: Engagement, theme_name: String) -> Result<String, String> {
    let theme = theme::get(&theme_name);
    let bytes = intelscribe_render::build_docx(&engagement, &theme)?;
    let dir = export_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.docx", export_stem(&engagement)));
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command(rename_all = "snake_case")]
fn search_techniques(query: String) -> Vec<packs::Technique> {
    packs::search(&query)
}

#[tauri::command(rename_all = "snake_case")]
fn search_ism(query: String) -> Vec<packs::IsmControl> {
    packs::ism_search(&query)
}

#[tauri::command(rename_all = "snake_case")]
fn extract_iocs(text: String) -> Vec<Ioc> {
    extract::extract_iocs(&text)
}

#[tauri::command(rename_all = "snake_case")]
fn extract_hosts(text: String) -> Vec<Host> {
    extract::extract_hosts(&text)
}

#[tauri::command(rename_all = "snake_case")]
fn extract_events(text: String) -> Vec<TimelineEvent> {
    extract::extract_events(&text)
}

#[tauri::command(rename_all = "snake_case")]
fn extract_detections(text: String) -> Vec<Detection> {
    extract::extract_detections(&text)
}

#[tauri::command(rename_all = "snake_case")]
fn suggest_techniques(text: String) -> Vec<packs::Technique> {
    packs::suggest_techniques(&text)
}

#[tauri::command(rename_all = "snake_case")]
fn lint_report(engagement: Engagement) -> Vec<intelscribe_core::lint::LintFinding> {
    intelscribe_core::lint::lint(&engagement)
}

#[tauri::command(rename_all = "snake_case")]
fn score_cvss(vector: String) -> Result<intelscribe_core::cvss::CvssResult, String> {
    intelscribe_core::cvss::score_vector(&vector)
}

#[derive(Serialize)]
struct PackInfo {
    attack_version: String,
    ism_version: String,
    technique_count: usize,
}

#[tauri::command(rename_all = "snake_case")]
fn pack_info() -> PackInfo {
    PackInfo {
        attack_version: packs::attack_version().to_string(),
        ism_version: packs::ism_version().to_string(),
        technique_count: packs::all_techniques().len(),
    }
}

#[tauri::command(rename_all = "snake_case")]
fn draft_summary(incident: Incident) -> DraftSummary {
    autofill::draft(&incident)
}

#[tauri::command(rename_all = "snake_case")]
fn draft_pentest_summary(engagement: Engagement) -> String {
    autofill::draft_pentest_summary(&engagement)
}

#[tauri::command(rename_all = "snake_case")]
fn list_art_styles() -> Vec<String> {
    theme::ART_STYLES.iter().map(|s| s.to_string()).collect()
}

#[tauri::command(rename_all = "snake_case")]
fn list_themes() -> Vec<ThemeMeta> {
    theme::builtin_themes()
        .into_iter()
        .map(|t| ThemeMeta {
            name: t.name,
            primary: t.palette.primary,
            accent: t.palette.accent,
        })
        .collect()
}

#[tauri::command(rename_all = "snake_case")]
fn save_engagement(engagement: Engagement) -> Result<Option<String>, String> {
    let stem = {
        let t = sanitize_filename(&engagement.title);
        if t.is_empty() { "report".to_string() } else { t }
    };
    let picked = rfd::FileDialog::new()
        .add_filter("IntelScribe report", &["sok"])
        .set_directory(projects_dir())
        .set_file_name(format!("{stem}.sok"))
        .save_file();
    match picked {
        Some(path) => {
            let json = serde_json::to_string_pretty(&engagement).map_err(|e| e.to_string())?;
            std::fs::write(&path, json).map_err(|e| e.to_string())?;
            Ok(Some(path.display().to_string()))
        }
        None => Ok(None),
    }
}

#[derive(Serialize)]
struct ProjectInfo {
    name: String,
    path: String,
}

#[tauri::command(rename_all = "snake_case")]
fn list_projects() -> Vec<ProjectInfo> {
    let mut entries: Vec<(std::time::SystemTime, ProjectInfo)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(projects_dir()) {
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) == Some("sok") {
                let modified = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("report")
                    .to_string();
                entries.push((modified, ProjectInfo { name, path: path.display().to_string() }));
            }
        }
    }
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    entries.into_iter().take(12).map(|(_, p)| p).collect()
}

#[tauri::command(rename_all = "snake_case")]
fn open_project(path: String) -> Result<Engagement, String> {
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("Not a valid .sok file: {e}"))
}

#[tauri::command(rename_all = "snake_case")]
fn open_engagement() -> Result<Option<Engagement>, String> {
    let picked = rfd::FileDialog::new()
        .add_filter("IntelScribe report", &["sok"])
        .set_directory(projects_dir())
        .pick_file();
    match picked {
        Some(path) => {
            let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let engagement: Engagement = serde_json::from_str(&text)
                .map_err(|e| format!("Not a valid .sok file: {e}"))?;
            Ok(Some(engagement))
        }
        None => Ok(None),
    }
}

/// Extract visible text from a .docx (a zip of XML). Paragraph and break tags
/// become newlines; all other tags are stripped.
fn docx_to_text(bytes: &[u8]) -> Result<String, String> {
    use std::io::Read;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let mut xml = String::new();
    zip.by_name("word/document.xml")
        .map_err(|_| "not a Word document (no word/document.xml)".to_string())?
        .read_to_string(&mut xml)
        .map_err(|e| e.to_string())?;

    let xml = xml
        .replace("</w:p>", "\n")
        .replace("<w:br/>", "\n")
        .replace("<w:br />", "\n")
        .replace("<w:tab/>", "\t");
    let mut out = String::with_capacity(xml.len() / 2);
    let mut in_tag = false;
    for ch in xml.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    Ok(out
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'"))
}

/// Best-effort text from a legacy binary .doc: extract runs of printable
/// characters, trying both single-byte and UTF-16LE encodings.
fn doc_strings(bytes: &[u8]) -> String {
    fn printable(b: u8) -> bool {
        b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b)
    }
    fn ascii_runs(bytes: &[u8]) -> String {
        let mut out = String::new();
        let mut run = String::new();
        for &b in bytes {
            if printable(b) {
                run.push(b as char);
            } else {
                if run.trim().len() >= 4 {
                    out.push_str(run.trim());
                    out.push('\n');
                }
                run.clear();
            }
        }
        if run.trim().len() >= 4 {
            out.push_str(run.trim());
        }
        out
    }
    fn utf16_runs(bytes: &[u8]) -> String {
        let mut out = String::new();
        let mut run = String::new();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let (lo, hi) = (bytes[i], bytes[i + 1]);
            if hi == 0 && printable(lo) {
                run.push(lo as char);
            } else {
                if run.trim().len() >= 4 {
                    out.push_str(run.trim());
                    out.push('\n');
                }
                run.clear();
            }
            i += 2;
        }
        if run.trim().len() >= 4 {
            out.push_str(run.trim());
        }
        out
    }
    let a = ascii_runs(bytes);
    let u = utf16_runs(bytes);
    if u.len() > a.len() {
        u
    } else {
        a
    }
}

fn read_document_text(path: &std::path::Path) -> Result<String, String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(match ext.as_str() {
        "docx" => docx_to_text(&bytes)?,
        "doc" => doc_strings(&bytes),
        "pdf" => pdf_extract::extract_text_from_mem(&bytes)
            .map_err(|e| format!("Could not read PDF: {e}"))?,
        _ => String::from_utf8_lossy(&bytes).into_owned(),
    })
}

#[tauri::command(rename_all = "snake_case")]
fn add_evidence() -> Result<Option<intelscribe_core::model::Evidence>, String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let picked = rfd::FileDialog::new()
        .add_filter(
            "Evidence",
            &[
                "png", "jpg", "jpeg", "gif", "bmp", "webp", "pdf", "txt", "log", "csv", "docx",
                "doc", "eml", "msg", "json", "xml", "zip", "pcap", "evtx",
            ],
        )
        .add_filter("All files", &["*"])
        .pick_file();
    let Some(path) = picked else { return Ok(None) };

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:x}", hasher.finalize());
    let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("file").to_string();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

    // Embed images under a size cap so the project file stays manageable.
    const EMBED_CAP: usize = 4_000_000;
    let is_image = matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp");
    let (image_data, image_ext) = if is_image && bytes.len() <= EMBED_CAP {
        (
            base64::engine::general_purpose::STANDARD.encode(&bytes),
            ext.clone(),
        )
    } else {
        (String::new(), String::new())
    };

    Ok(Some(intelscribe_core::model::Evidence {
        title: filename.clone(),
        filename,
        sha256,
        size_bytes: bytes.len() as u64,
        captured: String::new(),
        notes: String::new(),
        image_data,
        image_ext,
    }))
}

#[tauri::command(rename_all = "snake_case")]
fn import_document() -> Result<Option<String>, String> {
    let picked = rfd::FileDialog::new()
        .add_filter(
            "Documents",
            &["txt", "log", "csv", "tsv", "md", "text", "json", "xml", "docx", "doc", "pdf"],
        )
        .add_filter("All files", &["*"])
        .pick_file();
    match picked {
        Some(path) => Ok(Some(read_document_text(&path)?)),
        None => Ok(None),
    }
}

fn export_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Desktop")
        .join("IntelScribe Exports")
}

fn projects_dir() -> PathBuf {
    let dir = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Desktop")
        .join("IntelScribe Projects");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn main() {
    // Hidden CLI: `intelscribe-app --extract <file>` prints the extracted text.
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--extract" {
        match read_document_text(std::path::Path::new(&args[2])) {
            Ok(text) => print!("{text}"),
            Err(e) => eprintln!("error: {e}"),
        }
        return;
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            render_preview,
            export_pdf,
            export_docx,
            save_engagement,
            open_engagement,
            list_projects,
            open_project,
            import_document,
            add_evidence,
            search_techniques,
            search_ism,
            extract_iocs,
            extract_hosts,
            extract_events,
            extract_detections,
            suggest_techniques,
            lint_report,
            score_cvss,
            pack_info,
            draft_summary,
            draft_pentest_summary,
            list_art_styles,
            list_themes
        ])
        .run(tauri::generate_context!())
        .expect("error while running IntelScribe");
}
