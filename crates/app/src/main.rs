#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use intelscribe_core::autofill::{self, DraftSummary};
use intelscribe_core::model::{Engagement, Incident, Ioc};
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
    let out = intelscribe_render::render_preview(&source, 1.5)?;
    Ok(Preview {
        pages: out.pages,
        warnings: out.warnings,
    })
}

#[tauri::command(rename_all = "snake_case")]
async fn export_pdf(
    engagement: Engagement,
    theme_name: String,
    art_style: String,
) -> Result<String, String> {
    let source = build_source(&engagement, &theme_name, &art_style);
    let bytes = intelscribe_render::render_pdf(&source)?;

    let dir = export_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let stem = {
        let title = sanitize_filename(&engagement.title);
        let client = sanitize_filename(&engagement.client);
        match (title.is_empty(), client.is_empty()) {
            (false, false) => format!("{title} - {client}"),
            (false, true) => title,
            (true, false) => client,
            (true, true) => "report".to_string(),
        }
    };
    let path = dir.join(format!("{stem}.pdf"));
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
fn suggest_techniques(text: String) -> Vec<packs::Technique> {
    packs::suggest_techniques(&text)
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

fn export_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Desktop")
        .join("IntelScribe Exports")
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
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            render_preview,
            export_pdf,
            search_techniques,
            search_ism,
            extract_iocs,
            suggest_techniques,
            score_cvss,
            pack_info,
            draft_summary,
            list_art_styles,
            list_themes
        ])
        .run(tauri::generate_context!())
        .expect("error while running IntelScribe");
}
