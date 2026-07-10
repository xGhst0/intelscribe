use intelscribe_core::model::Engagement;
use intelscribe_core::{template, theme};

fn artifacts_dir() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-artifacts");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample() -> Engagement {
    serde_json::from_str(include_str!("../fixtures/demo_engagement.json"))
        .expect("demo fixture matches the model")
}

#[test]
fn sample_engagement_renders_across_all_themes() {
    let engagement = sample();
    let tpl = template::incident_report();
    let themes = theme::builtin_themes();
    assert!(themes.len() >= 18, "expected the full theme collection, got {}", themes.len());

    for theme in &themes {
        let src = intelscribe_render::build_source(&engagement, theme, &tpl, "auto");
        let pdf = intelscribe_render::render_pdf(&src)
            .unwrap_or_else(|e| panic!("PDF render failed for theme {}: {e}", theme.name));
        assert!(pdf.len() > 10_000, "suspiciously small PDF for {}", theme.name);
    }

    // Preview path (PNG pages) for a couple of themes.
    for theme in themes.iter().take(2) {
        let src = intelscribe_render::build_source(&engagement, theme, &tpl, "auto");
        let preview = intelscribe_render::render_preview(&src, 1.0)
            .unwrap_or_else(|e| panic!("preview render failed for theme {}: {e}", theme.name));
        assert!(preview.pages.len() >= 5, "expected a multi-page report");
        assert!(
            preview.warnings.is_empty(),
            "typst warnings for {}: {:?}",
            theme.name,
            preview.warnings
        );
    }

    // Keep one PDF as an inspectable artifact.
    let theme = theme::get("Harbour Teal");
    let src = intelscribe_render::build_source(&engagement, &theme, &tpl, "auto");
    let pdf = intelscribe_render::render_pdf(&src).unwrap();
    std::fs::write(artifacts_dir().join("sample.pdf"), &pdf).unwrap();
}

#[test]
fn generated_sections_appear() {
    let engagement = sample();
    let tpl = template::incident_report();
    let theme = theme::get("Harbour Teal");
    let src = intelscribe_render::build_source(&engagement, &theme, &tpl, "auto");
    for expected in [
        "Attack Path Overview",
        "Recommendations & Mitigations",
        "Priority Controls",
        "Essential Eight",
        "Observed Movement",
        "Framework Alignment",
        "CVSS 3.1",
        // ISM control text is quoted verbatim.
        "Microsoft Office macros in files originating from the internet are blocked",
        // CVSS score for the sample vector (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H = 9.6).
        "9.6",
        // Australian frameworks.
        "ASD category",
        "Regulatory & Reporting Obligations",
        "SOCI Act",
        "12 hours",
        "eligible data breach",
        "Essential Eight Maturity Assessment",
    ] {
        assert!(src.contains(expected), "missing section: {expected}");
    }
}

#[test]
fn every_art_style_renders_without_warnings() {
    let engagement = sample();
    let tpl = template::incident_report();
    let theme = theme::get("Harbour Teal");
    for style in theme::ART_STYLES {
        let src = intelscribe_render::build_source(&engagement, &theme, &tpl, style);
        let preview = intelscribe_render::render_preview(&src, 0.5)
            .unwrap_or_else(|e| panic!("render failed for art style {style}: {e}"));
        assert!(
            preview.warnings.is_empty(),
            "typst warnings for art style {style}: {:?}",
            preview.warnings
        );
    }
}

#[test]
fn autofill_drafts_from_sample_data() {
    let engagement = sample();
    let draft = intelscribe_core::autofill::draft(&engagement.incidents[0]);
    assert!(draft.overview.contains("initial access occurred"));
    assert!(draft.overview.contains("203.0.113.47"));
    assert!(!draft.key_findings.is_empty());
    assert!(draft.stakeholder_impact.contains("compromised"));
}

#[test]
fn pentest_report_renders() {
    let engagement: Engagement =
        serde_json::from_str(include_str!("../fixtures/demo_pentest.json"))
            .expect("pentest fixture matches the model");
    let tpl = template::incident_report();
    let theme = theme::get("Cobalt Ops");
    let src = intelscribe_render::build_source(&engagement, &theme, &tpl, "auto");
    for expected in [
        "= Findings",
        "Finding F1",
        "Unauthenticated SQL injection",
        "= Scope",
        "Methodology",
        "References — ACSC ISM",
        // ISM-1657 quoted in the critical finding's references.
        "Application control restricts the execution of executables",
    ] {
        assert!(src.contains(expected), "pentest missing: {expected}");
    }
    // It must NOT render incident-only sections.
    assert!(!src.contains("Attack Path Overview"), "incident section leaked into pentest");

    let pdf = intelscribe_render::render_pdf(&src).expect("pentest PDF renders");
    assert!(pdf.len() > 10_000);

    let dir = artifacts_dir();
    std::fs::write(dir.join("pentest.pdf"), &pdf).unwrap();
}

#[test]
fn empty_engagement_still_renders() {
    let engagement = Engagement::default();
    let theme = theme::get("Harbour Teal");
    let tpl = template::incident_report();
    let src = intelscribe_render::build_source(&engagement, &theme, &tpl, "auto");
    intelscribe_render::render_pdf(&src).expect("empty engagement must not break rendering");
}

#[test]
fn hostile_input_is_escaped() {
    let mut engagement = Engagement::default();
    engagement.title = r#"#import "evil.typ" [bracket] *bold* `tick` $math$ \back"#.to_string();
    engagement.client = "<label> @ref ~nbsp = heading".to_string();
    let theme = theme::get("Ember");
    let tpl = template::incident_report();
    let src = intelscribe_render::build_source(&engagement, &theme, &tpl, "auto");
    let out = intelscribe_render::render_pdf(&src);
    assert!(out.is_ok(), "escaping failed: {:?}", out.err());
}
