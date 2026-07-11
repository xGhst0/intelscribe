//! DOCX export: a structured Word document parallel to the Typst/PDF output,
//! intended for track-changes review. Pure Rust via docx-rs.

use std::collections::BTreeMap;
use std::io::Cursor;

use docx_rs::*;
use intelscribe_core::model::{Engagement, Incident, Phase, Severity};
use intelscribe_core::theme::Theme;
use intelscribe_core::{cvss, frameworks, packs};

fn hex(color: &str) -> String {
    color.trim_start_matches('#').to_uppercase()
}

// ---- paragraph / run helpers ------------------------------------------------

fn heading(text: &str, size: usize, color: &str) -> Paragraph {
    Paragraph::new()
        .add_run(Run::new().bold().size(size).color(color).add_text(text))
        .add_run(Run::new()) // spacing
}

fn h1(text: &str, primary: &str) -> Paragraph {
    heading(text, 32, primary)
}
fn h2(text: &str, primary: &str) -> Paragraph {
    heading(text, 26, primary)
}
fn h3(text: &str, ink: &str) -> Paragraph {
    heading(text, 22, ink)
}

fn para(text: &str) -> Paragraph {
    Paragraph::new().add_run(Run::new().size(20).add_text(text))
}

fn bullet(text: &str) -> Paragraph {
    Paragraph::new().add_run(Run::new().size(20).add_text(format!("•  {text}")))
}

fn label(label: &str, value: &str) -> Paragraph {
    Paragraph::new()
        .add_run(Run::new().bold().size(20).add_text(format!("{label}  ")))
        .add_run(Run::new().size(20).add_text(value))
}

fn code_para(code: &str) -> Paragraph {
    let mut run = Run::new().fonts(RunFonts::new().ascii("Consolas")).size(16);
    for (i, line) in code.lines().enumerate() {
        if i > 0 {
            run = run.add_break(BreakType::TextWrapping);
        }
        run = run.add_text(line);
    }
    Paragraph::new().add_run(run)
}

fn muted_italic(text: &str, muted: &str) -> Paragraph {
    Paragraph::new().add_run(Run::new().italic().size(17).color(muted).add_text(text))
}

// ---- table helpers ----------------------------------------------------------

fn header_cell(text: &str, primary: &str) -> TableCell {
    TableCell::new()
        .shading(Shading::new().shd_type(ShdType::Clear).fill(primary))
        .add_paragraph(
            Paragraph::new().add_run(Run::new().bold().size(18).color("FFFFFF").add_text(text)),
        )
}

fn body_cell(text: &str) -> TableCell {
    TableCell::new().add_paragraph(Paragraph::new().add_run(Run::new().size(18).add_text(text)))
}

fn mono_cell(text: &str) -> TableCell {
    TableCell::new().add_paragraph(
        Paragraph::new().add_run(Run::new().fonts(RunFonts::new().ascii("Consolas")).size(16).add_text(text)),
    )
}

fn make_table(headers: &[&str], rows: Vec<Vec<TableCell>>, primary: &str) -> Table {
    let mut trs = vec![TableRow::new(headers.iter().map(|h| header_cell(h, primary)).collect())];
    for row in rows {
        trs.push(TableRow::new(row));
    }
    Table::new(trs).width(9026, WidthType::Dxa).set_grid(vec![])
}

// ---- document ---------------------------------------------------------------

pub fn build_docx(e: &Engagement, theme: &Theme) -> Result<Vec<u8>, String> {
    let p = &theme.palette;
    let primary = hex(&p.primary);
    let ink = hex(&p.ink);
    let muted = hex(&p.muted);

    let mut docx = Docx::new();

    // Title block.
    docx = docx.add_paragraph(
        Paragraph::new().add_run(Run::new().bold().size(44).color(&primary).add_text(e.title.clone())),
    );
    let classification = e.classification.trim().to_uppercase();
    if !classification.is_empty() {
        docx = docx.add_paragraph(
            Paragraph::new()
                .align(AlignmentType::Left)
                .add_run(Run::new().bold().size(18).color(&primary).add_text(classification)),
        );
    }
    let prepared = if e.analyst_title.trim().is_empty() {
        e.analyst.clone()
    } else {
        format!("{}, {}", e.analyst, e.analyst_title)
    };
    docx = docx.add_paragraph(para(&format!(
        "{}   |   Prepared by {}   |   {}   |   Version {}",
        e.client, prepared, e.date, e.version
    )));
    docx = docx.add_paragraph(Paragraph::new());

    if e.report_kind.trim().eq_ignore_ascii_case("pentest") {
        docx = pentest_body(docx, e, theme, &primary, &ink, &muted);
    } else {
        docx = incident_body(docx, e, theme, &primary, &ink, &muted);
    }
    docx = evidence_register(docx, e, &primary, &muted);

    let mut buf = Vec::new();
    docx.build().pack(Cursor::new(&mut buf)).map_err(|err| err.to_string())?;
    Ok(buf)
}

fn incident_body(
    mut docx: Docx,
    e: &Engagement,
    theme: &Theme,
    primary: &str,
    ink: &str,
    muted: &str,
) -> Docx {
    // Executive summary.
    docx = docx.add_paragraph(h1("Executive Summary", primary));
    for (i, inc) in e.incidents.iter().enumerate() {
        docx = exec_summary(docx, inc, i + 1, theme, primary, ink);
    }
    // Technical analysis per incident.
    for (i, inc) in e.incidents.iter().enumerate() {
        docx = technical_analysis(docx, inc, i + 1, primary, ink, muted);
    }
    // Essential Eight assessment.
    if !e.essential_eight.is_empty() {
        docx = docx.add_paragraph(h1("Essential Eight Maturity Assessment", primary));
        let rows: Vec<Vec<TableCell>> = e
            .essential_eight
            .iter()
            .map(|it| {
                let cur = it.current_level.min(3);
                let tgt = it.target_level.min(3);
                let status = if cur >= tgt { "Met".to_string() } else { format!("Gap +{}", tgt - cur) };
                vec![
                    body_cell(&it.strategy),
                    body_cell(frameworks::e8_level_name(cur)),
                    body_cell(frameworks::e8_level_name(tgt)),
                    body_cell(&status),
                    body_cell(&it.notes),
                ]
            })
            .collect();
        docx = docx.add_table(make_table(
            &["Mitigation Strategy", "Current", "Target", "Status", "Notes"],
            rows,
            primary,
        ));
    }
    docx
}

fn severity_line(inc: &Incident, theme: &Theme) -> Paragraph {
    let color = hex(theme.severity_color(inc.severity));
    Paragraph::new()
        .add_run(Run::new().bold().size(20).add_text("Severity:  "))
        .add_run(Run::new().bold().size(20).color(&color).add_text(inc.severity.label().to_uppercase()))
}

fn exec_summary(
    mut docx: Docx,
    inc: &Incident,
    n: usize,
    theme: &Theme,
    primary: &str,
    ink: &str,
) -> Docx {
    docx = docx.add_paragraph(h2(&format!("Incident {n}: {}", inc.title), primary));
    if !inc.incident_id.trim().is_empty() {
        docx = docx.add_paragraph(label("Incident ID:", &inc.incident_id));
    }
    docx = docx.add_paragraph(severity_line(inc, theme));
    if let Ok(r) = cvss::score_vector(&inc.cvss_vector) {
        if !inc.cvss_vector.trim().is_empty() {
            docx = docx.add_paragraph(label("CVSS 3.1:", &format!("{} {} ({})", r.score, r.rating, r.vector)));
        }
    }
    if let Some(cat) = frameworks::acsc_category(&inc.acsc_category) {
        if !inc.acsc_category.trim().is_empty() {
            docx = docx.add_paragraph(label("ASD category:", &format!("{} — {}", cat.id, cat.label)));
        }
    }
    docx = docx.add_paragraph(label("Status:", &inc.status));

    if !inc.overview.trim().is_empty() {
        docx = docx.add_paragraph(h3("Incident Overview", ink)).add_paragraph(para(inc.overview.trim()));
    }
    if !inc.key_findings.is_empty() {
        docx = docx.add_paragraph(h3("Key Findings", ink));
        for f in &inc.key_findings {
            docx = docx.add_paragraph(bullet(f));
        }
    }
    if !inc.immediate_actions.is_empty() {
        docx = docx.add_paragraph(h3("Immediate Actions", ink));
        for a in &inc.immediate_actions {
            docx = docx.add_paragraph(bullet(a));
        }
    }
    if !inc.stakeholder_impact.trim().is_empty() {
        docx = docx
            .add_paragraph(h3("Stakeholder Impact", ink))
            .add_paragraph(para(inc.stakeholder_impact.trim()));
    }
    docx
}

fn technical_analysis(
    mut docx: Docx,
    inc: &Incident,
    n: usize,
    primary: &str,
    ink: &str,
    muted: &str,
) -> Docx {
    docx = docx.add_paragraph(h1(&format!("Technical Analysis (Incident {n})"), primary));

    // Affected systems.
    docx = docx.add_paragraph(h2("Affected Systems & Data", primary));
    for h in &inc.hosts {
        let name = if h.ip.trim().is_empty() {
            h.name.clone()
        } else {
            format!("{} ({})", h.name, h.ip)
        };
        docx = docx
            .add_paragraph(Paragraph::new().add_run(Run::new().bold().size(20).add_text(name)))
            .add_paragraph(para(&h.description));
    }
    if !inc.accounts.is_empty() {
        docx = docx.add_paragraph(h3("Affected Accounts", ink));
        for a in &inc.accounts {
            docx = docx.add_paragraph(bullet(&format!("{} — {}", a.name, a.description)));
        }
    }

    // Detections.
    docx = docx.add_paragraph(h2("Evidence Sources & Analysis", primary));
    for (i, d) in inc.detections.iter().enumerate() {
        let title = if d.title.trim().is_empty() {
            format!("Detection {}", i + 1)
        } else {
            format!("Detection {}: {}", i + 1, d.title)
        };
        docx = docx.add_paragraph(h3(&title, ink));
        if !d.data_source.trim().is_empty() {
            docx = docx.add_paragraph(label("Data source:", &d.data_source));
        }
        if !d.query.trim().is_empty() {
            docx = docx.add_paragraph(code_para(&d.query));
        }
        if !d.result.trim().is_empty() {
            docx = docx.add_paragraph(label("Result:", &d.result));
        }
    }

    // IoCs.
    if !inc.iocs.is_empty() {
        docx = docx.add_paragraph(h2("Indicators of Compromise (IoCs)", primary));
        let rows: Vec<Vec<TableCell>> = inc
            .iocs
            .iter()
            .map(|i| vec![mono_cell(&i.indicator), body_cell(&i.ioc_type), body_cell(&i.context)])
            .collect();
        docx = docx.add_table(make_table(&["Indicator", "Type", "Context"], rows, primary));
    }

    // Root cause.
    if !inc.root_cause.trim().is_empty() {
        docx = docx
            .add_paragraph(h2("Root Cause Analysis", primary))
            .add_paragraph(para(inc.root_cause.trim()));
    }

    // Timeline.
    if !inc.events.is_empty() {
        docx = docx.add_paragraph(h2("Technical Timeline", primary));
        let mut events: Vec<_> = inc.events.iter().collect();
        events.sort_by(|a, b| {
            Phase::ALL.iter().position(|p| *p == a.phase).cmp(&Phase::ALL.iter().position(|p| *p == b.phase))
                .then(a.timestamp.cmp(&b.timestamp))
        });
        let rows: Vec<Vec<TableCell>> = events
            .iter()
            .map(|ev| {
                vec![
                    mono_cell(&ev.timestamp),
                    body_cell(ev.phase.label()),
                    body_cell(&ev.host),
                    body_cell(&ev.description),
                ]
            })
            .collect();
        docx = docx.add_table(make_table(&["Time", "Phase", "Host", "Activity"], rows, primary));
    }

    // ATT&CK.
    if !inc.techniques.is_empty() {
        docx = docx.add_paragraph(h2("MITRE ATT&CK Mapping", primary));
        let mut techs = inc.techniques.clone();
        techs.sort_by(|a, b| a.id.cmp(&b.id));
        let rows: Vec<Vec<TableCell>> = techs
            .iter()
            .map(|t| vec![mono_cell(&t.id), body_cell(&t.name), body_cell(&t.tactic)])
            .collect();
        docx = docx.add_table(make_table(&["Technique", "Name", "Tactic"], rows, primary));
    }

    // Recommendations.
    docx = recommendations(docx, inc, primary, ink);

    // ISM framework alignment.
    let ism: Vec<_> = inc.ism_controls.iter().filter_map(|id| packs::ism_control(id)).collect();
    if !ism.is_empty() {
        docx = docx.add_paragraph(h2("Framework Alignment — ACSC ISM", primary));
        docx = docx.add_paragraph(muted_italic(
            &format!("Controls quoted verbatim from the ACSC ISM ({}).", packs::ism_version()),
            muted,
        ));
        let rows: Vec<Vec<TableCell>> =
            ism.iter().map(|c| vec![mono_cell(&c.id), body_cell(&c.text)]).collect();
        docx = docx.add_table(make_table(&["Control", "Text"], rows, primary));
    }

    // Regulatory.
    let reg = &inc.regulatory;
    let engaged = reg.critical_infrastructure || reg.personal_info_involved || !reg.soci_impact.trim().is_empty();
    if engaged {
        docx = docx.add_paragraph(h2("Regulatory & Reporting Obligations", primary));
        docx = docx.add_paragraph(muted_italic(
            "Advisory decision support, not legal advice.",
            muted,
        ));
        for det in [frameworks::assess_soci(reg), frameworks::assess_ndb(reg)] {
            docx = docx
                .add_paragraph(Paragraph::new().add_run(Run::new().bold().size(20).add_text(det.headline)))
                .add_paragraph(para(&det.detail));
        }
    }
    docx
}

fn recommendations(mut docx: Docx, inc: &Incident, primary: &str, ink: &str) -> Docx {
    if inc.techniques.is_empty() && inc.additional_recommendations.is_empty() {
        return docx;
    }
    docx = docx.add_paragraph(h2("Recommendations & Mitigations", primary));

    let mut controls: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    let mut e8: Vec<String> = Vec::new();
    for t in &inc.techniques {
        if let Some(entry) = packs::mitigations_for(&t.id) {
            for c in entry.controls {
                let slot = controls.entry(c.name).or_insert((c.reference, Vec::new()));
                if !slot.1.contains(&t.id) {
                    slot.1.push(t.id.clone());
                }
            }
            for s in entry.essential_eight {
                if !e8.contains(&s) {
                    e8.push(s);
                }
            }
        }
    }
    if !controls.is_empty() {
        docx = docx.add_paragraph(h3("Priority Controls (derived from observed techniques)", ink));
        let mut ranked: Vec<_> = controls.into_iter().collect();
        ranked.sort_by(|a, b| b.1 .1.len().cmp(&a.1 .1.len()).then(a.0.cmp(&b.0)));
        let rows: Vec<Vec<TableCell>> = ranked
            .iter()
            .map(|(name, (reference, techniques))| {
                vec![body_cell(name), mono_cell(&techniques.join(", ")), body_cell(reference)]
            })
            .collect();
        docx = docx.add_table(make_table(&["Recommended Control", "Addresses", "Reference"], rows, primary));
    }
    if !e8.is_empty() {
        docx = docx.add_paragraph(label("ACSC Essential Eight:", &e8.join(" · ")));
    }
    if !inc.additional_recommendations.is_empty() {
        docx = docx.add_paragraph(h3("Analyst Recommendations", ink));
        for r in &inc.additional_recommendations {
            docx = docx.add_paragraph(bullet(r));
        }
    }
    docx
}

fn pentest_body(
    mut docx: Docx,
    e: &Engagement,
    theme: &Theme,
    primary: &str,
    ink: &str,
    muted: &str,
) -> Docx {
    docx = docx.add_paragraph(h1("Executive Summary", primary));
    if !e.executive_summary.trim().is_empty() {
        docx = docx.add_paragraph(para(e.executive_summary.trim()));
    }

    // Findings summary table.
    if !e.findings.is_empty() {
        let mut order: Vec<usize> = (0..e.findings.len()).collect();
        order.sort_by_key(|&i| severity_rank(e.findings[i].severity));
        let rows: Vec<Vec<TableCell>> = order
            .iter()
            .enumerate()
            .map(|(n, &i)| {
                let f = &e.findings[i];
                let cvss = cvss::score_vector(&f.cvss_vector)
                    .ok()
                    .filter(|_| !f.cvss_vector.trim().is_empty())
                    .map(|r| r.score.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let status = if f.status.trim().is_empty() { "Open" } else { f.status.trim() };
                vec![
                    body_cell(&format!("F{}", n + 1)),
                    body_cell(&f.title),
                    body_cell(f.severity.label()),
                    body_cell(&cvss),
                    body_cell(status),
                ]
            })
            .collect();
        docx = docx.add_table(make_table(&["No.", "Finding", "Severity", "CVSS", "Status"], rows, primary));
    }

    if !e.scope.trim().is_empty() {
        docx = docx.add_paragraph(h2("Scope", primary)).add_paragraph(para(e.scope.trim()));
    }
    if !e.methodology.trim().is_empty() {
        docx = docx.add_paragraph(h2("Methodology", primary)).add_paragraph(para(e.methodology.trim()));
    }

    docx = docx.add_paragraph(h1("Findings", primary));
    let mut order: Vec<usize> = (0..e.findings.len()).collect();
    order.sort_by_key(|&i| severity_rank(e.findings[i].severity));
    for (n, &i) in order.iter().enumerate() {
        let f = &e.findings[i];
        docx = docx.add_paragraph(h2(&format!("Finding F{}: {}", n + 1, f.title), primary));
        let color = hex(theme.severity_color(f.severity));
        docx = docx.add_paragraph(
            Paragraph::new()
                .add_run(Run::new().bold().size(20).add_text("Severity:  "))
                .add_run(Run::new().bold().size(20).color(&color).add_text(f.severity.label().to_uppercase())),
        );
        if let Ok(r) = cvss::score_vector(&f.cvss_vector) {
            if !f.cvss_vector.trim().is_empty() {
                docx = docx.add_paragraph(label("CVSS 3.1:", &format!("{} {} ({})", r.score, r.rating, r.vector)));
            }
        }
        if !f.category.trim().is_empty() {
            docx = docx.add_paragraph(label("Category:", &f.category));
        }
        let status = if f.status.trim().is_empty() { "Open" } else { f.status.trim() };
        docx = docx.add_paragraph(label("Status:", status));
        if !f.affected.trim().is_empty() {
            docx = docx.add_paragraph(label("Affected:", &f.affected));
        }
        if !f.description.trim().is_empty() {
            docx = docx.add_paragraph(h3("Description", ink)).add_paragraph(para(f.description.trim()));
        }
        if !f.impact.trim().is_empty() {
            docx = docx.add_paragraph(h3("Impact", ink)).add_paragraph(para(f.impact.trim()));
        }
        if !f.remediation.trim().is_empty() {
            docx = docx.add_paragraph(h3("Remediation", ink)).add_paragraph(para(f.remediation.trim()));
        }
        let refs: Vec<_> = f.references.iter().filter_map(|id| packs::ism_control(id)).collect();
        if !refs.is_empty() {
            docx = docx.add_paragraph(h3("References — ACSC ISM", ink));
            for c in refs {
                docx = docx.add_paragraph(bullet(&format!("{} — {}", c.id, c.text)));
            }
        }
    }
    let _ = muted;
    docx
}

fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < KB * KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{:.1} MB", b / (KB * KB))
    }
}

fn evidence_register(mut docx: Docx, e: &Engagement, primary: &str, muted: &str) -> Docx {
    if e.evidence.is_empty() {
        return docx;
    }
    docx = docx.add_paragraph(h1("Evidence Register", primary));
    docx = docx.add_paragraph(muted_italic(
        "Collected evidence with SHA-256 integrity hashes.",
        muted,
    ));
    let rows: Vec<Vec<TableCell>> = e
        .evidence
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let desc = if ev.title.trim().is_empty() { &ev.filename } else { &ev.title };
            vec![
                body_cell(&format!("{}", i + 1)),
                body_cell(desc),
                mono_cell(&ev.filename),
                body_cell(&human_size(ev.size_bytes)),
                mono_cell(&ev.sha256),
                body_cell(&ev.captured),
            ]
        })
        .collect();
    docx.add_table(make_table(
        &["Ex.", "Description", "Filename", "Size", "SHA-256", "Collected"],
        rows,
        primary,
    ))
}

fn severity_rank(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Informational => 4,
    }
}
