use std::collections::BTreeMap;
use std::fmt::Write as _;

use intelscribe_core::cvss;
use intelscribe_core::frameworks;
use intelscribe_core::model::{Engagement, Incident, Phase};
use intelscribe_core::packs;
use intelscribe_core::theme::Palette;
use intelscribe_core::template::ReportTemplate;
use intelscribe_core::theme::Theme;

use crate::art;

/// Escape a user string for a Typst markup context.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '#'
                | '['
                | ']'
                | '*'
                | '_'
                | '`'
                | '$'
                | '<'
                | '>'
                | '@'
                | '~'
                | '='
                | '-'
                | '+'
                | '/'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Escape a user string for a Typst string literal ("...").
fn esc_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Fence a code snippet as a Typst raw block, growing the fence until it
/// cannot collide with the content.
fn raw_block(code: &str) -> String {
    let mut fence = String::from("```");
    while code.contains(fence.as_str()) {
        fence.push('`');
    }
    format!("{fence}\n{}\n{fence}", code.trim_end())
}

fn guidance(s: &mut String, theme: &Theme, text: &str) {
    let _ = writeln!(
        s,
        "#text(size: 8.5pt, fill: rgb(\"{}\"), style: \"italic\")[{}]\n",
        theme.palette.muted,
        esc(text)
    );
}

fn table_header_cell(label: &str) -> String {
    format!("[#text(fill: white, weight: \"bold\", size: 9pt)[{label}]]")
}

/// Map a CVSS qualitative rating to the theme's severity palette.
fn severity_rating_color<'a>(p: &'a Palette, rating: &str) -> &'a str {
    match rating {
        "Critical" => &p.severity_critical,
        "High" => &p.severity_high,
        "Medium" => &p.severity_medium,
        "Low" => &p.severity_low,
        _ => &p.severity_info,
    }
}

/// Map an ACSC category tier to the theme's severity palette.
fn tier_color<'a>(p: &'a Palette, tier: &str) -> &'a str {
    match tier {
        "critical" => &p.severity_critical,
        "high" => &p.severity_high,
        "medium" => &p.severity_medium,
        "low" => &p.severity_low,
        _ => &p.severity_info,
    }
}

/// Build the complete Typst source for an engagement. `art_style` is one of
/// `theme::ART_STYLES` or "auto" to use the theme's default cover art.
pub fn build_source(e: &Engagement, theme: &Theme, tpl: &ReportTemplate, art_style: &str) -> String {
    let p = &theme.palette;
    let ty = &theme.typography;
    let mut s = String::with_capacity(32 * 1024);
    let classification = e.classification.trim().to_uppercase();

    // Document-wide set/show rules.
    let _ = writeln!(s, "#set document(title: \"{}\")", esc_str(&e.title));
    let _ = writeln!(
        s,
        "#set text(font: \"{}\", size: {}pt, fill: rgb(\"{}\"), lang: \"en\")",
        esc_str(&ty.body_font),
        ty.base_size,
        p.ink
    );
    s.push_str("#set par(justify: true, leading: 0.68em)\n");
    let _ = writeln!(
        s,
        "#show heading.where(level: 1): set text(font: \"{}\", fill: rgb(\"{}\"), size: 16pt)",
        esc_str(&ty.heading_font),
        p.primary
    );
    let _ = writeln!(
        s,
        "#show heading.where(level: 2): set text(font: \"{}\", fill: rgb(\"{}\"), size: 12.5pt)",
        esc_str(&ty.heading_font),
        p.primary
    );
    let _ = writeln!(
        s,
        "#show heading.where(level: 3): set text(font: \"{}\", fill: rgb(\"{}\"), size: 11pt)",
        esc_str(&ty.heading_font),
        p.ink
    );
    s.push_str("#show heading: set block(above: 1.5em, below: 0.9em)\n");
    let _ = writeln!(
        s,
        "#show raw.where(block: true): set text(font: \"{}\", size: 7.5pt)",
        esc_str(&ty.mono_font)
    );
    let _ = writeln!(
        s,
        "#show raw.where(block: true): it => block(width: 100%, fill: rgb(\"{}\"), stroke: 0.5pt + rgb(\"{}\"), inset: 8pt, radius: 3pt, it)",
        p.stripe, p.table_border
    );
    let _ = writeln!(
        s,
        "#show raw.where(block: false): set text(font: \"{}\", size: 0.9em)",
        esc_str(&ty.mono_font)
    );

    cover(&mut s, e, theme, &classification, art_style);
    body_setup(&mut s, e, theme, &classification);

    // Table of contents.
    s.push_str("#outline(title: [Table of Contents], depth: 2, indent: auto)\n#pagebreak()\n\n");

    // Statement of confidentiality (template boilerplate).
    let client = if e.client.trim().is_empty() {
        "the issuing organisation".to_string()
    } else {
        e.client.clone()
    };
    s.push_str("= Statement of Confidentiality\n");
    let confidentiality = tpl.confidentiality.replace("{client}", &client);
    let _ = writeln!(s, "{}\n", esc(confidentiality.trim()));

    // Engagement contacts.
    s.push_str("= Engagement Contacts\n");
    let _ = writeln!(
        s,
        "#table(columns: (1fr, 1fr), stroke: 0.5pt + rgb(\"{}\"), inset: 7pt, fill: (x, y) => if y == 0 {{ rgb(\"{}\") }} else {{ white }},\n{},\n{},\n[{}], [{}],\n)\n",
        p.table_border,
        p.primary,
        table_header_cell("Contact"),
        table_header_cell("Role"),
        esc(&e.analyst),
        esc(&e.analyst_title)
    );

    // Branch on report type. The preamble above (styles, cover, TOC,
    // confidentiality, contacts) is shared by every report.
    if e.report_kind.trim().eq_ignore_ascii_case("pentest") {
        pentest_body(&mut s, e, theme);
        evidence_section(&mut s, e, theme);
        return s;
    }

    // Executive summary, one subsection per incident.
    s.push_str("= Executive Summary\n");
    for (i, inc) in e.incidents.iter().enumerate() {
        exec_summary(&mut s, inc, i + 1, theme);
    }

    // Technical analysis per incident.
    for (i, inc) in e.incidents.iter().enumerate() {
        technical_analysis(&mut s, inc, i + 1, theme, tpl);
    }

    essential_eight_section(&mut s, e, theme);
    evidence_section(&mut s, e, theme);

    s
}

/// ATT&CK enterprise tactics in canonical (kill-chain) order.
const TACTIC_ORDER: [&str; 14] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
];

fn tactic_order_index(tactic: &str) -> usize {
    TACTIC_ORDER
        .iter()
        .position(|t| t.eq_ignore_ascii_case(tactic))
        .unwrap_or(TACTIC_ORDER.len())
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", t.trim_end())
    }
}

/// A compact ATT&CK Navigator-style coverage matrix: observed techniques laid
/// out in columns by their primary tactic, in kill-chain order.
fn attack_matrix(s: &mut String, inc: &Incident, theme: &Theme) {
    let p = &theme.palette;
    let mono = esc_str(&theme.typography.mono_font);
    if inc.techniques.is_empty() {
        return;
    }

    // Group techniques by primary (first) tactic.
    let mut groups: Vec<(String, Vec<&intelscribe_core::model::TechniqueRef>)> = Vec::new();
    for t in &inc.techniques {
        let primary = t
            .tactic
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let key = if primary.is_empty() { "Other".to_string() } else { primary };
        match groups.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&key)) {
            Some((_, v)) => v.push(t),
            None => groups.push((key, vec![t])),
        }
    }
    groups.sort_by_key(|(k, _)| tactic_order_index(k));
    for (_, v) in groups.iter_mut() {
        v.sort_by(|a, b| a.id.cmp(&b.id));
    }

    s.push_str("=== ATT&CK Coverage Matrix\n");
    let _ = writeln!(
        s,
        "#text(size: 8.5pt, fill: rgb(\"{}\"), style: \"italic\")[Observed techniques by tactic, in kill-chain order.]\n",
        p.muted
    );

    // Lay out tactic columns four to a row.
    const PER_ROW: usize = 4;
    let mut cells = String::new();
    for (tactic, techs) in &groups {
        let mut chips = String::new();
        for t in techs {
            let _ = writeln!(
                chips,
                "#box(width: 100%, fill: rgb(\"{stripe}\"), stroke: 0.5pt + rgb(\"{border}\"), radius: 2.5pt, inset: (x: 4pt, y: 3pt))[#text(font: \"{mono}\", size: 7pt, weight: \"bold\", fill: rgb(\"{primary}\"))[{id}]#linebreak()#text(size: 6.5pt)[{name}]]",
                stripe = p.stripe,
                border = p.table_border,
                primary = p.primary,
                id = esc(&t.id),
                name = esc(&truncate_chars(&t.name, 30)),
            );
            chips.push_str("#v(3pt)\n");
        }
        let _ = writeln!(
            cells,
            "box(width: 100%, inset: 0pt)[#box(width: 100%, fill: rgb(\"{accent}\"), radius: 3pt, inset: (x: 5pt, y: 4pt))[#text(fill: white, size: 7.5pt, weight: \"bold\")[{tactic}]]#v(4pt)\n{chips}],",
            accent = p.primary,
            tactic = esc(tactic),
        );
    }
    // Pad the final row so the grid stays aligned.
    let remainder = groups.len() % PER_ROW;
    if remainder != 0 {
        for _ in 0..(PER_ROW - remainder) {
            cells.push_str("[],\n");
        }
    }
    let _ = writeln!(
        s,
        "#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 6pt, align: top,\n{cells})\n"
    );
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

/// Decode embedded evidence images into virtual assets the Typst world serves.
/// Paths match those emitted by `evidence_section`.
pub fn collect_assets(e: &Engagement) -> Vec<(String, Vec<u8>)> {
    use base64::Engine as _;
    let mut out = Vec::new();
    for (i, ev) in e.evidence.iter().enumerate() {
        if ev.image_data.is_empty() || ev.image_ext.is_empty() {
            continue;
        }
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&ev.image_data) {
            out.push((format!("/evidence/{}.{}", i + 1, ev.image_ext), bytes));
        }
    }
    out
}

/// Evidence Register: a chain-of-custody table with SHA-256 integrity hashes,
/// followed by embedded image exhibits.
fn evidence_section(s: &mut String, e: &Engagement, theme: &Theme) {
    let p = &theme.palette;
    if e.evidence.is_empty() {
        return;
    }
    let mono = esc_str(&theme.typography.mono_font);
    s.push_str("#pagebreak()\n= Evidence Register\n");
    let _ = writeln!(
        s,
        "#text(size: 8.5pt, fill: rgb(\"{}\"), style: \"italic\")[Collected evidence with SHA-256 integrity hashes. Exhibit numbers are referenced throughout the report.]\n",
        p.muted
    );

    let mut rows = String::new();
    for (i, ev) in e.evidence.iter().enumerate() {
        let desc = if ev.title.trim().is_empty() { ev.filename.clone() } else { ev.title.clone() };
        // Break the 64-char hash into 32-char lines so it wraps inside its cell.
        let sha_chunks: Vec<String> = ev
            .sha256
            .chars()
            .collect::<Vec<_>>()
            .chunks(32)
            .map(|c| c.iter().collect())
            .collect();
        let sha = sha_chunks.join("#linebreak()");
        let _ = writeln!(
            rows,
            "[#text(weight: \"bold\")[{n}]], [{desc}#linebreak()#text(size: 7.5pt, fill: rgb(\"{muted}\"))[{notes}]], [#text(font: \"{mono}\", size: 7.5pt)[{file}]], [#text(size: 8pt)[{size}]], [#text(font: \"{mono}\", size: 6pt)[{sha}]], [#text(size: 8pt)[{cap}]],",
            n = i + 1,
            desc = esc(&desc),
            muted = p.muted,
            notes = esc(&ev.notes),
            file = esc(&ev.filename),
            size = human_size(ev.size_bytes),
            sha = sha,
            cap = esc(&ev.captured),
        );
    }
    let _ = writeln!(
        s,
        "#table(columns: (30pt, 1fr, 0.85fr, 40pt, 122pt, 0.8fr), stroke: 0.5pt + rgb(\"{border}\"), inset: 5pt, fill: (x, y) => if y == 0 {{ rgb(\"{primary}\") }} else if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{h1},\n{h2},\n{h3},\n{h4},\n{h5},\n{h6},\n{rows})\n",
        h1 = table_header_cell("Ex."),
        h2 = table_header_cell("Description"),
        h3 = table_header_cell("Filename"),
        h4 = table_header_cell("Size"),
        h5 = table_header_cell("SHA-256"),
        h6 = table_header_cell("Collected"),
        border = p.table_border,
        primary = p.primary,
        stripe = p.stripe,
        rows = rows,
    );

    // Embedded image exhibits.
    for (i, ev) in e.evidence.iter().enumerate() {
        if ev.image_data.is_empty() || ev.image_ext.is_empty() {
            continue;
        }
        let caption = if ev.title.trim().is_empty() { ev.filename.clone() } else { ev.title.clone() };
        let _ = writeln!(
            s,
            "#figure(image(\"/evidence/{n}.{ext}\", width: 88%), caption: [Exhibit {n} — {cap}])\n#v(6pt)",
            n = i + 1,
            ext = esc_str(&ev.image_ext),
            cap = esc(&caption),
        );
    }
}

fn severity_rank(sev: intelscribe_core::model::Severity) -> u8 {
    use intelscribe_core::model::Severity::*;
    match sev {
        Critical => 0,
        High => 1,
        Medium => 2,
        Low => 3,
        Informational => 4,
    }
}

/// Penetration-test report body (executive summary, scope, methodology and
/// detailed findings). Reuses the shared cover/confidentiality preamble.
fn pentest_body(s: &mut String, e: &Engagement, theme: &Theme) {
    let p = &theme.palette;
    let tpl = intelscribe_core::template::pentest_report();

    s.push_str("= Executive Summary\n");
    guidance(s, theme, &tpl.exec_guidance);
    if !e.executive_summary.trim().is_empty() {
        let _ = writeln!(s, "{}\n", esc(e.executive_summary.trim()));
    }
    findings_summary(s, e, theme);

    if !e.scope.trim().is_empty() {
        s.push_str("== Scope\n");
        guidance(s, theme, &tpl.scope_guidance);
        let _ = writeln!(s, "{}\n", esc(e.scope.trim()));
    }
    if !e.methodology.trim().is_empty() {
        s.push_str("== Methodology\n");
        guidance(s, theme, &tpl.methodology_guidance);
        let _ = writeln!(s, "{}\n", esc(e.methodology.trim()));
    }

    let _ = writeln!(s, "#pagebreak()\n= Findings");
    guidance(s, theme, &tpl.findings_guidance);
    if e.findings.is_empty() {
        let _ = writeln!(s, "#text(fill: rgb(\"{}\"))[No findings recorded.]\n", p.muted);
        return;
    }
    let mut order: Vec<usize> = (0..e.findings.len()).collect();
    order.sort_by_key(|&i| severity_rank(e.findings[i].severity));
    for (n, &i) in order.iter().enumerate() {
        finding_section(s, &e.findings[i], n + 1, theme);
    }
}

/// Severity distribution badges and a summary table of all findings.
fn findings_summary(s: &mut String, e: &Engagement, theme: &Theme) {
    let p = &theme.palette;
    if e.findings.is_empty() {
        return;
    }
    use intelscribe_core::model::Severity::*;
    let sevs = [Critical, High, Medium, Low, Informational];
    let mut cells = String::new();
    for sev in sevs {
        let count = e.findings.iter().filter(|f| f.severity == sev).count();
        let color = theme.severity_color(sev);
        let _ = writeln!(
            cells,
            "box(width: 100%, fill: rgb(\"{color}\"), radius: 4pt, inset: (y: 7pt))[#align(center)[#text(fill: white, size: 15pt, weight: \"bold\")[{count}]#linebreak()#text(fill: white, size: 7.5pt, tracking: 0.6pt)[{label}]]],",
            label = sev.label().to_uppercase(),
        );
    }
    let _ = writeln!(
        s,
        "#grid(columns: (1fr, 1fr, 1fr, 1fr, 1fr), gutter: 6pt,\n{cells})\n#v(8pt)"
    );

    // Summary table, ordered by severity.
    let mut order: Vec<usize> = (0..e.findings.len()).collect();
    order.sort_by_key(|&i| severity_rank(e.findings[i].severity));
    let mut rows = String::new();
    for (n, &i) in order.iter().enumerate() {
        let f = &e.findings[i];
        let sev = theme.severity_color(f.severity);
        let cvss = cvss::score_vector(&f.cvss_vector)
            .ok()
            .filter(|_| !f.cvss_vector.trim().is_empty())
            .map(|r| format!("{}", r.score))
            .unwrap_or_else(|| "—".to_string());
        let status = if f.status.trim().is_empty() { "Open" } else { f.status.trim() };
        let _ = writeln!(
            rows,
            "[#text(size: 8.5pt)[F{num}]], [#text(size: 9pt)[{title}]], [#box(fill: rgb(\"{sev}\"), radius: 2.5pt, inset: (x: 5pt, y: 2.5pt))[#text(fill: white, size: 7.5pt, weight: \"bold\")[{sevlabel}]]], [#text(size: 8.5pt)[{cvss}]], [#text(size: 8.5pt)[{status}]],",
            num = n + 1,
            title = esc(&f.title),
            sevlabel = f.severity.label().to_uppercase(),
            cvss = cvss,
            status = esc(status),
        );
    }
    let _ = writeln!(
        s,
        "#table(columns: (28pt, 1fr, 74pt, 42pt, 78pt), stroke: 0.5pt + rgb(\"{border}\"), inset: 6pt, fill: (x, y) => if y == 0 {{ rgb(\"{primary}\") }} else if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{h1},\n{h2},\n{h3},\n{h4},\n{h5},\n{rows})\n",
        h1 = table_header_cell("No."),
        h2 = table_header_cell("Finding"),
        h3 = table_header_cell("Severity"),
        h4 = table_header_cell("CVSS"),
        h5 = table_header_cell("Status"),
        border = p.table_border,
        primary = p.primary,
        stripe = p.stripe,
        rows = rows,
    );
}

fn finding_section(s: &mut String, f: &intelscribe_core::model::Finding, n: usize, theme: &Theme) {
    let p = &theme.palette;
    let mono = esc_str(&theme.typography.mono_font);
    let title = if f.title.trim().is_empty() {
        String::new()
    } else {
        format!(": {}", esc(&f.title))
    };
    let _ = writeln!(s, "== Finding F{n}{title}");

    // Meta table.
    let sev = theme.severity_color(f.severity);
    let mut meta = format!(
        "[#text(weight: \"bold\")[Severity:]], [#box(fill: rgb(\"{sev}\"), radius: 3pt, inset: (x: 7pt, y: 3.5pt))[#text(fill: white, size: 8.5pt, weight: \"bold\", tracking: 0.6pt)[{sevlabel}]]],",
        sevlabel = f.severity.label().to_uppercase(),
    );
    if let Ok(r) = cvss::score_vector(&f.cvss_vector) {
        if !f.cvss_vector.trim().is_empty() {
            let color = severity_rating_color(p, &r.rating);
            meta.push_str(&format!(
                "\n[#text(weight: \"bold\")[CVSS 3.1:]], [#box(fill: rgb(\"{color}\"), radius: 3pt, inset: (x: 7pt, y: 3.5pt))[#text(fill: white, size: 8.5pt, weight: \"bold\")[{score} {rating}]] #h(6pt) #text(font: \"{mono}\", size: 8pt, fill: rgb(\"{muted}\"))[{vector}]],",
                color = color, score = r.score, rating = r.rating,
                muted = p.muted, vector = esc(&r.vector),
            ));
        }
    }
    if !f.category.trim().is_empty() {
        meta.push_str(&format!("\n[#text(weight: \"bold\")[Category:]], [{}],", esc(&f.category)));
    }
    let status = if f.status.trim().is_empty() { "Open" } else { f.status.trim() };
    meta.push_str(&format!("\n[#text(weight: \"bold\")[Status:]], [{}],", esc(status)));
    if !f.affected.trim().is_empty() {
        meta.push_str(&format!("\n[#text(weight: \"bold\")[Affected:]], [{}],", esc(&f.affected)));
    }
    let _ = writeln!(
        s,
        "#table(columns: (86pt, 1fr), stroke: none, inset: (y: 3.5pt, x: 0pt),\n{meta}\n)"
    );

    if !f.description.trim().is_empty() {
        s.push_str("=== Description\n");
        let _ = writeln!(s, "{}\n", esc(f.description.trim()));
    }
    if !f.impact.trim().is_empty() {
        s.push_str("=== Impact\n");
        let _ = writeln!(s, "{}\n", esc(f.impact.trim()));
    }
    if !f.remediation.trim().is_empty() {
        s.push_str("=== Remediation\n");
        let _ = writeln!(s, "{}\n", esc(f.remediation.trim()));
    }

    // ISM references, quoted verbatim.
    let refs: Vec<_> = f.references.iter().filter_map(|id| packs::ism_control(id)).collect();
    if !refs.is_empty() {
        s.push_str("=== References — ACSC ISM\n");
        for c in refs {
            let _ = writeln!(
                s,
                "- #text(font: \"{mono}\", weight: \"bold\", size: 8.5pt)[{id}] — {text}",
                id = esc(&c.id),
                text = esc(&c.text),
            );
        }
        s.push('\n');
    }
    let _ = writeln!(s, "#v(4pt)\n#line(length: 100%, stroke: 0.5pt + rgb(\"{}\"))\n", p.table_border);
}

fn cover(s: &mut String, e: &Engagement, theme: &Theme, classification: &str, art_style: &str) {
    let p = &theme.palette;
    let _ = writeln!(
        s,
        "#set page(paper: \"a4\", margin: (x: 64pt, y: 76pt), fill: gradient.linear(angle: 30deg, rgb(\"{}\"), rgb(\"{}\"), rgb(\"{}\")), header: none, footer: none)",
        p.banner_start, p.primary, p.banner_end
    );
    let style = if art_style == "auto" { theme.cover_art.as_str() } else { art_style };
    s.push_str(&art::generate(
        style,
        theme.art_seed,
        &p.accent,
        &theme.typography.mono_font,
    ));
    if !classification.is_empty() {
        let _ = writeln!(
            s,
            "#box(stroke: 1pt + rgb(\"{}\"), radius: 3pt, inset: (x: 10pt, y: 5pt))[#text(fill: rgb(\"{}\"), size: 9pt, weight: \"bold\", tracking: 1.2pt)[{}]]",
            p.accent,
            p.accent,
            esc(classification)
        );
    }
    s.push_str("#v(1fr)\n");
    let _ = writeln!(
        s,
        "#text(fill: white, size: 27pt, weight: \"bold\")[{}]",
        esc(&e.title)
    );
    s.push_str("#v(4pt)\n");
    let _ = writeln!(s, "#line(length: 32%, stroke: 2.5pt + rgb(\"{}\"))", p.accent);
    s.push_str("#v(8pt)\n");
    let _ = writeln!(
        s,
        "#text(fill: rgb(\"#dbe7ea\"), size: 14pt)[{}]",
        esc(&e.client)
    );
    s.push_str("#v(1.6fr)\n");
    let prepared = if e.analyst_title.trim().is_empty() {
        esc(&e.analyst)
    } else {
        format!("{}, {}", esc(&e.analyst), esc(&e.analyst_title))
    };
    let _ = writeln!(
        s,
        "#grid(columns: (1fr, 1fr), align(left)[#text(fill: rgb(\"#c3d3d9\"), size: 9.5pt)[Prepared by {}]], align(right)[#text(fill: rgb(\"#c3d3d9\"), size: 9.5pt)[{} · Version {}]])",
        prepared,
        esc(&e.date),
        esc(&e.version)
    );
    s.push_str("#v(20pt)\n");
    s.push_str("#text(fill: rgb(\"#8ea6ad\"), size: 8pt)[Generated offline with IntelScribe]\n\n");
}

fn body_setup(s: &mut String, e: &Engagement, theme: &Theme, classification: &str) {
    let p = &theme.palette;
    let header = if classification.is_empty() {
        "none".to_string()
    } else {
        format!(
            "align(center, text(size: 8pt, weight: \"bold\", tracking: 1.2pt, fill: rgb(\"{}\"))[{}])",
            p.primary,
            esc(classification)
        )
    };
    let footer_centre = if classification.is_empty() {
        "[]".to_string()
    } else {
        format!(
            "align(center, text(size: 8pt, weight: \"bold\", fill: rgb(\"{}\"))[{}])",
            p.primary,
            esc(classification)
        )
    };
    let _ = writeln!(
        s,
        "#set page(fill: white, margin: (x: 56pt, top: 76pt, bottom: 64pt), header: {header}, footer: grid(columns: (1fr, 1fr, 1fr), align(left, text(size: 8pt, fill: rgb(\"{muted}\"))[{client}]), {footer_centre}, align(right, text(size: 8pt, fill: rgb(\"{muted}\"))[#context counter(page).display()])))",
        muted = p.muted,
        client = esc(&e.client),
    );
    s.push_str("#counter(page).update(1)\n\n");
}

fn exec_summary(s: &mut String, inc: &Incident, n: usize, theme: &Theme) {
    let p = &theme.palette;
    let _ = writeln!(s, "== Incident {}: {}", n, esc(&inc.title));
    let sev = theme.severity_color(inc.severity);

    // Optional CVSS row, only when a valid base vector is present.
    let cvss_row = match cvss::score_vector(&inc.cvss_vector) {
        Ok(r) if !inc.cvss_vector.trim().is_empty() => {
            let color = severity_rating_color(p, &r.rating);
            format!(
                "\n[#text(weight: \"bold\")[CVSS 3.1:]], [#box(fill: rgb(\"{color}\"), radius: 3pt, inset: (x: 7pt, y: 3.5pt))[#text(fill: white, size: 8.5pt, weight: \"bold\")[{score} {rating}]] #h(6pt) #text(font: \"{mono}\", size: 8pt, fill: rgb(\"{muted}\"))[{vector}]],",
                color = color,
                score = r.score,
                rating = r.rating,
                mono = esc_str(&theme.typography.mono_font),
                muted = p.muted,
                vector = esc(&r.vector),
            )
        }
        _ => String::new(),
    };

    // Optional ASD/ACSC category row.
    let acsc_row = match frameworks::acsc_category(&inc.acsc_category) {
        Some(cat) if !inc.acsc_category.trim().is_empty() => {
            let color = tier_color(p, &cat.tier);
            format!(
                "\n[#text(weight: \"bold\")[ASD category:]], [#box(fill: rgb(\"{color}\"), radius: 3pt, inset: (x: 7pt, y: 3.5pt))[#text(fill: white, size: 8.5pt, weight: \"bold\")[{id}]] #h(6pt) #text(size: 8.5pt)[{label}]],",
                color = color,
                id = esc(&cat.id),
                label = esc(&cat.label),
            )
        }
        _ => String::new(),
    };

    let _ = writeln!(
        s,
        "#table(columns: (110pt, 1fr), stroke: none, inset: (y: 4pt, x: 0pt),\n[#text(weight: \"bold\")[Incident ID:]], [#text(font: \"{mono}\", size: 9pt)[{id}]],\n[#text(weight: \"bold\")[Severity:]], [#box(fill: rgb(\"{sev}\"), radius: 3pt, inset: (x: 7pt, y: 3.5pt))[#text(fill: white, size: 8.5pt, weight: \"bold\", tracking: 0.8pt)[{sevlabel}]]],{cvss_row}{acsc_row}\n[#text(weight: \"bold\")[Status:]], [{status}],\n)",
        mono = esc_str(&theme.typography.mono_font),
        id = esc(&inc.incident_id),
        sev = sev,
        sevlabel = inc.severity.label().to_uppercase(),
        status = esc(&inc.status),
        cvss_row = cvss_row,
        acsc_row = acsc_row,
    );

    if !inc.overview.trim().is_empty() {
        s.push_str("=== Incident Overview\n");
        let _ = writeln!(s, "{}\n", esc(inc.overview.trim()));
    }
    if !inc.key_findings.is_empty() {
        s.push_str("=== Key Findings\n");
        for f in &inc.key_findings {
            let _ = writeln!(s, "- {}", esc(f));
        }
        s.push('\n');
    }
    if !inc.immediate_actions.is_empty() {
        s.push_str("=== Immediate Actions\n");
        for a in &inc.immediate_actions {
            let _ = writeln!(s, "- {}", esc(a));
        }
        s.push('\n');
    }
    if !inc.stakeholder_impact.trim().is_empty() {
        s.push_str("=== Stakeholder Impact\n");
        let _ = writeln!(s, "{}\n", esc(inc.stakeholder_impact.trim()));
    }
    let _ = writeln!(s, "#v(6pt)\n#line(length: 100%, stroke: 0.5pt + rgb(\"{}\"))\n", p.table_border);
}

fn technical_analysis(
    s: &mut String,
    inc: &Incident,
    n: usize,
    theme: &Theme,
    tpl: &ReportTemplate,
) {
    let p = &theme.palette;
    let mono = esc_str(&theme.typography.mono_font);
    let _ = writeln!(s, "#pagebreak()\n= Technical Analysis (Incident {n})");

    attack_map(s, inc, theme, tpl);

    // Affected systems & data.
    s.push_str("== Affected Systems & Data\n");
    guidance(s, theme, &tpl.affected_guidance);
    if !inc.hosts.is_empty() {
        s.push_str("=== Affected Systems\n");
        for h in &inc.hosts {
            let ip = if h.ip.trim().is_empty() {
                String::new()
            } else {
                format!(" ({})", esc(&h.ip))
            };
            let _ = writeln!(s, "*{}*{}\n\n{}\n", esc(&h.name), ip, esc(&h.description));
        }
    }
    if !inc.accounts.is_empty() {
        s.push_str("=== Affected Accounts\n");
        for a in &inc.accounts {
            let _ = writeln!(s, "- *{}* — {}", esc(&a.name), esc(&a.description));
        }
        s.push('\n');
    }

    // Evidence & detections.
    s.push_str("== Evidence Sources & Analysis\n");
    guidance(s, theme, &tpl.evidence_guidance);
    if inc.detections.is_empty() {
        let _ = writeln!(
            s,
            "#text(fill: rgb(\"{}\"))[No detections recorded yet.]\n",
            p.muted
        );
    }
    for (i, d) in inc.detections.iter().enumerate() {
        let title = if d.title.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", esc(&d.title))
        };
        let _ = writeln!(s, "=== Detection {}{}", i + 1, title);
        if !d.data_source.trim().is_empty() {
            let _ = writeln!(s, "*Data source:* {}\n", esc(&d.data_source));
        }
        if !d.query.trim().is_empty() {
            let _ = writeln!(s, "{}\n", raw_block(&d.query));
        }
        if !d.result.trim().is_empty() {
            let _ = writeln!(s, "*Result:* {}\n", esc(&d.result));
        }
    }

    // Indicators of compromise.
    s.push_str("== Indicators of Compromise (IoCs)\n");
    guidance(s, theme, &tpl.ioc_guidance);
    if inc.iocs.is_empty() {
        let _ = writeln!(
            s,
            "#text(fill: rgb(\"{}\"))[No indicators recorded yet.]\n",
            p.muted
        );
    } else {
        let mut rows = String::new();
        for ioc in &inc.iocs {
            let _ = writeln!(
                rows,
                "[#text(font: \"{mono}\", size: 8pt)[{}]], [{}], [{}],",
                esc(&ioc.indicator),
                esc(&ioc.ioc_type),
                esc(&ioc.context)
            );
        }
        let _ = writeln!(
            s,
            "#table(columns: (2.4fr, 1.1fr, 2.2fr), stroke: 0.5pt + rgb(\"{border}\"), inset: 6pt, fill: (x, y) => if y == 0 {{ rgb(\"{primary}\") }} else if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{},\n{},\n{},\n{rows})\n",
            table_header_cell("Indicator"),
            table_header_cell("Type"),
            table_header_cell("Context"),
            border = p.table_border,
            primary = p.primary,
            stripe = p.stripe,
            rows = rows,
        );
    }

    // Root cause analysis.
    if !inc.root_cause.trim().is_empty() {
        s.push_str("== Root Cause Analysis\n");
        guidance(s, theme, &tpl.root_cause_guidance);
        let _ = writeln!(s, "{}\n", esc(inc.root_cause.trim()));
    }

    // Technical timeline, grouped in kill-chain order.
    s.push_str("== Technical Timeline\n");
    guidance(s, theme, &tpl.timeline_guidance);
    let mut any_events = false;
    for phase in Phase::ALL {
        let mut events: Vec<_> = inc.events.iter().filter(|ev| ev.phase == phase).collect();
        if events.is_empty() {
            continue;
        }
        any_events = true;
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let _ = writeln!(s, "=== {}", phase.label());
        let mut rows = String::new();
        for ev in events {
            let _ = writeln!(
                rows,
                "[#text(font: \"{mono}\", size: 8pt)[{}]], [{}], [{}],",
                esc(&ev.timestamp),
                esc(&ev.host),
                esc(&ev.description)
            );
        }
        let _ = writeln!(
            s,
            "#table(columns: (66pt, 82pt, 1fr), stroke: 0.5pt + rgb(\"{border}\"), inset: 6pt, fill: (x, y) => if y == 0 {{ rgb(\"{primary}\") }} else if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{},\n{},\n{},\n{rows})\n",
            table_header_cell("Time"),
            table_header_cell("Host"),
            table_header_cell("Activity"),
            border = p.table_border,
            primary = p.primary,
            stripe = p.stripe,
            rows = rows,
        );
    }
    if !any_events {
        let _ = writeln!(
            s,
            "#text(fill: rgb(\"{}\"))[No timeline events recorded yet.]\n",
            p.muted
        );
    }

    // MITRE ATT&CK mapping.
    s.push_str("== Nature of the Attack — MITRE ATT&CK Mapping\n");
    guidance(s, theme, &tpl.nature_guidance);
    if inc.techniques.is_empty() {
        let _ = writeln!(
            s,
            "#text(fill: rgb(\"{}\"))[No techniques mapped yet.]\n",
            p.muted
        );
    } else {
        let mut techniques = inc.techniques.clone();
        techniques.sort_by(|a, b| a.id.cmp(&b.id));
        let mut rows = String::new();
        for t in &techniques {
            let _ = writeln!(
                rows,
                "[#text(font: \"{mono}\", size: 8.5pt)[{}]], [{}], [{}],",
                esc(&t.id),
                esc(&t.name),
                esc(&t.tactic)
            );
        }
        let _ = writeln!(
            s,
            "#table(columns: (76pt, 1fr, 130pt), stroke: 0.5pt + rgb(\"{border}\"), inset: 6pt, fill: (x, y) => if y == 0 {{ rgb(\"{primary}\") }} else if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{},\n{},\n{},\n{rows})\n",
            table_header_cell("Technique"),
            table_header_cell("Name"),
            table_header_cell("Tactic"),
            border = p.table_border,
            primary = p.primary,
            stripe = p.stripe,
            rows = rows,
        );
        attack_matrix(s, inc, theme);
    }

    recommendations(s, inc, theme, tpl);
    framework_alignment(s, inc, theme);
    regulatory_section(s, inc, theme);
}

/// Regulatory & Reporting Obligations: deterministic SOCI Act and OAIC NDB
/// determinations from the analyst's assessment inputs.
fn regulatory_section(s: &mut String, inc: &Incident, theme: &Theme) {
    let p = &theme.palette;
    let reg = &inc.regulatory;
    let engaged = reg.critical_infrastructure
        || reg.personal_info_involved
        || !reg.soci_impact.trim().is_empty();
    if !engaged {
        return;
    }
    s.push_str("== Regulatory & Reporting Obligations\n");
    let _ = writeln!(
        s,
        "#text(size: 8.5pt, fill: rgb(\"{}\"), style: \"italic\")[Advisory assessment derived from the analyst's inputs against the SOCI Act and the OAIC Notifiable Data Breaches scheme. This is decision support, not legal advice — confirm obligations with legal/privacy counsel.]\n",
        p.muted
    );

    for det in [frameworks::assess_soci(reg), frameworks::assess_ndb(reg)] {
        let edge = if det.obligation { &p.severity_high } else { &p.accent };
        let _ = writeln!(
            s,
            "#block(width: 100%, fill: rgb(\"{stripe}\"), stroke: (left: 3pt + rgb(\"{edge}\")), inset: 10pt, radius: 3pt, above: 8pt)[#text(weight: \"bold\", size: 10pt, fill: rgb(\"{primary}\"))[{headline}]#linebreak()#text(size: 9.5pt)[{detail}]]\n",
            stripe = p.stripe,
            edge = edge,
            primary = p.primary,
            headline = esc(&det.headline),
            detail = esc(&det.detail),
        );
    }
}

/// Essential Eight Maturity Assessment (engagement-level): a matrix of the
/// eight strategies with current vs target maturity and a met/gap status.
fn essential_eight_section(s: &mut String, e: &Engagement, theme: &Theme) {
    let p = &theme.palette;
    if e.essential_eight.is_empty() {
        return;
    }
    s.push_str("#pagebreak()\n= Essential Eight Maturity Assessment\n");
    let _ = writeln!(
        s,
        "#text(size: 8.5pt, fill: rgb(\"{}\"), style: \"italic\")[Self-assessed maturity against the ACSC Essential Eight. Maturity Levels: ML0 posture weaknesses; ML1 commodity tradecraft; ML2 modest step-up; ML3 adaptive adversaries.]\n",
        p.muted
    );

    let mut rows = String::new();
    for item in &e.essential_eight {
        let current = item.current_level.min(3);
        let target = item.target_level.min(3);
        let met = current >= target;
        let cur_color = if met { &p.severity_low } else { &p.severity_high };
        let status = if met {
            "Met".to_string()
        } else {
            format!("Gap +{}", target - current)
        };
        let status_color = if met { &p.severity_low } else { &p.severity_high };
        let _ = writeln!(
            rows,
            "[{strategy}], [#box(fill: rgb(\"{cur_color}\"), radius: 3pt, inset: (x: 6pt, y: 3pt))[#text(fill: white, size: 8.5pt, weight: \"bold\")[{cur}]]], [#text(size: 8.5pt)[{tgt}]], [#text(fill: rgb(\"{status_color}\"), weight: \"bold\", size: 8.5pt)[{status}]], [#text(size: 8.5pt)[{notes}]],",
            strategy = esc(&item.strategy),
            cur_color = cur_color,
            cur = frameworks::e8_level_name(current),
            tgt = frameworks::e8_level_name(target),
            status_color = status_color,
            status = status,
            notes = esc(&item.notes),
        );
    }
    let _ = writeln!(
        s,
        "#table(columns: (1.6fr, 58pt, 52pt, 64pt, 1.7fr), stroke: 0.5pt + rgb(\"{border}\"), inset: 6pt, fill: (x, y) => if y == 0 {{ rgb(\"{primary}\") }} else if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{h1},\n{h2},\n{h3},\n{h4},\n{h5},\n{rows})\n",
        h1 = table_header_cell("Mitigation Strategy"),
        h2 = table_header_cell("Current"),
        h3 = table_header_cell("Target"),
        h4 = table_header_cell("Status"),
        h5 = table_header_cell("Notes"),
        border = p.table_border,
        primary = p.primary,
        stripe = p.stripe,
        rows = rows,
    );
}

/// Framework Alignment: quotes the analyst-cited ISM controls verbatim from
/// the bundled ACSC ISM OSCAL catalog.
fn framework_alignment(s: &mut String, inc: &Incident, theme: &Theme) {
    let p = &theme.palette;
    let resolved: Vec<_> = inc
        .ism_controls
        .iter()
        .filter_map(|id| packs::ism_control(id))
        .collect();
    if resolved.is_empty() {
        return;
    }
    s.push_str("== Framework Alignment — ACSC ISM\n");
    let _ = writeln!(
        s,
        "#text(size: 8.5pt, fill: rgb(\"{}\"), style: \"italic\")[Controls quoted verbatim from the ACSC Information Security Manual (ISM {}). Each control text is reproduced for the analyst's convenience; refer to cyber.gov.au for the authoritative version.]\n",
        p.muted,
        esc(packs::ism_version())
    );
    let mono = esc_str(&theme.typography.mono_font);
    let mut rows = String::new();
    for c in &resolved {
        let meta = if c.updated.is_empty() {
            String::new()
        } else {
            format!(
                "#linebreak()#text(size: 6.8pt, fill: rgb(\"{}\"))[Rev {} · {}]",
                p.muted,
                esc(&c.revision),
                esc(&c.updated)
            )
        };
        let _ = writeln!(
            rows,
            "[#text(font: \"{mono}\", size: 8pt, weight: \"bold\")[{}]{meta}], [#text(size: 8pt, fill: rgb(\"{}\"))[{}]#linebreak()#text(size: 9pt)[{}]],",
            esc(&c.id),
            p.muted,
            esc(&c.topic),
            esc(&c.text)
        );
    }
    let _ = writeln!(
        s,
        "#table(columns: (74pt, 1fr), stroke: 0.5pt + rgb(\"{border}\"), inset: 6pt, fill: (x, y) => if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{rows})\n",
        border = p.table_border,
        stripe = p.stripe,
    );
}

/// Attack Path Overview: a kill-chain strip plus a host-to-host movement
/// diagram, both derived from the incident's timeline events.
fn attack_map(s: &mut String, inc: &Incident, theme: &Theme, tpl: &ReportTemplate) {
    let p = &theme.palette;
    if inc.events.is_empty() && inc.hosts.len() < 2 {
        return;
    }
    s.push_str("== Attack Path Overview\n");
    guidance(s, theme, &tpl.attack_map_guidance);

    // --- Kill chain strip ---
    let attack_phases = &Phase::ALL[..7];
    let short = |ph: Phase| match ph {
        Phase::Reconnaissance => "RECON",
        Phase::InitialCompromise => "INITIAL",
        Phase::CommandAndControl => "C2",
        Phase::Enumeration => "ENUM",
        Phase::LateralMovement => "LATERAL",
        Phase::DataAccess => "DATA",
        Phase::MalwareActivity => "MALWARE",
        _ => "",
    };
    let mut cells = String::new();
    for &ph in attack_phases {
        let count = inc.events.iter().filter(|e| e.phase == ph).count();
        let (fill, label_color, sub_color, sub) = if count > 0 {
            (p.accent.as_str(), "#ffffff", "#ffffff", format!("{count} event{}", if count == 1 { "" } else { "s" }))
        } else {
            (p.stripe.as_str(), p.muted.as_str(), p.muted.as_str(), "—".to_string())
        };
        let _ = writeln!(
            cells,
            "box(width: 100%, fill: rgb(\"{fill}\"), radius: 4pt, inset: (x: 2pt, y: 7pt))[#align(center)[#text(size: 7.5pt, weight: \"bold\", fill: rgb(\"{label_color}\"))[{}]#linebreak()#text(size: 6.8pt, fill: rgb(\"{sub_color}\"))[{sub}]]],",
            short(ph)
        );
    }
    let _ = writeln!(
        s,
        "#grid(columns: (1fr, 1fr, 1fr, 1fr, 1fr, 1fr, 1fr), gutter: 5pt,\n{cells})\n#v(6pt)"
    );

    // --- Host movement diagram ---
    let mut sorted_events: Vec<_> = inc.events.iter().collect();
    sorted_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let mut order: Vec<String> = Vec::new();
    for ev in &sorted_events {
        let h = ev.host.trim();
        if !h.is_empty() && !order.iter().any(|x| x.eq_ignore_ascii_case(h)) {
            order.push(h.to_string());
        }
    }
    for h in &inc.hosts {
        let name = h.name.trim();
        if !name.is_empty() && !order.iter().any(|x| x.eq_ignore_ascii_case(name)) {
            order.push(name.to_string());
        }
    }

    if order.len() >= 2 {
        // Directed movement edges from chronological host transitions.
        let idx_of = |name: &str, order: &[String]| {
            order.iter().position(|x| x.eq_ignore_ascii_case(name))
        };
        let mut edges: Vec<(usize, usize)> = Vec::new();
        let mut cur: Option<usize> = None;
        for ev in &sorted_events {
            let h = ev.host.trim();
            if h.is_empty() {
                continue;
            }
            if let Some(i) = idx_of(h, &order) {
                if let Some(c) = cur {
                    if c != i && !edges.contains(&(c, i)) {
                        edges.push((c, i));
                    }
                }
                cur = Some(i);
            }
        }

        let per_row = 4usize;
        let (node_w, node_h, gap_x, row_h) = (104.0f64, 40.0f64, 18.0f64, 88.0f64);
        let pos = |i: usize| -> (f64, f64) {
            let row = i / per_row;
            let col = i % per_row;
            (col as f64 * (node_w + gap_x) + 4.0, row as f64 * row_h + 8.0)
        };
        let rows = order.len().div_ceil(per_row);
        let height = rows as f64 * row_h - 30.0;

        let _ = writeln!(s, "#block(width: 100%, height: {height:.0}pt, above: 10pt, below: 6pt)[");

        // Edges first, under the nodes.
        for &(a, b) in &edges {
            let (ax, ay) = pos(a);
            let (bx, by) = pos(b);
            let (cax, cay) = (ax + node_w / 2.0, ay + node_h / 2.0);
            let (cbx, cby) = (bx + node_w / 2.0, by + node_h / 2.0);
            let (dx, dy) = (cbx - cax, cby - cay);
            let len = (dx * dx + dy * dy).sqrt().max(1.0);
            let (ux, uy) = (dx / len, dy / len);
            let (sx, sy) = (cax + ux * 56.0, cay + uy * 24.0);
            let (ex, ey) = (cbx - ux * 60.0, cby - uy * 26.0);
            let _ = writeln!(
                s,
                "#place(top + left, line(start: ({sx:.1}pt, {sy:.1}pt), end: ({ex:.1}pt, {ey:.1}pt), stroke: 1.1pt + rgb(\"{}\")))",
                p.primary
            );
            // Arrowhead triangle, vertices normalised to their bounding box.
            let (tx, ty) = (ex + ux * 7.0, ey + uy * 7.0);
            let (bxp, byp) = (tx - ux * 8.0, ty - uy * 8.0);
            let (px, py) = (-uy, ux);
            let pts = [
                (tx, ty),
                (bxp + px * 4.0, byp + py * 4.0),
                (bxp - px * 4.0, byp - py * 4.0),
            ];
            let min_x = pts.iter().map(|q| q.0).fold(f64::MAX, f64::min);
            let min_y = pts.iter().map(|q| q.1).fold(f64::MAX, f64::min);
            let verts = pts
                .iter()
                .map(|q| format!("({:.1}pt, {:.1}pt)", q.0 - min_x, q.1 - min_y))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                s,
                "#place(top + left, dx: {min_x:.1}pt, dy: {min_y:.1}pt, polygon(fill: rgb(\"{}\"), {verts}))",
                p.primary
            );
        }

        // Nodes.
        for (i, name) in order.iter().enumerate() {
            let (x, y) = pos(i);
            let ip = inc
                .hosts
                .iter()
                .find(|h| h.name.trim().eq_ignore_ascii_case(name))
                .map(|h| h.ip.trim().to_string())
                .unwrap_or_default();
            let (fill, stroke, name_color, ip_color) = if i == 0 {
                (p.accent.as_str(), format!("1.2pt + rgb(\"{}\")", p.accent), "#ffffff", "#ffffff")
            } else {
                (p.stripe.as_str(), format!("1pt + rgb(\"{}\")", p.primary), p.primary.as_str(), p.muted.as_str())
            };
            let ip_line = if ip.is_empty() {
                String::new()
            } else {
                format!("#linebreak()#text(size: 6.3pt, fill: rgb(\"{ip_color}\"))[{}]", esc(&ip))
            };
            let _ = writeln!(
                s,
                "#place(top + left, dx: {x:.1}pt, dy: {y:.1}pt, rect(width: {node_w}pt, height: {node_h}pt, radius: 5pt, fill: rgb(\"{fill}\"), stroke: {stroke})[#align(center + horizon)[#text(size: 8pt, weight: \"bold\", fill: rgb(\"{name_color}\"))[{}]{ip_line}]])",
                esc(name)
            );
        }
        s.push_str("]\n");
        let _ = writeln!(
            s,
            "#text(size: 7.5pt, fill: rgb(\"{}\"))[Patient zero highlighted; arrows show observed movement between hosts in timeline order.]\n",
            p.muted
        );
    }

    // Movement narrative from lateral-movement events.
    let lateral: Vec<_> = sorted_events
        .iter()
        .filter(|e| e.phase == Phase::LateralMovement)
        .collect();
    if !lateral.is_empty() {
        s.push_str("=== Observed Movement\n");
        for ev in lateral {
            let mono = esc_str(&theme.typography.mono_font);
            let host = if ev.host.trim().is_empty() {
                String::new()
            } else {
                format!(" *{}* —", esc(&ev.host))
            };
            let _ = writeln!(
                s,
                "- #text(font: \"{mono}\", size: 8.5pt)[{}]{host} {}",
                esc(&ev.timestamp),
                esc(&ev.description)
            );
        }
        s.push('\n');
    }
}

/// Recommendations & Mitigations: controls auto-derived from the mapped
/// ATT&CK techniques via the mitigations pack, an Essential Eight rollup,
/// and the analyst's own recommendations.
fn recommendations(s: &mut String, inc: &Incident, theme: &Theme, tpl: &ReportTemplate) {
    let p = &theme.palette;
    if inc.techniques.is_empty() && inc.additional_recommendations.is_empty() {
        return;
    }
    s.push_str("== Recommendations & Mitigations\n");
    guidance(s, theme, &tpl.recommendations_guidance);

    // Control name -> (reference, techniques it addresses).
    let mut controls: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    let mut e8: Vec<String> = Vec::new();
    for t in &inc.techniques {
        if t.id.trim().is_empty() {
            continue;
        }
        if let Some(entry) = packs::mitigations_for(&t.id) {
            for c in entry.controls {
                let slot = controls.entry(c.name).or_insert((c.reference, Vec::new()));
                if !slot.1.contains(&t.id) {
                    slot.1.push(t.id.clone());
                }
            }
            for strategy in entry.essential_eight {
                if !e8.contains(&strategy) {
                    e8.push(strategy);
                }
            }
        }
    }

    if !controls.is_empty() {
        s.push_str("=== Priority Controls (derived from observed techniques)\n");
        let mut ranked: Vec<_> = controls.into_iter().collect();
        ranked.sort_by(|a, b| b.1 .1.len().cmp(&a.1 .1.len()).then(a.0.cmp(&b.0)));
        let mono = esc_str(&theme.typography.mono_font);
        let mut rows = String::new();
        for (name, (reference, techniques)) in &ranked {
            let _ = writeln!(
                rows,
                "[{}], [#text(font: \"{mono}\", size: 7.5pt)[{}]], [#text(size: 8.5pt)[{}]],",
                esc(name),
                esc(&techniques.join(", ")),
                esc(reference)
            );
        }
        let _ = writeln!(
            s,
            "#table(columns: (2.7fr, 1.3fr, 1.3fr), stroke: 0.5pt + rgb(\"{border}\"), inset: 6pt, fill: (x, y) => if y == 0 {{ rgb(\"{primary}\") }} else if calc.even(y) {{ rgb(\"{stripe}\") }} else {{ white }},\n{},\n{},\n{},\n{rows})\n",
            table_header_cell("Recommended Control"),
            table_header_cell("Addresses"),
            table_header_cell("Reference"),
            border = p.table_border,
            primary = p.primary,
            stripe = p.stripe,
            rows = rows,
        );
    }

    if !e8.is_empty() {
        let items = e8
            .iter()
            .map(|x| esc(x))
            .collect::<Vec<_>>()
            .join(" · ");
        let _ = writeln!(
            s,
            "#block(width: 100%, fill: rgb(\"{stripe}\"), stroke: (left: 3pt + rgb(\"{accent}\")), inset: 10pt, radius: 3pt)[#text(weight: \"bold\", size: 9.5pt, fill: rgb(\"{primary}\"))[ACSC Essential Eight — strategies relevant to this incident]#linebreak()#text(size: 9.5pt)[{items}]]\n",
            stripe = p.stripe,
            accent = p.accent,
            primary = p.primary,
        );
    }

    if !inc.additional_recommendations.is_empty() {
        s.push_str("=== Analyst Recommendations\n");
        for r in &inc.additional_recommendations {
            let _ = writeln!(s, "- {}", esc(r));
        }
        s.push('\n');
    }
}
