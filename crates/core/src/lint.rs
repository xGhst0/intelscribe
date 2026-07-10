//! Report linter: deterministic completeness, consistency and sanitisation
//! checks over an engagement. Findings are advisory authoring aids surfaced in
//! the editor; they never block rendering.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::extract;
use crate::model::{Engagement, Incident};

#[derive(Debug, Clone, Serialize)]
pub struct LintFinding {
    /// "error" | "warning" | "info".
    pub level: String,
    pub category: String,
    pub message: String,
    pub location: String,
}

fn level_rank(level: &str) -> u8 {
    match level {
        "error" => 0,
        "warning" => 1,
        _ => 2,
    }
}

fn technique_ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bT\d{4}(?:\.\d{3})?\b").unwrap())
}

/// Collect all free-text prose in an incident into one string for scanning.
fn incident_prose(inc: &Incident) -> String {
    let mut parts: Vec<&str> = vec![&inc.overview, &inc.root_cause, &inc.stakeholder_impact];
    parts.extend(inc.key_findings.iter().map(String::as_str));
    parts.extend(inc.immediate_actions.iter().map(String::as_str));
    parts.extend(inc.additional_recommendations.iter().map(String::as_str));
    for d in &inc.detections {
        parts.push(&d.title);
        parts.push(&d.data_source);
        parts.push(&d.query);
        parts.push(&d.result);
    }
    for ev in &inc.events {
        parts.push(&ev.description);
    }
    parts.join("\n")
}

fn is_private_ipv4(ip: &str) -> bool {
    let clean = extract::refang(ip);
    let octets: Vec<u16> = clean
        .split('.')
        .filter_map(|o| o.trim().parse().ok())
        .collect();
    if octets.len() != 4 {
        return false;
    }
    let (a, b) = (octets[0], octets[1]);
    a == 10
        || (a == 192 && b == 168)
        || (a == 172 && (16..=31).contains(&b))
        || a == 127
}

pub fn lint(e: &Engagement) -> Vec<LintFinding> {
    let mut out: Vec<LintFinding> = Vec::new();
    let mut add = |level: &str, category: &str, message: String, location: &str| {
        out.push(LintFinding {
            level: level.to_string(),
            category: category.to_string(),
            message,
            location: location.to_string(),
        });
    };

    // ---- Engagement-level ----
    if e.incidents.is_empty() {
        add("error", "completeness", "The report has no incidents.".into(), "Engagement");
    }
    if e.classification.trim().is_empty() {
        add("warning", "classification", "No classification marking is set.".into(), "Engagement");
    }
    if e.client.trim().is_empty() {
        add("info", "completeness", "No client / organisation name is set.".into(), "Engagement");
    }

    // ---- Per-incident ----
    for (i, inc) in e.incidents.iter().enumerate() {
        let loc = format!("Incident {}", i + 1);
        let prose = incident_prose(inc);

        // Completeness.
        if inc.title.trim().is_empty() {
            add("warning", "completeness", "Incident has no title.".into(), &loc);
        }
        if inc.overview.trim().is_empty() {
            add("warning", "completeness", "No incident overview.".into(), &loc);
        }
        if inc.detections.is_empty() {
            add("warning", "completeness", "No detections recorded.".into(), &loc);
        }
        if inc.incident_id.trim().is_empty() {
            add("info", "completeness", "No incident ID set.".into(), &loc);
        }
        if inc.techniques.is_empty() {
            add("info", "coverage", "No ATT&CK techniques mapped.".into(), &loc);
        }

        // Techniques referenced in prose but missing from the table.
        let mapped: BTreeSet<String> =
            inc.techniques.iter().map(|t| t.id.trim().to_uppercase()).collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for m in technique_ref_re().find_iter(&prose) {
            let id = m.as_str().to_uppercase();
            if seen.insert(id.clone()) && !mapped.contains(&id) {
                add(
                    "warning",
                    "consistency",
                    format!("ATT&CK technique {id} is referenced in the text but not listed in the technique table."),
                    &loc,
                );
            }
        }

        // Timeline hosts not present under Affected Systems.
        let host_names: BTreeSet<String> =
            inc.hosts.iter().map(|h| h.name.trim().to_lowercase()).filter(|n| !n.is_empty()).collect();
        let mut flagged_hosts: BTreeSet<String> = BTreeSet::new();
        for ev in &inc.events {
            let h = ev.host.trim();
            if h.is_empty() {
                continue;
            }
            let key = h.to_lowercase();
            if !host_names.contains(&key) && flagged_hosts.insert(key) {
                add(
                    "warning",
                    "consistency",
                    format!("Timeline references host '{h}' which is not listed under Affected Systems."),
                    &loc,
                );
            }
        }

        // Duplicate host names with conflicting IPs.
        for a in 0..inc.hosts.len() {
            for b in (a + 1)..inc.hosts.len() {
                let (ha, hb) = (&inc.hosts[a], &inc.hosts[b]);
                if !ha.name.trim().is_empty()
                    && ha.name.trim().eq_ignore_ascii_case(hb.name.trim())
                    && ha.ip.trim() != hb.ip.trim()
                {
                    add(
                        "warning",
                        "consistency",
                        format!("Host '{}' is listed with conflicting addresses ('{}' and '{}').", ha.name.trim(), ha.ip.trim(), hb.ip.trim()),
                        &loc,
                    );
                }
            }
        }

        // Indicators present in prose but absent from the IoC table.
        let table: BTreeSet<String> = inc
            .iocs
            .iter()
            .map(|ioc| extract::refang(&ioc.indicator).to_lowercase())
            .collect();
        let mut flagged_iocs: BTreeSet<String> = BTreeSet::new();
        for ioc in extract::extract_iocs(&prose) {
            // Skip filenames/registry — too noisy for a prose-vs-table check.
            if ioc.ioc_type == "Filename" || ioc.ioc_type == "Registry Key" {
                continue;
            }
            let key = extract::refang(&ioc.indicator).to_lowercase();
            if !table.contains(&key) && flagged_iocs.insert(key) {
                add(
                    "info",
                    "consistency",
                    format!("Indicator '{}' appears in the text but is not in the IoC table.", ioc.indicator),
                    &loc,
                );
            }
        }

        // Sanitisation: internal/private IPs listed as indicators.
        for ioc in &inc.iocs {
            if ioc.ioc_type.contains("IPv4") && is_private_ipv4(&ioc.indicator) {
                add(
                    "info",
                    "sanitisation",
                    format!("Internal IP '{}' is listed as an indicator — review before external release.", ioc.indicator),
                    &loc,
                );
            }
        }
    }

    out.sort_by(|a, b| level_rank(&a.level).cmp(&level_rank(&b.level)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Detection, Host, Ioc, TechniqueRef, TimelineEvent};

    fn base() -> Engagement {
        let mut e = Engagement {
            classification: "OFFICIAL".into(),
            client: "Acme".into(),
            ..Default::default()
        };
        e.incidents.push(Incident {
            title: "Test".into(),
            incident_id: "id-1".into(),
            overview: "An overview.".into(),
            detections: vec![Detection { title: "d".into(), ..Default::default() }],
            techniques: vec![TechniqueRef { id: "T1055".into(), ..Default::default() }],
            ..Default::default()
        });
        e
    }

    fn has(findings: &[LintFinding], needle: &str) -> bool {
        findings.iter().any(|f| f.message.contains(needle))
    }

    #[test]
    fn clean_incident_has_no_warnings_or_errors() {
        let findings = lint(&base());
        assert!(!findings.iter().any(|f| f.level != "info"), "unexpected: {findings:?}");
    }

    #[test]
    fn flags_unmapped_technique_in_prose() {
        let mut e = base();
        e.incidents[0].root_cause = "The attacker used T1003.001 to dump LSASS.".into();
        let findings = lint(&e);
        assert!(has(&findings, "T1003.001 is referenced"), "{findings:?}");
    }

    #[test]
    fn flags_timeline_host_not_in_systems() {
        let mut e = base();
        e.incidents[0].hosts = vec![Host { name: "WKS-1".into(), ..Default::default() }];
        e.incidents[0].events = vec![TimelineEvent { host: "DC-99".into(), ..Default::default() }];
        let findings = lint(&e);
        assert!(has(&findings, "DC-99"), "{findings:?}");
    }

    #[test]
    fn flags_internal_ip_indicator() {
        let mut e = base();
        e.incidents[0].iocs = vec![Ioc {
            indicator: "10[.]0[.]0[.]5".into(),
            ioc_type: "IPv4".into(),
            context: String::new(),
        }];
        let findings = lint(&e);
        assert!(has(&findings, "Internal IP"), "{findings:?}");
    }

    #[test]
    fn missing_overview_is_a_warning() {
        let mut e = base();
        e.incidents[0].overview = String::new();
        let findings = lint(&e);
        assert!(findings.iter().any(|f| f.level == "warning" && f.message.contains("overview")));
    }
}
