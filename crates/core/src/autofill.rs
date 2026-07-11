//! Deterministic exec-summary drafting: composes prose from the incident
//! model using sentence templates. Same input always yields the same draft.

use serde::Serialize;

use crate::model::{Engagement, Incident, Phase, Severity};

fn severity_rank(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Informational => 4,
    }
}

/// Draft a penetration-test executive summary from the findings: count,
/// severity breakdown, the most significant finding, and an overall risk
/// framing. Deterministic.
pub fn draft_pentest_summary(e: &Engagement) -> String {
    let n = e.findings.len();
    if n == 0 {
        return String::new();
    }
    let count = |sev: Severity| e.findings.iter().filter(|f| f.severity == sev).count();
    let (c, h, m, l, i) = (
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        count(Severity::Informational),
    );

    let mut parts: Vec<String> = Vec::new();
    let subject = if e.client.trim().is_empty() {
        "The assessment".to_string()
    } else {
        format!("The assessment of {}", e.client.trim())
    };
    parts.push(format!(
        "{subject} identified {n} finding{}.",
        if n == 1 { "" } else { "s" }
    ));

    let mut sev_bits = Vec::new();
    for (num, word) in [(c, "critical"), (h, "high"), (m, "medium"), (l, "low"), (i, "informational")] {
        if num > 0 {
            sev_bits.push(format!("{num} {word}"));
        }
    }
    if !sev_bits.is_empty() {
        parts.push(format!("By severity: {}.", join_list(&sev_bits)));
    }

    if let Some(top) = e.findings.iter().min_by_key(|f| severity_rank(f.severity)) {
        if !top.title.trim().is_empty() {
            parts.push(format!(
                "The most significant finding is {} ({} severity).",
                top.title.trim(),
                top.severity.label().to_lowercase()
            ));
        }
    }

    if c > 0 || h > 0 {
        parts.push(
            "Collectively the findings present a material risk that a moderately skilled attacker \
             could exploit; prioritised remediation of the higher-severity findings is recommended."
                .to_string(),
        );
    } else {
        parts.push(
            "The findings represent a low aggregate risk and can be addressed through routine \
             hardening within normal maintenance windows."
                .to_string(),
        );
    }
    parts.join(" ")
}

#[derive(Debug, Clone, Serialize)]
pub struct DraftSummary {
    pub overview: String,
    pub key_findings: Vec<String>,
    pub stakeholder_impact: String,
}

fn first_sentence(text: &str) -> String {
    let t = text.trim();
    match t.find(". ") {
        Some(i) => t[..i + 1].to_string(),
        None => t.to_string(),
    }
}

fn join_list(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        2 => format!("{} and {}", items[0], items[1]),
        n => format!("{} and {}", items[..n - 1].join(", "), items[n - 1]),
    }
}

pub fn draft(inc: &Incident) -> DraftSummary {
    let mut overview = Vec::<String>::new();

    // Initial access.
    let initial = inc
        .events
        .iter()
        .filter(|e| e.phase == Phase::InitialCompromise)
        .min_by(|a, b| a.timestamp.cmp(&b.timestamp))
        .or_else(|| inc.events.iter().min_by(|a, b| a.timestamp.cmp(&b.timestamp)));
    if let Some(ev) = initial {
        let host = if ev.host.trim().is_empty() {
            String::new()
        } else {
            format!(" on host {}", ev.host.trim())
        };
        overview.push(format!(
            "The investigation determined that initial access occurred at {}{}. {}",
            ev.timestamp.trim(),
            host,
            first_sentence(&ev.description)
        ));
    }

    // Command and control.
    let c2: Vec<String> = inc
        .iocs
        .iter()
        .filter(|i| i.ioc_type.to_ascii_lowercase().contains("c2"))
        .map(|i| i.indicator.clone())
        .collect();
    if !c2.is_empty() {
        overview.push(format!(
            "Command-and-control infrastructure was identified at {}.",
            join_list(&c2)
        ));
    }

    // Scope of movement.
    let hosts: Vec<String> = inc.hosts.iter().map(|h| h.name.clone()).filter(|n| !n.is_empty()).collect();
    let lateral = inc.events.iter().any(|e| e.phase == Phase::LateralMovement);
    if hosts.len() > 1 && lateral {
        overview.push(format!(
            "The adversary moved laterally across {} hosts ({}).",
            hosts.len(),
            join_list(&hosts)
        ));
    } else if hosts.len() == 1 {
        overview.push(format!("Activity was confined to the host {}.", hosts[0]));
    }

    // Technique-driven colour.
    let has = |prefix: &str| inc.techniques.iter().any(|t| t.id.starts_with(prefix));
    let mut caps = Vec::new();
    if has("T1003") || has("T1558") {
        caps.push("harvested credential material".to_string());
    }
    let persistence = ["T1053", "T1547", "T1543", "T1136", "T1098"]
        .iter()
        .filter(|p| has(p))
        .count();
    if persistence > 0 {
        caps.push(format!(
            "established {persistence} independent persistence mechanism{}",
            if persistence == 1 { "" } else { "s" }
        ));
    }
    if has("T1041") || has("T1071") {
        caps.push("maintained an active exfiltration-capable channel".to_string());
    }
    if !caps.is_empty() {
        overview.push(format!("During the intrusion the adversary {}.", join_list(&caps)));
    }

    overview.push(format!(
        "The incident is assessed as {} severity and is currently {}.",
        inc.severity.label(),
        if inc.status.trim().is_empty() { "under investigation" } else { inc.status.trim() }
    ));

    // Key findings: one per detection, capped at six.
    let mut key_findings: Vec<String> = inc
        .detections
        .iter()
        .filter(|d| !d.title.trim().is_empty() || !d.result.trim().is_empty())
        .take(6)
        .map(|d| {
            if d.title.trim().is_empty() {
                first_sentence(&d.result)
            } else if d.result.trim().is_empty() {
                d.title.trim().to_string()
            } else {
                format!("{} — {}", d.title.trim(), first_sentence(&d.result))
            }
        })
        .collect();
    if key_findings.is_empty() {
        // Fall back to technique-based findings.
        key_findings = inc
            .techniques
            .iter()
            .take(6)
            .map(|t| format!("{} ({}) observed — {}.", t.name, t.id, t.tactic))
            .collect();
    }

    // Stakeholder impact.
    let domain_scope = inc.techniques.iter().any(|t| t.id.starts_with("T1003"))
        || inc
            .hosts
            .iter()
            .any(|h| h.description.to_ascii_lowercase().contains("domain controller"));
    let mut impact = Vec::new();
    if domain_scope {
        impact.push(
            "Credential material was exposed at a level that requires the affected domain to be \
             treated as compromised; all accounts, including privileged and service accounts, \
             should be considered potentially exposed until reset."
                .to_string(),
        );
    }
    match inc.severity {
        Severity::Critical | Severity::High => impact.push(
            "Stakeholders should anticipate significant remediation effort with associated \
             operational downtime, and should assess breach-notification obligations (including \
             the OAIC Notifiable Data Breaches scheme) based on the data holdings involved."
                .to_string(),
        ),
        Severity::Medium => impact.push(
            "Remediation can proceed within normal change windows, but the findings should be \
             tracked to closure and controls uplifted to prevent recurrence."
                .to_string(),
        ),
        Severity::Low | Severity::Informational => impact.push(
            "No material business impact is expected; the findings are provided to support \
             continuous improvement of the security posture."
                .to_string(),
        ),
    }

    DraftSummary {
        overview: overview.join(" "),
        key_findings,
        stakeholder_impact: impact.join(" "),
    }
}
