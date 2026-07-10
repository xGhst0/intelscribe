use serde::Deserialize;

/// Boilerplate and analyst guidance for a report template. Templates are data
/// (TOML), not code, so adding new report types never requires recompiling.
#[derive(Debug, Clone, Deserialize)]
pub struct ReportTemplate {
    pub id: String,
    pub name: String,
    pub confidentiality: String,
    pub affected_guidance: String,
    pub evidence_guidance: String,
    pub ioc_guidance: String,
    pub root_cause_guidance: String,
    pub timeline_guidance: String,
    pub nature_guidance: String,
    pub attack_map_guidance: String,
    pub recommendations_guidance: String,
}

pub fn incident_report() -> ReportTemplate {
    toml::from_str(include_str!("../../../templates/incident-report.toml"))
        .expect("bundled incident-report template is valid TOML")
}

/// Boilerplate and guidance for the penetration-test report.
#[derive(Debug, Clone, Deserialize)]
pub struct PentestTemplate {
    pub id: String,
    pub name: String,
    pub exec_guidance: String,
    pub scope_guidance: String,
    pub methodology_guidance: String,
    pub findings_guidance: String,
}

pub fn pentest_report() -> PentestTemplate {
    toml::from_str(include_str!("../../../templates/pentest-report.toml"))
        .expect("bundled pentest-report template is valid TOML")
}
