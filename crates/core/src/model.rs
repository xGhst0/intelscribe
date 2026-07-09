use serde::{Deserialize, Serialize};

/// The single source of truth for a report: every fact is entered once here
/// and every rendered section is derived from it.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Engagement {
    pub title: String,
    pub client: String,
    pub analyst: String,
    pub analyst_title: String,
    pub date: String,
    pub version: String,
    pub classification: String,
    pub incidents: Vec<Incident>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Incident {
    pub incident_id: String,
    pub title: String,
    pub severity: Severity,
    pub status: String,
    pub overview: String,
    pub key_findings: Vec<String>,
    pub immediate_actions: Vec<String>,
    pub stakeholder_impact: String,
    pub root_cause: String,
    pub hosts: Vec<Host>,
    pub accounts: Vec<Account>,
    pub detections: Vec<Detection>,
    pub iocs: Vec<Ioc>,
    pub events: Vec<TimelineEvent>,
    pub techniques: Vec<TechniqueRef>,
    /// Analyst-authored recommendations, printed after the auto-derived
    /// mitigations in the Recommendations section.
    pub additional_recommendations: Vec<String>,
    /// ISM control ids the analyst has cited (e.g. "ISM-1490"); the control
    /// text is quoted automatically in the Framework Alignment section.
    pub ism_controls: Vec<String>,
    /// Optional CVSS 3.1 base vector for the incident, e.g.
    /// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
    pub cvss_vector: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Severity {
    Critical,
    High,
    #[default]
    Medium,
    Low,
    Informational,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Informational => "Informational",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Host {
    pub name: String,
    pub ip: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Account {
    pub name: String,
    pub description: String,
}

/// One step-by-step detection: the CDSA-style data source / query / result triplet.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Detection {
    pub title: String,
    pub data_source: String,
    pub query: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Ioc {
    pub indicator: String,
    pub ioc_type: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub phase: Phase,
    pub host: String,
    pub description: String,
}

/// Kill-chain phases used to group the technical timeline, in report order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Phase {
    #[default]
    Reconnaissance,
    InitialCompromise,
    CommandAndControl,
    Enumeration,
    LateralMovement,
    DataAccess,
    MalwareActivity,
    Containment,
    Eradication,
    Recovery,
}

impl Phase {
    pub const ALL: [Phase; 10] = [
        Phase::Reconnaissance,
        Phase::InitialCompromise,
        Phase::CommandAndControl,
        Phase::Enumeration,
        Phase::LateralMovement,
        Phase::DataAccess,
        Phase::MalwareActivity,
        Phase::Containment,
        Phase::Eradication,
        Phase::Recovery,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Phase::Reconnaissance => "Reconnaissance",
            Phase::InitialCompromise => "Initial Compromise",
            Phase::CommandAndControl => "C2 Communications",
            Phase::Enumeration => "Enumeration",
            Phase::LateralMovement => "Lateral Movement",
            Phase::DataAccess => "Data Access & Exfiltration",
            Phase::MalwareActivity => "Malware Deployment & Activity",
            Phase::Containment => "Containment",
            Phase::Eradication => "Eradication",
            Phase::Recovery => "Recovery",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TechniqueRef {
    pub id: String,
    pub name: String,
    pub tactic: String,
}
