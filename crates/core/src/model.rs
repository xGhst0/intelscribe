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
    /// Engagement-level ACSC Essential Eight maturity self-assessment.
    pub essential_eight: Vec<EssentialEightItem>,

    /// Collected evidence (chain-of-custody register; images embedded).
    pub evidence: Vec<Evidence>,

    /// Which report to produce: "" or "incident" (default) render the incident
    /// report; "pentest" renders the penetration-test report from the fields
    /// below.
    pub report_kind: String,
    /// Pentest: engagement-level executive summary prose.
    pub executive_summary: String,
    /// Pentest: scope of the assessment.
    pub scope: String,
    /// Pentest: methodology / approach.
    pub methodology: String,
    /// Pentest: the findings.
    pub findings: Vec<Finding>,
}

/// A collected evidence item for the chain-of-custody register.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Evidence {
    pub title: String,
    pub filename: String,
    /// SHA-256 hex digest of the file contents.
    pub sha256: String,
    pub size_bytes: u64,
    /// When/where the evidence was collected (free text).
    pub captured: String,
    pub notes: String,
    /// Base64-encoded file bytes for embedding (images under the size cap only).
    pub image_data: String,
    /// Original file extension for images, e.g. "png"; empty if not embedded.
    pub image_ext: String,
}

/// A penetration-test finding.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    /// Optional CVSS 3.1 base vector.
    pub cvss_vector: String,
    /// Category, e.g. "Injection", "Access Control", "Cryptography".
    pub category: String,
    /// Affected assets / endpoints.
    pub affected: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    /// ISM control ids supporting the remediation (quoted verbatim).
    pub references: Vec<String>,
    /// Remediation status: "Open", "Remediated", "Risk Accepted", etc.
    pub status: String,
    /// Risk-matrix likelihood, 0 (unset) or 1–5 (Rare … Almost Certain).
    pub likelihood: u8,
    /// Risk-matrix consequence/impact rating, 0 (unset) or 1–5.
    pub impact_rating: u8,
}

/// One row of an Essential Eight maturity assessment. Levels are 0–3.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EssentialEightItem {
    pub strategy: String,
    pub current_level: u8,
    pub target_level: u8,
    pub notes: String,
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
    /// ASD/ACSC incident category, "" or "C1".."C6".
    pub acsc_category: String,
    /// Australian regulatory reporting assessment (SOCI Act, OAIC NDB).
    pub regulatory: Regulatory,
}

/// Inputs for the Australian regulatory reporting assessment. The analyst sets
/// these; the determinations are derived deterministically at render time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Regulatory {
    /// The affected asset is a critical infrastructure asset under the SOCI Act.
    pub critical_infrastructure: bool,
    /// SOCI impact assessment: "", "none", "relevant", or "significant".
    pub soci_impact: String,
    /// When the entity became aware (free text; echoed in the obligation).
    pub aware_time: String,
    /// Personal information was involved (engages the OAIC NDB scheme).
    pub personal_info_involved: bool,
    /// Serious harm to affected individuals is assessed as likely.
    pub serious_harm_likely: bool,
    /// Remedial action is assessed to have prevented the likely serious harm.
    pub remedial_action_prevents_harm: bool,
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
