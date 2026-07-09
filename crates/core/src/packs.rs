use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// MITRE ATT&CK
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub mitigations: Vec<AttackMitigation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMitigation {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize)]
struct AttackPack {
    version: String,
    techniques: Vec<Technique>,
}

fn attack_pack() -> &'static AttackPack {
    static PACK: OnceLock<AttackPack> = OnceLock::new();
    PACK.get_or_init(|| {
        serde_json::from_str(include_str!("../../../packs/attack-full.json"))
            .expect("bundled attack-full pack is valid JSON")
    })
}

pub fn attack_version() -> &'static str {
    &attack_pack().version
}

pub fn all_techniques() -> &'static [Technique] {
    &attack_pack().techniques
}

/// Case-insensitive search over technique ids, names and tactics, ranked so
/// that id/name prefix matches come first. Capped at 20 results.
pub fn search(query: &str) -> Vec<Technique> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return all_techniques().iter().take(20).cloned().collect();
    }
    let mut scored: Vec<(u8, &Technique)> = all_techniques()
        .iter()
        .filter_map(|t| {
            let id = t.id.to_ascii_lowercase();
            let name = t.name.to_ascii_lowercase();
            let tactic = t.tactic.to_ascii_lowercase();
            let rank = if id == q {
                0
            } else if id.starts_with(&q) {
                1
            } else if name.to_ascii_lowercase().starts_with(&q) {
                2
            } else if name.contains(&q) {
                3
            } else if id.contains(&q) || tactic.contains(&q) {
                4
            } else {
                return None;
            };
            Some((rank, t))
        })
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)));
    scored.into_iter().take(20).map(|(_, t)| t.clone()).collect()
}

/// Exact lookup by technique id (case-insensitive).
pub fn technique(id: &str) -> Option<Technique> {
    let id = id.trim().to_ascii_uppercase();
    all_techniques().iter().find(|t| t.id == id).cloned()
}

// ---------------------------------------------------------------------------
// Curated mitigations (control-level recommendations, from M3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationControl {
    pub name: String,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationEntry {
    /// ATT&CK base technique id (no sub-technique suffix), e.g. "T1566".
    pub technique: String,
    pub controls: Vec<MitigationControl>,
    pub essential_eight: Vec<String>,
}

pub fn mitigations() -> Vec<MitigationEntry> {
    serde_json::from_str(include_str!("../../../packs/mitigations.json"))
        .expect("bundled mitigations pack is valid JSON")
}

/// Look up curated mitigations for a (possibly sub-)technique id: "T1566.001"
/// falls back to the "T1566" entry.
pub fn mitigations_for(technique_id: &str) -> Option<MitigationEntry> {
    let base = technique_id.split('.').next().unwrap_or(technique_id).trim().to_uppercase();
    mitigations().into_iter().find(|m| m.technique == base)
}

// ---------------------------------------------------------------------------
// ACSC Information Security Manual (ISM)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsmControl {
    pub id: String,
    pub section: String,
    pub topic: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub applicability: Vec<String>,
    pub text: String,
}

#[derive(Deserialize)]
struct IsmPack {
    version: String,
    controls: Vec<IsmControl>,
}

fn ism_pack() -> &'static IsmPack {
    static PACK: OnceLock<IsmPack> = OnceLock::new();
    PACK.get_or_init(|| {
        serde_json::from_str(include_str!("../../../packs/ism.json"))
            .expect("bundled ism pack is valid JSON")
    })
}

pub fn ism_version() -> &'static str {
    &ism_pack().version
}

/// Exact ISM control lookup. Accepts "ISM-0042", "0042" or "42".
pub fn ism_control(id: &str) -> Option<IsmControl> {
    let digits: String = id.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let normalised = format!("ISM-{:0>4}", digits.trim_start_matches('0'));
    ism_pack()
        .controls
        .iter()
        .find(|c| c.id.eq_ignore_ascii_case(&normalised) || c.id.eq_ignore_ascii_case(id))
        .cloned()
}

/// Search ISM controls by id fragment or text, capped at 20 results.
pub fn ism_search(query: &str) -> Vec<IsmControl> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(u8, &IsmControl)> = ism_pack()
        .controls
        .iter()
        .filter_map(|c| {
            let id = c.id.to_ascii_lowercase();
            let rank = if id.contains(&q) {
                0
            } else if c.topic.to_ascii_lowercase().contains(&q) {
                1
            } else if c.text.to_ascii_lowercase().contains(&q) {
                2
            } else {
                return None;
            };
            Some((rank, c))
        })
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)));
    scored.into_iter().take(20).map(|(_, c)| c.clone()).collect()
}
