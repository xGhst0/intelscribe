//! Australian cyber security frameworks: ASD/ACSC incident categorisation,
//! the ACSC Essential Eight maturity model, and deterministic reporting-
//! obligation assessments for the SOCI Act and the OAIC Notifiable Data
//! Breaches scheme.
//!
//! The assessment logic encodes the statutory decision tests; it is advisory
//! and does not constitute legal advice.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::model::Regulatory;

// ---------------------------------------------------------------------------
// ASD/ACSC incident categorisation (C1–C6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcscCategory {
    pub id: String,
    /// "critical" | "high" | "medium" | "low" | "info" — drives badge colour.
    pub tier: String,
    pub label: String,
    pub detail: String,
}

#[derive(Deserialize)]
struct AcscPack {
    source: String,
    categories: Vec<AcscCategory>,
}

fn acsc_pack() -> &'static AcscPack {
    static P: OnceLock<AcscPack> = OnceLock::new();
    P.get_or_init(|| {
        serde_json::from_str(include_str!("../../../packs/acsc-categories.json"))
            .expect("bundled acsc-categories pack is valid JSON")
    })
}

pub fn acsc_source() -> &'static str {
    &acsc_pack().source
}

pub fn acsc_categories() -> &'static [AcscCategory] {
    &acsc_pack().categories
}

pub fn acsc_category(id: &str) -> Option<&'static AcscCategory> {
    let id = id.trim().to_ascii_uppercase();
    acsc_pack().categories.iter().find(|c| c.id == id)
}

// ---------------------------------------------------------------------------
// Essential Eight maturity model
// ---------------------------------------------------------------------------

pub const E8_STRATEGIES: [&str; 8] = [
    "Application control",
    "Patch applications",
    "Configure Microsoft Office macro settings",
    "User application hardening",
    "Restrict administrative privileges",
    "Patch operating systems",
    "Multi-factor authentication",
    "Regular backups",
];

/// (level, short name, description) for Maturity Levels 0–3.
pub fn e8_maturity_levels() -> [(u8, &'static str, &'static str); 4] {
    [
        (0, "ML0", "Weaknesses in the entity's overall cyber security posture."),
        (1, "ML1", "Partly aligned — mitigates adversaries using widely available, commodity tradecraft."),
        (2, "ML2", "Mostly aligned — mitigates adversaries operating with a modest step-up in capability and effort."),
        (3, "ML3", "Fully aligned — mitigates adaptive adversaries willing to invest significant time and effort."),
    ]
}

pub fn e8_level_name(level: u8) -> &'static str {
    match level {
        0 => "ML0",
        1 => "ML1",
        2 => "ML2",
        _ => "ML3",
    }
}

// ---------------------------------------------------------------------------
// Reporting-obligation assessments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Determination {
    /// Whether a reporting obligation is engaged (drives colour/emphasis).
    pub obligation: bool,
    pub headline: String,
    pub detail: String,
}

/// SOCI Act (Security of Critical Infrastructure Act 2018) reporting.
pub fn assess_soci(reg: &Regulatory) -> Determination {
    if !reg.critical_infrastructure {
        return Determination {
            obligation: false,
            headline: "SOCI Act — not applicable".to_string(),
            detail: "The affected asset is not identified as a critical infrastructure asset \
                     under the SOCI Act, so the mandatory cyber incident reporting obligations \
                     are not engaged."
                .to_string(),
        };
    }
    let aware = if reg.aware_time.trim().is_empty() {
        String::new()
    } else {
        format!(" (entity became aware: {})", reg.aware_time.trim())
    };
    match reg.soci_impact.trim().to_ascii_lowercase().as_str() {
        "significant" => Determination {
            obligation: true,
            headline: "SOCI Act — report to ASD within 12 hours".to_string(),
            detail: format!(
                "Assessed as a critical cyber security incident having a SIGNIFICANT impact on the \
                 availability of the asset. Report to ASD within 12 hours of becoming aware{aware}. \
                 An oral report is acceptable within the deadline, followed by a written record \
                 within the period specified by the SOCI Act."
            ),
        },
        "relevant" => Determination {
            obligation: true,
            headline: "SOCI Act — report to ASD within 72 hours".to_string(),
            detail: format!(
                "Assessed as a cyber security incident having a RELEVANT impact on the asset. \
                 Report to ASD within 72 hours of becoming aware{aware}."
            ),
        },
        _ => Determination {
            obligation: false,
            headline: "SOCI Act — no reportable impact assessed".to_string(),
            detail: "No significant or relevant impact on the critical infrastructure asset has \
                     been assessed at this time. Reassess as the investigation progresses."
                .to_string(),
        },
    }
}

/// OAIC Notifiable Data Breaches scheme (Privacy Act 1988, Part IIIC).
pub fn assess_ndb(reg: &Regulatory) -> Determination {
    if !reg.personal_info_involved {
        return Determination {
            obligation: false,
            headline: "NDB scheme — not engaged".to_string(),
            detail: "No personal information was involved, so the Notifiable Data Breaches \
                     scheme is not engaged."
                .to_string(),
        };
    }
    if !reg.serious_harm_likely {
        return Determination {
            obligation: false,
            headline: "NDB scheme — unlikely to be notifiable".to_string(),
            detail: "Personal information was involved, but serious harm to affected individuals \
                     is not currently assessed as likely. This is not an eligible data breach on \
                     the present assessment; continue to monitor and reassess if new information \
                     emerges."
                .to_string(),
        };
    }
    if reg.remedial_action_prevents_harm {
        return Determination {
            obligation: false,
            headline: "NDB scheme — remedial action taken".to_string(),
            detail: "Although personal information was involved and serious harm was possible, \
                     remedial action is assessed to have prevented the likely risk of serious \
                     harm. On this basis it is not an eligible data breach; document the remedial \
                     action and the reassessment."
                .to_string(),
        };
    }
    Determination {
        obligation: true,
        headline: "NDB scheme — likely an eligible data breach (notify)".to_string(),
        detail: "Unauthorised access to, disclosure of, or loss of personal information is likely \
                 to result in serious harm to affected individuals, and this has not been \
                 prevented by remedial action. This is likely an eligible data breach: notify the \
                 OAIC and affected individuals as soon as practicable after completing the \
                 assessment."
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Regulatory {
        Regulatory::default()
    }

    #[test]
    fn acsc_categories_load() {
        assert_eq!(acsc_categories().len(), 6);
        assert_eq!(acsc_category("c3").unwrap().tier, "high");
        assert!(acsc_category("C7").is_none());
    }

    #[test]
    fn soci_windows() {
        let mut r = reg();
        assert!(!assess_soci(&r).obligation); // not CI

        r.critical_infrastructure = true;
        r.soci_impact = "significant".into();
        let d = assess_soci(&r);
        assert!(d.obligation && d.detail.contains("12 hours"));

        r.soci_impact = "relevant".into();
        assert!(assess_soci(&r).detail.contains("72 hours"));

        r.soci_impact = "none".into();
        assert!(!assess_soci(&r).obligation);
    }

    #[test]
    fn ndb_three_limb_test() {
        let mut r = reg();
        assert!(!assess_ndb(&r).obligation); // no PI

        r.personal_info_involved = true;
        assert!(!assess_ndb(&r).obligation); // harm not likely

        r.serious_harm_likely = true;
        assert!(assess_ndb(&r).obligation); // notifiable

        r.remedial_action_prevents_harm = true;
        assert!(!assess_ndb(&r).obligation); // remediated
    }
}
