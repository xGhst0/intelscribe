//! CVSS 3.1 base score calculator, implemented exactly per the FIRST.org
//! specification (including the Roundup integer-math function).

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CvssResult {
    pub score: f64,
    pub rating: String,
    pub vector: String,
}

/// Roundup as defined in the CVSS 3.1 spec (Appendix A).
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

pub fn rating(score: f64) -> &'static str {
    if score <= 0.0 {
        "None"
    } else if score < 4.0 {
        "Low"
    } else if score < 7.0 {
        "Medium"
    } else if score < 9.0 {
        "High"
    } else {
        "Critical"
    }
}

/// Score a CVSS 3.x base vector, e.g.
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (prefix optional).
pub fn score_vector(vector: &str) -> Result<CvssResult, String> {
    let mut av = None;
    let mut ac = None;
    let mut pr = None;
    let mut ui = None;
    let mut scope_changed = None;
    let mut c = None;
    let mut i = None;
    let mut a = None;

    for part in vector.trim().split('/') {
        let part = part.trim().to_uppercase();
        if part.is_empty() || part.starts_with("CVSS:") {
            continue;
        }
        let (metric, value) = part
            .split_once(':')
            .ok_or_else(|| format!("malformed metric: {part}"))?;
        let value = value.to_string();
        match metric {
            "AV" => {
                av = Some(match value.as_str() {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return Err(format!("bad AV value: {value}")),
                })
            }
            "AC" => {
                ac = Some(match value.as_str() {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return Err(format!("bad AC value: {value}")),
                })
            }
            "PR" => pr = Some(value),
            "UI" => {
                ui = Some(match value.as_str() {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return Err(format!("bad UI value: {value}")),
                })
            }
            "S" => {
                scope_changed = Some(match value.as_str() {
                    "U" => false,
                    "C" => true,
                    _ => return Err(format!("bad S value: {value}")),
                })
            }
            "C" | "I" | "A" => {
                let w = match value.as_str() {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return Err(format!("bad {metric} value: {value}")),
                };
                match metric {
                    "C" => c = Some(w),
                    "I" => i = Some(w),
                    _ => a = Some(w),
                }
            }
            // Temporal/environmental metrics are accepted but ignored (base score only).
            _ => {}
        }
    }

    let av = av.ok_or("missing AV")?;
    let ac = ac.ok_or("missing AC")?;
    let pr_raw = pr.ok_or("missing PR")?;
    let ui = ui.ok_or("missing UI")?;
    let scope_changed = scope_changed.ok_or("missing S")?;
    let c = c.ok_or("missing C")?;
    let i = i.ok_or("missing I")?;
    let a = a.ok_or("missing A")?;

    let pr = match (pr_raw.as_str(), scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return Err(format!("bad PR value: {pr_raw}")),
    };

    let iss: f64 = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact: f64 = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability: f64 = 8.22 * av * ac * pr * ui;

    let score = if impact <= 0.0 {
        0.0
    } else if scope_changed {
        roundup((1.08 * (impact + exploitability)).min(10.0))
    } else {
        roundup((impact + exploitability).min(10.0))
    };

    Ok(CvssResult {
        score,
        rating: rating(score).to_string(),
        vector: normalise(vector),
    })
}

fn normalise(vector: &str) -> String {
    let body: Vec<String> = vector
        .trim()
        .split('/')
        .map(|p| p.trim().to_uppercase())
        .filter(|p| !p.is_empty() && !p.starts_with("CVSS:"))
        .collect();
    format!("CVSS:3.1/{}", body.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> f64 {
        score_vector(v).unwrap().score
    }

    #[test]
    fn known_vectors() {
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(s("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
    }

    #[test]
    fn prefix_optional_and_case_insensitive() {
        assert_eq!(s("av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h"), 9.8);
    }

    #[test]
    fn ratings() {
        assert_eq!(rating(9.8), "Critical");
        assert_eq!(rating(7.8), "High");
        assert_eq!(rating(6.1), "Medium");
        assert_eq!(rating(2.0), "Low");
        assert_eq!(rating(0.0), "None");
    }

    #[test]
    fn missing_metric_is_an_error() {
        assert!(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H").is_err());
    }
}
