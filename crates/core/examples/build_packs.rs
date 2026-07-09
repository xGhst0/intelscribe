//! Pack builder: preprocesses the raw MITRE ATT&CK STIX bundle and the ACSC
//! ISM OSCAL catalog into the compact packs embedded in the binary.
//!
//! Inputs (downloaded manually, gitignored):
//!   packs/raw/enterprise-attack.json  — https://github.com/mitre-attack/attack-stix-data
//!   packs/raw/ISM_catalog.json        — https://github.com/AustralianCyberSecurityCentre/ism-oscal
//!
//! Outputs (committed, embedded via include_str!):
//!   packs/attack-full.json
//!   packs/ism.json
//!
//! Usage: cargo run -p intelscribe-core --example build_packs

use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Value};

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    build_attack(&root);
    build_ism(&root);
}

fn capitalize(w: &str) -> String {
    let mut chars = w.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn tactic_display(phase: &str) -> String {
    phase
        .split('-')
        .map(|w| if w == "and" || w == "or" { w.to_string() } else { capitalize(w) })
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_citations(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("(Citation:") {
        out.push_str(&rest[..i]);
        match rest[i..].find(')') {
            Some(j) => rest = &rest[i + j + 1..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Replace markdown links [text](url) with just the text.
fn strip_links(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(close) = rest.find("](") {
        let open = match rest[..close].rfind('[') {
            Some(o) => o,
            None => break,
        };
        let end = match rest[close + 2..].find(')') {
            Some(e) => close + 2 + e,
            None => break,
        };
        out.push_str(&rest[..open]);
        out.push_str(&rest[open + 1..close]);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

fn summarise(description: &str, max_chars: usize) -> String {
    let first_para = description.split("\n\n").next().unwrap_or("");
    let clean = strip_links(&strip_citations(first_para))
        .replace("<code>", "`")
        .replace("</code>", "`")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if clean.chars().count() <= max_chars {
        clean
    } else {
        let truncated: String = clean.chars().take(max_chars).collect();
        format!("{}…", truncated.trim_end())
    }
}

fn external_id(obj: &Value) -> Option<String> {
    obj["external_references"].as_array()?.iter().find_map(|r| {
        if r["source_name"].as_str() == Some("mitre-attack") {
            r["external_id"].as_str().map(str::to_string)
        } else {
            None
        }
    })
}

fn is_active(obj: &Value) -> bool {
    obj["revoked"].as_bool() != Some(true) && obj["x_mitre_deprecated"].as_bool() != Some(true)
}

fn build_attack(root: &Path) {
    let raw = std::fs::read_to_string(root.join("packs/raw/enterprise-attack.json"))
        .expect("packs/raw/enterprise-attack.json missing — download it first");
    let bundle: Value = serde_json::from_str(&raw).expect("valid STIX JSON");
    let objects = bundle["objects"].as_array().expect("bundle.objects");

    let version = objects
        .iter()
        .find(|o| o["type"].as_str() == Some("x-mitre-collection"))
        .and_then(|o| o["x_mitre_version"].as_str())
        .unwrap_or("unknown")
        .to_string();

    // course-of-action stix-id -> (M-id, name)
    let mut coas: HashMap<&str, (String, String)> = HashMap::new();
    for o in objects {
        if o["type"].as_str() == Some("course-of-action") && is_active(o) {
            if let (Some(stix_id), Some(mid), Some(name)) =
                (o["id"].as_str(), external_id(o), o["name"].as_str())
            {
                if mid.starts_with('M') {
                    coas.insert(stix_id, (mid, name.to_string()));
                }
            }
        }
    }

    // attack-pattern stix-id -> mitigating course-of-action stix-ids
    let mut mitigates: HashMap<&str, Vec<&str>> = HashMap::new();
    for o in objects {
        if o["type"].as_str() == Some("relationship")
            && o["relationship_type"].as_str() == Some("mitigates")
            && is_active(o)
        {
            if let (Some(src), Some(dst)) = (o["source_ref"].as_str(), o["target_ref"].as_str()) {
                if dst.starts_with("attack-pattern--") {
                    mitigates.entry(dst).or_default().push(src);
                }
            }
        }
    }

    let mut techniques = Vec::new();
    for o in objects {
        if o["type"].as_str() != Some("attack-pattern") || !is_active(o) {
            continue;
        }
        let Some(id) = external_id(o) else { continue };
        if !id.starts_with('T') {
            continue;
        }
        let name = o["name"].as_str().unwrap_or_default().to_string();
        let tactics: Vec<String> = o["kill_chain_phases"]
            .as_array()
            .map(|phases| {
                phases
                    .iter()
                    .filter(|p| p["kill_chain_name"].as_str() == Some("mitre-attack"))
                    .filter_map(|p| p["phase_name"].as_str().map(tactic_display))
                    .collect()
            })
            .unwrap_or_default();
        let description = summarise(o["description"].as_str().unwrap_or(""), 550);

        let mut mits: Vec<(String, String)> = mitigates
            .get(o["id"].as_str().unwrap_or_default())
            .map(|srcs| srcs.iter().filter_map(|s| coas.get(s).cloned()).collect())
            .unwrap_or_default();
        mits.sort();
        mits.dedup();
        mits.truncate(8);

        techniques.push(json!({
            "id": id,
            "name": name,
            "tactic": tactics.join(", "),
            "description": description,
            "mitigations": mits.iter().map(|(mid, mname)| json!({"id": mid, "name": mname})).collect::<Vec<_>>(),
        }));
    }
    techniques.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

    let out = json!({ "version": version, "techniques": techniques });
    let path = root.join("packs/attack-full.json");
    std::fs::write(&path, serde_json::to_string(&out).unwrap()).unwrap();
    println!(
        "attack-full.json: ATT&CK v{version}, {} techniques ({:.1} KB)",
        techniques_len(&out),
        std::fs::metadata(&path).unwrap().len() as f64 / 1024.0
    );
}

fn techniques_len(v: &Value) -> usize {
    v["techniques"].as_array().map(|a| a.len()).unwrap_or(0)
}

fn prop(obj: &Value, name: &str) -> Option<String> {
    obj["props"].as_array()?.iter().find_map(|p| {
        if p["name"].as_str() == Some(name) {
            p["value"].as_str().map(str::to_string)
        } else {
            None
        }
    })
}

fn props_all(obj: &Value, name: &str) -> Vec<String> {
    obj["props"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|p| p["name"].as_str() == Some(name))
                .filter_map(|p| p["value"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn walk_groups(group: &Value, section: &str, topic: &str, out: &mut Vec<Value>) {
    let title = group["title"].as_str().unwrap_or(topic);
    // Top-level groups become the section; nested titles become the topic.
    let (section, topic) = if section.is_empty() {
        (title, title)
    } else {
        (section, title)
    };

    if let Some(controls) = group["controls"].as_array() {
        for c in controls {
            let Some(raw_id) = c["id"].as_str() else { continue };
            let id = raw_id.to_uppercase(); // ism-0042 -> ISM-0042
            let text = c["parts"]
                .as_array()
                .and_then(|parts| {
                    parts
                        .iter()
                        .find(|p| p["name"].as_str() == Some("statement"))
                        .and_then(|p| p["prose"].as_str())
                })
                .unwrap_or_default();
            out.push(json!({
                "id": id,
                "section": section,
                "topic": topic,
                "revision": prop(c, "revision").unwrap_or_default(),
                "updated": prop(c, "updated").unwrap_or_default(),
                "applicability": props_all(c, "applicability"),
                "text": text,
            }));
        }
    }
    if let Some(groups) = group["groups"].as_array() {
        for g in groups {
            walk_groups(g, section, topic, out);
        }
    }
}

fn build_ism(root: &Path) {
    let raw = std::fs::read_to_string(root.join("packs/raw/ISM_catalog.json"))
        .expect("packs/raw/ISM_catalog.json missing — download it first");
    let doc: Value = serde_json::from_str(&raw).expect("valid OSCAL JSON");
    let catalog = &doc["catalog"];
    let version = catalog["metadata"]["version"].as_str().unwrap_or("unknown").to_string();

    let mut controls = Vec::new();
    if let Some(groups) = catalog["groups"].as_array() {
        for g in groups {
            walk_groups(g, "", "", &mut controls);
        }
    }
    controls.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

    let out = json!({ "version": version, "controls": controls });
    let path = root.join("packs/ism.json");
    std::fs::write(&path, serde_json::to_string(&out).unwrap()).unwrap();
    println!(
        "ism.json: ISM {version}, {} controls ({:.1} KB)",
        controls.len(),
        std::fs::metadata(&path).unwrap().len() as f64 / 1024.0
    );
}
