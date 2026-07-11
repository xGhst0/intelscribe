//! Run every extractor over a text file and print a summary, for diagnosing
//! real-world pastes/imports.
//! Usage: cargo run -p intelscribe-core --example extract_all -- <file>

use intelscribe_core::{extract, packs};

fn main() {
    let path = std::env::args().nth(1).expect("pass a text file path");
    let text = std::fs::read_to_string(&path).unwrap();

    let hosts = extract::extract_hosts(&text);
    println!("=== HOSTS ({}) ===", hosts.len());
    for h in hosts.iter().take(30) {
        println!("  {:<24} {}", h.name, h.ip);
    }

    let events = extract::extract_events(&text);
    println!("\n=== TIMELINE EVENTS ({}) ===", events.len());
    for ev in events.iter().take(30) {
        println!("  [{:<24}] {:<8} {}", ev.timestamp, ev.host,
            ev.description.chars().take(70).collect::<String>());
    }

    let iocs = extract::extract_iocs(&text);
    println!("\n=== IOCS ({}) ===", iocs.len());
    for i in iocs.iter().take(30) {
        println!("  [{:<13}] {}", i.ioc_type, i.indicator);
    }

    let dets = extract::extract_detections(&text);
    println!("\n=== DETECTIONS ({}) ===", dets.len());
    for d in dets.iter().take(40) {
        println!("  {:<40} | ds={} q={} r={}",
            d.title.chars().take(40).collect::<String>(),
            !d.data_source.is_empty(), d.query.lines().count(), !d.result.is_empty());
    }

    let techs = packs::suggest_techniques(&text);
    println!("\n=== TECHNIQUES ({}) ===", techs.len());
    for t in techs.iter().take(30) {
        println!("  {:<11} {}", t.id, t.name);
    }
}
