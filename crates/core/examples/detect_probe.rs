//! Parse a detection block from a file and print the result, for verifying the
//! detection extractor against real report pastes.
//! Usage: cargo run -p intelscribe-core --example detect_probe -- <file>

use intelscribe_core::extract;

fn main() {
    let path = std::env::args().nth(1).expect("pass a text file path");
    let text = std::fs::read_to_string(&path).unwrap();
    let dets = extract::extract_detections(&text);
    println!("Parsed {} detections:\n", dets.len());
    for (i, d) in dets.iter().enumerate() {
        let ds = d.data_source.chars().take(50).collect::<String>();
        let ql = d.query.lines().count();
        let rs = d.result.chars().take(60).collect::<String>();
        println!("  {}. {}", i + 1, d.title);
        println!("     data source: {ds}");
        println!("     query: {ql} line(s)");
        println!("     result: {rs}…\n");
    }
}
