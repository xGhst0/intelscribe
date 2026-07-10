//! Demonstrates the real IoC extractor and ATT&CK suggester on a realistic
//! paste. Run: cargo run -p intelscribe-core --example ingest_demo

use intelscribe_core::{extract, packs};

fn main() {
    let paste = r#"
2026-03-14 09:12:05  WKS-041  WINWORD.EXE spawned powershell.exe -nop -w hidden -enc; macro download cradle to hxxp://evil-c2[.]example[.]com/officeupdate
2026-03-14 09:12:07  WKS-041  Beacon to 203[.]0[.]113[.]47 over port 443
2026-03-14 09:15:00  WKS-041  SharpHound LDAP collection started
2026-03-14 09:24:12  WKS-041  4769 RC4 (0x17) service ticket requested for svc_reporting (kerberoasting)
2026-03-14 09:31:57  WKS-041  PsExec over ADMIN$ to APP-02 (192.0.2.52); dropped C:\ProgramData\collector.exe
2026-03-14 09:44:19  APP-02  WMIC remote process creation against dc01.corp.local
2026-03-14 09:46:52  DC-01  svchost.exe opened lsass.exe 0x1010 via comsvcs.dll minidump (sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
2026-03-14 09:48:03  DC-01  schtasks created scheduled task Updater for persistence; HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\System set
2026-03-14 10:02:11  DC-01  Report emailed to attacker@bad-domain[.]net
"#;

    println!("=== Extracted hosts ===");
    for h in extract::extract_hosts(paste) {
        println!("  {:<18} {}", h.name, h.ip);
    }

    println!("\n=== Extracted timeline events ===");
    for ev in extract::extract_events(paste) {
        println!("  {:<10} [{:<18}] {:<8} {}", ev.timestamp, ev.phase.label(), ev.host, ev.description);
    }

    println!("\n=== Extracted IoCs ===");
    for ioc in extract::extract_iocs(paste) {
        println!("  [{:<13}] {}", ioc.ioc_type, ioc.indicator);
    }

    println!("\n=== Suggested ATT&CK techniques ===");
    for t in packs::suggest_techniques(paste) {
        println!("  {:<11} {:<42} ({})", t.id, t.name, t.tactic);
    }
}
