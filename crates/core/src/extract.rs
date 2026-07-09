//! IoC extraction from pasted text (logs, notes, command output).
//!
//! The pipeline is: refang the input so defanged indicators parse, pull out
//! indicators in priority order (blanking each match so later patterns cannot
//! re-match inside it), then defang network indicators for the report table.
//! Fully deterministic and offline.

use std::sync::OnceLock;

use regex::Regex;

use crate::model::Ioc;

/// File extensions that should be treated as filenames, not domains, when they
/// appear as a bare `name.ext` token.
const FILE_EXTS: &[&str] = &[
    "exe", "dll", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
    "ps1", "psm1", "vbs", "vba", "js", "jse", "bat", "cmd", "txt", "log", "png",
    "jpg", "jpeg", "gif", "bmp", "zip", "rar", "7z", "tar", "gz", "tmp", "dat",
    "bin", "sys", "ini", "xml", "json", "yaml", "yml", "lnk", "scr", "hta",
    "jar", "py", "sh", "conf", "cfg", "msi", "cab", "iso", "img", "pdf", "rtf",
    "one", "csv", "db", "sqlite", "pfx", "key", "pem", "crt",
];

/// Common system binaries and libraries that are almost never useful as
/// standalone filename indicators; their abuse is captured by the technique
/// suggester instead. Compared case-insensitively.
const SYSTEM_BINARIES: &[&str] = &[
    "svchost.exe", "lsass.exe", "powershell.exe", "powershell_ise.exe", "cmd.exe",
    "explorer.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "rundll32.exe", "regsvr32.exe", "services.exe", "wininit.exe", "winlogon.exe",
    "csrss.exe", "smss.exe", "lsaiso.exe", "spoolsv.exe", "taskhost.exe",
    "taskhostw.exe", "dllhost.exe", "conhost.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "wmic.exe", "wmiprvse.exe", "net.exe", "net1.exe", "reg.exe",
    "schtasks.exe", "whoami.exe", "sc.exe", "psexesvc.exe", "comsvcs.dll",
    "kernel32.dll", "ntdll.dll", "user32.dll", "msvcrt.dll", "advapi32.dll",
    "ws2_32.dll", "gdi32.dll", "ole32.dll", "shell32.dll",
];

/// Recognised top-level / corporate domain suffixes. A bare `a.b` token is only
/// treated as a domain when its last label is one of these, which rejects code
/// tokens such as `Net.WebClient` or `System.Diagnostics`.
const COMMON_TLDS: &[&str] = &[
    "com", "net", "org", "io", "gov", "edu", "mil", "co", "info", "biz", "app",
    "dev", "xyz", "online", "site", "top", "live", "cloud", "tech", "ai", "me",
    "tv", "cc", "us", "uk", "au", "nz", "ca", "de", "fr", "nl", "ru", "cn", "jp",
    "kr", "in", "br", "za", "sg", "hk", "ir", "ua", "pl", "it", "es", "se", "no",
    "fi", "dk", "ch", "at", "be", "cz", "gr", "pt", "ro", "hu", "id", "my", "ph",
    "th", "vn", "local", "internal", "lan", "corp", "intranet", "home",
];

struct Patterns {
    url: Regex,
    email: Regex,
    sha256: Regex,
    sha1: Regex,
    md5: Regex,
    registry: Regex,
    win_path: Regex,
    ipv4: Regex,
    domain: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        url: Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s<>"'\)\]\}]+"#).unwrap(),
        email: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap(),
        sha256: Regex::new(r"\b[A-Fa-f0-9]{64}\b").unwrap(),
        sha1: Regex::new(r"\b[A-Fa-f0-9]{40}\b").unwrap(),
        md5: Regex::new(r"\b[A-Fa-f0-9]{32}\b").unwrap(),
        registry: Regex::new(r#"(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s"'<>|]+"#).unwrap(),
        win_path: Regex::new(r#"\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n\s]+"#).unwrap(),
        ipv4: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
            .unwrap(),
        domain: Regex::new(
            r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
        )
        .unwrap(),
    })
}

/// Convert common defanged notations back to their real form so patterns match.
pub fn refang(input: &str) -> String {
    let mut s = input.to_string();
    for (from, to) in [
        ("hxxps", "https"),
        ("hXXps", "https"),
        ("hxxp", "http"),
        ("hXXp", "http"),
        ("fxp", "ftp"),
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[dot]", "."),
        ("(dot)", "."),
        ("[at]", "@"),
        ("(at)", "@"),
        ("[@]", "@"),
        ("[:]", ":"),
        ("[://]", "://"),
        ("[//]", "//"),
    ] {
        s = s.replace(from, to);
    }
    s
}

fn defang_network(s: &str) -> String {
    s.replace("http", "hxxp").replace('.', "[.]")
}

fn defang_ip_or_domain(s: &str) -> String {
    s.replace('.', "[.]")
}

fn defang_email(s: &str) -> String {
    s.replace('@', "[@]").replace('.', "[.]")
}

/// Blank out `[start, end)` in a byte buffer with spaces (preserving length so
/// later regex offsets stay valid).
fn blank(buf: &mut Vec<u8>, start: usize, end: usize) {
    for b in &mut buf[start..end] {
        *b = b' ';
    }
}

fn last_label(s: &str) -> String {
    s.rsplit('.').next().unwrap_or("").to_ascii_lowercase()
}

/// Extract indicators of compromise from free text. Indicators are returned
/// deduplicated, with network indicators defanged and a context of
/// "Auto-extracted".
pub fn extract_iocs(input: &str) -> Vec<Ioc> {
    let text = refang(input);
    let p = patterns();
    let mut work = text.clone().into_bytes();
    let mut out: Vec<Ioc> = Vec::new();

    let push = |indicator: String, ioc_type: &str, out: &mut Vec<Ioc>| {
        if indicator.trim().is_empty() {
            return;
        }
        let exists = out
            .iter()
            .any(|i| i.ioc_type == ioc_type && i.indicator.eq_ignore_ascii_case(&indicator));
        if !exists {
            out.push(Ioc {
                indicator,
                ioc_type: ioc_type.to_string(),
                context: "Auto-extracted".to_string(),
            });
        }
    };

    // Run a pattern over the current working buffer, emit each match through
    // `handle`, then blank the spans so later passes skip them.
    let mut pass = |re: &Regex, out: &mut Vec<Ioc>, handle: &dyn Fn(&str, &mut Vec<Ioc>)| {
        let snapshot = String::from_utf8_lossy(&work).into_owned();
        let mut spans = Vec::new();
        for m in re.find_iter(&snapshot) {
            handle(m.as_str(), out);
            spans.push((m.start(), m.end()));
        }
        for (s, e) in spans {
            blank(&mut work, s, e);
        }
    };

    // Priority order: broad/composite indicators first.
    pass(&p.url, &mut out, &|m, out| push(defang_network(m), "URL", out));
    pass(&p.email, &mut out, &|m, out| push(defang_email(m), "Email Address", out));
    pass(&p.sha256, &mut out, &|m, out| push(m.to_lowercase(), "Hash", out));
    pass(&p.sha1, &mut out, &|m, out| push(m.to_lowercase(), "Hash", out));
    pass(&p.md5, &mut out, &|m, out| push(m.to_lowercase(), "Hash", out));
    pass(&p.registry, &mut out, &|m, out| push(m.trim().to_string(), "Registry Key", out));
    pass(&p.win_path, &mut out, &|m, out| push(m.trim().to_string(), "File Path", out));
    pass(&p.ipv4, &mut out, &|m, out| push(defang_ip_or_domain(m), "IPv4", out));
    pass(&p.domain, &mut out, &|m, out| {
        let tld = last_label(m);
        if FILE_EXTS.contains(&tld.as_str()) {
            // A bare filename; drop common system binaries as non-indicators.
            if !SYSTEM_BINARIES.contains(&m.to_ascii_lowercase().as_str()) {
                push(m.to_string(), "Filename", out);
            }
        } else if COMMON_TLDS.contains(&tld.as_str()) {
            push(defang_ip_or_domain(m), "Domain", out);
        }
        // Otherwise it's neither a recognisable domain nor filename (e.g. a
        // code token like Net.WebClient) — skip it.
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indicators(iocs: &[Ioc], kind: &str) -> Vec<String> {
        iocs.iter()
            .filter(|i| i.ioc_type == kind)
            .map(|i| i.indicator.clone())
            .collect()
    }

    #[test]
    fn extracts_and_defangs_network_indicators() {
        let log = "\
            Beacon to 18.207.78.25 over port 80.\n\
            Stager: http://evil.example.com/officeupdate\n\
            Also saw hxxp://203[.]0[.]113[.]9/beacon and 10[.]0[.]0[.]142.";
        let iocs = extract_iocs(log);
        let ips = indicators(&iocs, "IPv4");
        assert!(ips.contains(&"18[.]207[.]78[.]25".to_string()));
        assert!(ips.contains(&"10[.]0[.]0[.]142".to_string()));
        let urls = indicators(&iocs, "URL");
        assert!(urls.iter().any(|u| u.contains("hxxp://evil[.]example[.]com/officeupdate")));
        assert!(urls.iter().any(|u| u.contains("203[.]0[.]113[.]9")));
    }

    #[test]
    fn extracts_hashes_paths_registry_email_filename() {
        let log = "\
            Dropped C:\\Users\\marty\\AppData\\Local\\SharpHound.exe\n\
            Persistence HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\System\n\
            SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
            Contact attacker@bad-domain.net about invoice.doc";
        let iocs = extract_iocs(log);
        assert!(indicators(&iocs, "Hash").iter().any(|h| h.len() == 64));
        assert!(indicators(&iocs, "File Path").iter().any(|p| p.contains("SharpHound.exe")));
        assert!(indicators(&iocs, "Registry Key").iter().any(|r| r.contains("CurrentVersion")));
        assert!(indicators(&iocs, "Email Address").iter().any(|e| e.contains("[@]")));
        assert!(indicators(&iocs, "Filename").contains(&"invoice.doc".to_string()));
    }

    #[test]
    fn deduplicates_repeats() {
        let iocs = extract_iocs("1.2.3.4 and again 1.2.3.4 and 1.2.3.4");
        assert_eq!(indicators(&iocs, "IPv4").len(), 1);
    }

    #[test]
    fn domain_inside_url_not_double_counted() {
        let iocs = extract_iocs("http://evil.example.com/x");
        // The host must not also surface as a standalone Domain.
        assert!(indicators(&iocs, "Domain").is_empty());
        assert_eq!(indicators(&iocs, "URL").len(), 1);
    }

    #[test]
    fn filters_code_tokens_and_system_binaries() {
        let text = "IEX (New-Object Net.WebClient); svchost.exe opened lsass.exe; \
                    beacon at evil.com dropped payload badtool.exe";
        let iocs = extract_iocs(text);
        // Code token misread as a domain must be dropped.
        assert!(!iocs.iter().any(|i| i.indicator.to_lowercase().contains("webclient")));
        // System binaries must not appear as filename indicators.
        assert!(indicators(&iocs, "Filename").iter().all(|f| {
            let l = f.to_lowercase();
            l != "svchost.exe" && l != "lsass.exe"
        }));
        // Genuine indicators survive.
        assert!(indicators(&iocs, "Domain").contains(&"evil[.]com".to_string()));
        assert!(indicators(&iocs, "Filename").contains(&"badtool.exe".to_string()));
    }
}
