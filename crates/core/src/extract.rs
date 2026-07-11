//! IoC extraction from pasted text (logs, notes, command output).
//!
//! The pipeline is: refang the input so defanged indicators parse, pull out
//! indicators in priority order (blanking each match so later patterns cannot
//! re-match inside it), then defang network indicators for the report table.
//! Fully deterministic and offline.

use std::sync::OnceLock;

use regex::Regex;

use crate::model::{Detection, Host, Ioc, Phase, TimelineEvent};

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

/// Strip trailing sentence punctuation that a regex greedily swept up from
/// surrounding prose (e.g. a path ending in `).` or `,`).
fn trim_trailing_punct(s: &str) -> &str {
    s.trim_end_matches(|c: char| ").,;:'\"]}>".contains(c))
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
    pass(&p.url, &mut out, &|m, out| push(defang_network(trim_trailing_punct(m)), "URL", out));
    pass(&p.email, &mut out, &|m, out| push(defang_email(m), "Email Address", out));
    pass(&p.sha256, &mut out, &|m, out| push(m.to_lowercase(), "Hash", out));
    pass(&p.sha1, &mut out, &|m, out| push(m.to_lowercase(), "Hash", out));
    pass(&p.md5, &mut out, &|m, out| push(m.to_lowercase(), "Hash", out));
    pass(&p.registry, &mut out, &|m, out| push(trim_trailing_punct(m).to_string(), "Registry Key", out));
    pass(&p.win_path, &mut out, &|m, out| push(trim_trailing_punct(m).to_string(), "File Path", out));
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

// ---------------------------------------------------------------------------
// Host extraction
// ---------------------------------------------------------------------------

struct HostPatterns {
    /// `host=`, `hostname:`, `Computer=`, `ComputerName:`, `DestinationHost=` …
    kv: Regex,
    /// UNC path host: `\\HOST\share`.
    unc: Regex,
    /// FQDN with an internal suffix, e.g. `dc01.corp.local`.
    fqdn: Regex,
    /// `NAME (1.2.3.4)` — host name immediately followed by its IP.
    name_ip: Regex,
    /// A host-like token immediately following a leading timestamp
    /// (the common `TIMESTAMP HOST message` column layout).
    lead_host: Regex,
    ipv4: Regex,
}

fn host_patterns() -> &'static HostPatterns {
    static P: OnceLock<HostPatterns> = OnceLock::new();
    P.get_or_init(|| HostPatterns {
        kv: Regex::new(
            r#"(?i)\b(?:host(?:name)?|computer(?:name)?|dest(?:ination)?host|source[_ ]?host|src[_ ]?host)\s*[:=]\s*"?([A-Za-z0-9][A-Za-z0-9._-]{1,63})"?"#,
        )
        .unwrap(),
        unc: Regex::new(r"\\\\([A-Za-z0-9][A-Za-z0-9._-]{1,63})\\").unwrap(),
        fqdn: Regex::new(
            r"(?i)\b([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.(?:local|internal|corp|lan|intranet|home))\b",
        )
        .unwrap(),
        name_ip: Regex::new(
            r"\b([A-Za-z][A-Za-z0-9._-]{1,40})\s*\(\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\)",
        )
        .unwrap(),
        lead_host: Regex::new(
            r"(?i)^\s*(?:\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}:\d{2}\S*|\d{1,2}:\d{2}(?::\d{2})?)\s+([A-Za-z][A-Za-z0-9._-]{1,30})\b",
        )
        .unwrap(),
        ipv4: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
            .unwrap(),
    })
}

/// Heuristic: does this token look like a computer name (rather than a plain
/// word)? Requires a digit, a hyphen, or an all-uppercase form.
fn looks_host_like(t: &str) -> bool {
    if is_ipv4(t) {
        return false;
    }
    let has_digit = t.chars().any(|c| c.is_ascii_digit());
    let has_hyphen = t.contains('-');
    let all_upper = t.len() >= 2
        && t.chars().any(|c| c.is_ascii_alphabetic())
        && t.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '.');
    has_digit || has_hyphen || all_upper
}

struct HostHit {
    name: String,
    ip: String,
    /// The full substring matched, so callers can strip it from a description.
    matched: String,
}

fn is_ipv4(s: &str) -> bool {
    let hp = host_patterns();
    hp.ipv4.is_match(s) && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Tokens that look host-like but are tools, protocols or filler words rather
/// than computer names.
const NON_HOST: &[&str] = &[
    "wmic", "psexec", "psexesvc", "whoami", "powershell", "powershell_ise", "cmd", "iex",
    "rundll32", "regsvr32", "svchost", "lsass", "schtasks", "setspn", "mimikatz", "sharphound",
    "bloodhound", "certutil", "bitsadmin", "at", "on", "in", "to", "by", "the", "and", "for",
    "net", "reg", "sc", "http", "https", "ftp", "ldap", "smb", "rdp", "dns", "tcp", "udp", "rc4",
    "aes", "ntlm", "result", "query", "image", "user", "host", "data", "source", "winword",
    "excel", "outlook", "explorer", "rundll",
];

/// All host mentions on a single (already refanged) line, in reading order.
fn hosts_on_line(line: &str) -> Vec<HostHit> {
    let hp = host_patterns();
    let mut hits: Vec<HostHit> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    let push = |name: &str, ip: &str, matched: &str, hits: &mut Vec<HostHit>, seen: &mut Vec<String>| {
        let name = name.trim();
        if name.len() < 2 || is_ipv4(name) || NON_HOST.contains(&name.to_ascii_lowercase().as_str()) {
            return;
        }
        let key = name.to_lowercase();
        if let Some(pos) = seen.iter().position(|s| *s == key) {
            // Already recorded — fill in an address if we now have one.
            if hits[pos].ip.is_empty() && !ip.is_empty() {
                hits[pos].ip = ip.to_string();
            }
            return;
        }
        seen.push(key);
        hits.push(HostHit { name: name.to_string(), ip: ip.to_string(), matched: matched.to_string() });
    };

    // The reporting host in a `TIMESTAMP HOST message` line takes precedence,
    // so a later inline target does not become the event's host.
    if let Some(c) = hp.lead_host.captures(line) {
        let name = &c[1];
        if looks_host_like(name) {
            push(name, "", name, &mut hits, &mut seen);
        }
    }
    // `NAME (IP)` — the only form we trust to pair a host with an address.
    for c in hp.name_ip.captures_iter(line) {
        push(&c[1], &c[2], c.get(0).unwrap().as_str(), &mut hits, &mut seen);
    }
    for c in hp.kv.captures_iter(line) {
        let name = &c[1];
        if !is_ipv4(name) {
            push(name, "", c.get(0).unwrap().as_str(), &mut hits, &mut seen);
        }
    }
    for c in hp.unc.captures_iter(line) {
        push(&c[1], "", c.get(0).unwrap().as_str(), &mut hits, &mut seen);
    }
    for c in hp.fqdn.captures_iter(line) {
        push(&c[1], "", c.get(0).unwrap().as_str(), &mut hits, &mut seen);
    }
    hits
}

/// Extract affected hosts (name + best-effort IP) from free text.
pub fn extract_hosts(input: &str) -> Vec<Host> {
    let text = refang(input);
    let mut out: Vec<Host> = Vec::new();
    for line in text.lines() {
        for hit in hosts_on_line(line) {
            match out.iter_mut().find(|h| h.name.eq_ignore_ascii_case(&hit.name)) {
                Some(existing) => {
                    if existing.ip.trim().is_empty() && !hit.ip.is_empty() {
                        existing.ip = hit.ip;
                    }
                }
                None => out.push(Host {
                    name: hit.name,
                    ip: hit.ip,
                    description: "Identified during automated extraction.".to_string(),
                }),
            }
        }
        if out.len() >= 50 {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Timeline event extraction
// ---------------------------------------------------------------------------

struct TsPatterns {
    iso: Regex,
    dmy: Regex,
    clock: Regex,
}

fn ts_patterns() -> &'static TsPatterns {
    static P: OnceLock<TsPatterns> = OnceLock::new();
    P.get_or_init(|| TsPatterns {
        // ISO / full datetime: 2026-03-14 09:12:05
        iso: Regex::new(r"\b(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2})(?::(\d{2}))?").unwrap(),
        // Day-month-year: 14-03-2026 09:12:05 or 14/03/26 9:12
        dmy: Regex::new(
            r"\b(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})(?:[ T,]+|\s+at\s+)(\d{1,2}):(\d{2})(?::(\d{2}))?",
        )
        .unwrap(),
        // Bare clock: 03:38:40 or 03:40
        clock: Regex::new(r"\b(\d{1,2}):(\d{2})(?::(\d{2}))?\b").unwrap(),
    })
}

fn valid_hms(h: u32, m: u32, s: u32) -> bool {
    h < 24 && m < 60 && s < 60
}

fn two_digit_year(y: u32) -> u32 {
    if y >= 100 {
        y % 100
    } else {
        y
    }
}

/// Find the first valid timestamp on a line, returning its byte range and a
/// normalised form: `dd-mm-yy hh:mm:ss` when a date is present, else `hh:mm:ss`.
fn find_timestamp(line: &str) -> Option<(std::ops::Range<usize>, String)> {
    let p = ts_patterns();

    let grab = |c: &regex::Captures, hi: usize, mi: usize, si: usize| -> Option<(u32, u32, u32)> {
        let h: u32 = c.get(hi)?.as_str().parse().ok()?;
        let m: u32 = c.get(mi)?.as_str().parse().ok()?;
        let s: u32 = c.get(si).map(|x| x.as_str().parse().unwrap_or(0)).unwrap_or(0);
        valid_hms(h, m, s).then_some((h, m, s))
    };

    if let Some(c) = p.iso.captures(line) {
        if let Some((h, m, s)) = grab(&c, 4, 5, 6) {
            let (y, mo, d) = (
                c[1].parse::<u32>().unwrap_or(0),
                c[2].parse::<u32>().unwrap_or(0),
                c[3].parse::<u32>().unwrap_or(0),
            );
            let mm = c.get(0).unwrap();
            return Some((
                mm.start()..mm.end(),
                format!("{:02}-{:02}-{:02} {:02}:{:02}:{:02}", d, mo, two_digit_year(y), h, m, s),
            ));
        }
    }
    if let Some(c) = p.dmy.captures(line) {
        if let Some((h, m, s)) = grab(&c, 4, 5, 6) {
            let (d, mo, y) = (
                c[1].parse::<u32>().unwrap_or(0),
                c[2].parse::<u32>().unwrap_or(0),
                c[3].parse::<u32>().unwrap_or(0),
            );
            if d <= 31 && mo <= 12 {
                let mm = c.get(0).unwrap();
                return Some((
                    mm.start()..mm.end(),
                    format!("{:02}-{:02}-{:02} {:02}:{:02}:{:02}", d, mo, two_digit_year(y), h, m, s),
                ));
            }
        }
    }
    // Bare clock — first range-valid match on the line.
    for c in p.clock.captures_iter(line) {
        if let Some((h, m, s)) = grab(&c, 1, 2, 3) {
            let mm = c.get(0).unwrap();
            return Some((mm.start()..mm.end(), format!("{:02}:{:02}:{:02}", h, m, s)));
        }
    }
    None
}

fn guess_phase(desc: &str) -> Phase {
    let d = desc.to_ascii_lowercase();
    let has = |ks: &[&str]| ks.iter().any(|k| d.contains(k));
    if has(&["phish", "macro", ".doc", "opened the attach", "initial access", "initial execution", "malicious attachment", "winword"]) {
        Phase::InitialCompromise
    } else if has(&["beacon", "command-and-control", "command and control", " c2 ", "download cradle", "downloadstring", "http beacon", "https beacon"]) {
        Phase::CommandAndControl
    } else if has(&["lsass", "dcsync", "kerberoast", "credential dump", "mimikatz", "sekurlsa", "exfil", "0x1010", "4769"]) {
        Phase::DataAccess
    } else if has(&["psexec", "wmic", "admin$", "pass-the-ticket", "pass the ticket", "pass-the-hash", "lateral", "psexesvc", "remote execution", "ipc$"]) {
        Phase::LateralMovement
    } else if has(&["scheduled task", "schtasks", "run key", "currentversion\\run", "service install", "7045", "persistence", "createremotethread", "process injection", "rundll32", "uac bypass", "fodhelper", "new-service"]) {
        Phase::MalwareActivity
    } else if has(&["sharphound", "bloodhound", "ldap", "adfind"]) {
        Phase::Reconnaissance
    } else if has(&["whoami", "net user", "net group", "net view", "port scan", "nltest", "systeminfo", "tasklist", "enumerat", "discovery"]) {
        Phase::Enumeration
    } else if has(&["isolated", "contained", "quarantine", "blocked outbound", "perimeter block"]) {
        Phase::Containment
    } else if has(&["eradicat", "removed the", "deleted the"]) {
        Phase::Eradication
    } else if has(&["restored", "recovered", "rebuilt"]) {
        Phase::Recovery
    } else {
        Phase::Enumeration
    }
}

fn clean_description(s: &str) -> String {
    let trimmed = s.trim().trim_start_matches(|c: char| "-|,:;>·•*[]".contains(c) || c.is_whitespace());
    trimmed.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract timeline events from lines that carry a timestamp. Each event gets a
/// timestamp, the host on the line (if any), a cleaned description, and a
/// best-effort kill-chain phase (all editable afterwards).
pub fn extract_events(input: &str) -> Vec<TimelineEvent> {
    let text = refang(input);
    let mut out: Vec<TimelineEvent> = Vec::new();

    for line in text.lines() {
        let Some((range, timestamp)) = find_timestamp(line) else { continue };

        let hosts = hosts_on_line(line);
        let host_name = hosts.first().map(|h| h.name.clone()).unwrap_or_default();

        // If the timestamp leads the line it is a log entry — strip the
        // timestamp and host to leave the message. Otherwise the line is prose
        // (the time sits mid-sentence), so keep the whole sentence readable.
        let leading_ws = line.len() - line.trim_start().len();
        let description = if range.start <= leading_ws + 2 {
            let raw = &line[range.clone()];
            let mut d = line.replacen(raw, " ", 1);
            if let Some(h) = hosts.first() {
                d = d.replacen(&h.matched, " ", 1);
            }
            clean_description(&d)
        } else {
            clean_description(line)
        };
        if description.chars().count() < 12 {
            continue;
        }

        if out.iter().any(|e| e.timestamp == timestamp && e.description == description) {
            continue;
        }
        out.push(TimelineEvent {
            timestamp,
            phase: guess_phase(&description),
            host: host_name,
            description,
        });
        if out.len() >= 100 {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Structured detection extraction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Field {
    None,
    DataSource,
    Query,
    Result,
}

fn detection_header() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*detection\s+\d+\s*[:\-\u{2013}\u{2014}]?\s*(.*)$").unwrap())
}

/// Classify a line as a labelled field. Splits on the first colon and matches
/// the label; returns the field kind and any inline value after the colon.
fn field_label(line: &str) -> Option<(Field, String)> {
    let (left, right) = line.split_once(':')?;
    let key = left.trim().to_ascii_lowercase();
    let rest = right.trim().to_string();
    if key == "data source" || key == "data sources" {
        Some((Field::DataSource, rest))
    } else if key == "result" || key == "results" {
        Some((Field::Result, rest))
    } else if key.starts_with("query") {
        Some((Field::Query, rest))
    } else if key.starts_with("tool command") {
        Some((Field::Query, rest))
    } else {
        None
    }
}

fn is_page_number(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && t.len() <= 4 && t.chars().all(|c| c.is_ascii_digit())
}

/// Parse detection blocks structured as `Detection N: title / Data source: … /
/// Query: … / Result: …` into `Detection` records. Tolerant of stray page
/// numbers, blank lines, and multiple query segments per detection.
pub fn extract_detections(input: &str) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    let mut cur: Option<Detection> = None;
    let mut field = Field::None;

    let push_query = |d: &mut Detection, text: &str| {
        if !text.trim().is_empty() {
            if !d.query.is_empty() {
                d.query.push('\n');
            }
            d.query.push_str(text.trim_end());
        }
    };
    let append_prose = |s: &mut String, text: &str| {
        let t = text.trim();
        if t.is_empty() {
            return;
        }
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(t);
    };

    for raw in input.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim();

        if let Some(caps) = detection_header().captures(trimmed) {
            if let Some(d) = cur.take() {
                out.push(d);
            }
            let mut d = Detection::default();
            d.title = caps.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
            cur = Some(d);
            field = Field::None;
            continue;
        }

        let Some(d) = cur.as_mut() else { continue };

        if trimmed.is_empty() || is_page_number(trimmed) {
            continue;
        }

        if let Some((kind, rest)) = field_label(trimmed) {
            field = kind;
            match kind {
                Field::DataSource => append_prose(&mut d.data_source, &rest),
                Field::Result => append_prose(&mut d.result, &rest),
                // A trailing sub-label like "Query: PsExec installs:" is skipped;
                // an inline query is kept.
                Field::Query => {
                    if !rest.is_empty() && !rest.ends_with(':') {
                        push_query(d, &rest);
                    } else if !d.query.is_empty() {
                        d.query.push('\n');
                    }
                }
                Field::None => {}
            }
            continue;
        }

        // Continuation of the current field.
        match field {
            Field::DataSource => append_prose(&mut d.data_source, trimmed),
            Field::Query => push_query(d, line.trim_start()),
            Field::Result => append_prose(&mut d.result, trimmed),
            Field::None => {}
        }
    }
    if let Some(d) = cur.take() {
        out.push(d);
    }
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
    fn parses_structured_detections() {
        // A slice of a real report paste, including PDF page-number artifacts.
        let block = "\
Detection 1: DCSync replication against the domain controller\n\
Data source: Windows Security log, Event ID 4662 (Directory Service Access).\n\
Query:\n\
index=windows OR index=main EventCode=4662 (Message=\"*Replicating Directory Changes*\"\n\
| table _time, host, Account_Name, Object_Name, Access_Mask, Properties\n\
Result: The non-domain-controller account management performed Control Access on\n\
27\n\
11 September 2023. The management account's activity is the illegitimate DCSync.\n\
Detection 2: DCSync tool and target (Invoke-Mimikatz)\n\
Data source: Sysmon Event ID 1 (Process Creation).\n\
Query:\n\
index=windows sourcetype=\"wineventlog:sysmon\" EventCode=1 Image=\"*powershell*\"\n\
| sort _time\n\
Result: On WIN-HIDUIPTH344, PowerShell executed Invoke-Mimikatz targeting krbtgt.";
        let dets = extract_detections(block);
        assert_eq!(dets.len(), 2, "{dets:?}");
        assert_eq!(dets[0].title, "DCSync replication against the domain controller");
        assert!(dets[0].data_source.contains("Event ID 4662"));
        assert!(dets[0].query.contains("EventCode=4662"));
        assert!(dets[0].query.contains("| table"));
        assert!(dets[0].result.contains("Control Access"));
        assert!(dets[0].result.contains("11 September"));
        // The stray page number must not pollute the result.
        assert!(!dets[0].result.contains("27"), "page number leaked: {}", dets[0].result);
        assert_eq!(dets[1].title, "DCSync tool and target (Invoke-Mimikatz)");
        assert!(dets[1].query.contains("wineventlog:sysmon"));
        assert!(dets[1].result.contains("Invoke-Mimikatz"));
    }

    #[test]
    fn detection_with_multiple_queries_and_leading_fragment() {
        let block = "\
der.\n\
Detection 6: Lateral Movement (PsExec and WMIC)\n\
Data source: Windows System log, Event ID 7045; Sysmon Event ID 1.\n\
Query: PsExec service installs:\n\
index=windows OR index=main EventCode=7045 PSEXESVC\n\
| sort t\n\
30\n\
Query: WMI remote execution:\n\
index=windows sourcetype=\"wineventlog:sysmon\" EventCode=1 Image=\"*WMIC.exe*\"\n\
| sort t\n\
Result: The attacker used two remote-execution techniques to move between hosts.";
        let dets = extract_detections(block);
        assert_eq!(dets.len(), 1, "leading fragment should not start a detection: {dets:?}");
        assert_eq!(dets[0].title, "Lateral Movement (PsExec and WMIC)");
        // Both query segments captured, sub-labels and page number dropped.
        assert!(dets[0].query.contains("PSEXESVC"), "q: {}", dets[0].query);
        assert!(dets[0].query.contains("WMIC.exe"), "q: {}", dets[0].query);
        assert!(!dets[0].query.contains("PsExec service installs"), "sub-label leaked");
        assert!(!dets[0].query.contains("30"), "page number leaked");
        assert!(dets[0].result.contains("two remote-execution techniques"));
    }

    #[test]
    fn extracts_hosts_with_ips() {
        let log = "\
            09:12:04  host=WKS-041  user opened doc\n\
            Lateral movement to APP-02 (192.0.2.52) over SMB\n\
            Payload staged on \\\\10.100.0.24\\ADMIN$\\x.exe\n\
            Kerberos logon to dc01.corp.local";
        let hosts = extract_hosts(log);
        let names: Vec<&str> = hosts.iter().map(|h| h.name.as_str()).collect();
        assert!(names.contains(&"WKS-041"));
        assert!(names.contains(&"APP-02"));
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("dc01.corp.local")));
        let app = hosts.iter().find(|h| h.name == "APP-02").unwrap();
        assert_eq!(app.ip, "192.0.2.52");
    }

    #[test]
    fn extracts_events_with_phase_and_host() {
        let log = "\
            2026-03-14 09:12:05  WKS-041  user opened purchase-order.doc and macro ran\n\
            09:24:12  WKS-041  RC4 service ticket requested for svc_reporting (kerberoasting)\n\
            09:31:57  APP-02 (192.0.2.52)  PsExec used to move laterally\n\
            no timestamp here, should be ignored";
        let events = extract_events(log);
        assert_eq!(events.len(), 3, "{events:?}");
        assert_eq!(events[0].phase, Phase::InitialCompromise);
        assert_eq!(events[1].phase, Phase::DataAccess);
        assert_eq!(events[2].phase, Phase::LateralMovement);
        assert_eq!(events[2].host, "APP-02");
        assert!(events[0].description.contains("macro"));
        // Timestamp and host must be stripped from the description.
        assert!(!events[0].description.contains("2026-03-14"));
    }

    #[test]
    fn rejects_invalid_times_and_normalises() {
        // "25:80" inside 18.207.78.25:80 must not become a timeline event.
        assert!(extract_events("Beacon to 18.207.78.25:80/officeupdate over HTTP").is_empty());
        // dd-mm-yyyy datetime normalises to dd-mm-yy hh:mm:ss.
        let e2 = extract_events("14-03-2026 09:12:05 workstation dumped lsass memory");
        assert_eq!(e2.len(), 1);
        assert_eq!(e2[0].timestamp, "14-03-26 09:12:05");
        // Bare clock pads seconds; prose keeps the sentence readable.
        let e3 = extract_events("At 03:40 the collector started enumerating the domain");
        assert_eq!(e3[0].timestamp, "03:40:00");
        assert!(e3[0].description.to_lowercase().contains("collector started"));
    }

    #[test]
    fn trims_trailing_punctuation_on_paths() {
        let iocs = extract_iocs("dropped C:\\ProgramData\\Analytics.exe).");
        assert!(indicators(&iocs, "File Path").contains(&"C:\\ProgramData\\Analytics.exe".to_string()),
            "{:?}", indicators(&iocs, "File Path"));
    }

    #[test]
    fn tool_tokens_are_not_hosts() {
        let hosts = extract_hosts("18:32:35 WMIC /node:10.0.0.216 process call create x.exe");
        assert!(!hosts.iter().any(|h| h.name.eq_ignore_ascii_case("wmic")), "{hosts:?}");
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
