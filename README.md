# IntelScribe

**Offline desktop assistant for writing commercial-grade technical cyber reports.**

Fill out a structured form once — IntelScribe generates the executive summary,
numbered detections, IoC tables, an auto-drawn attack-path map, a kill-chain
timeline, MITRE ATT&CK mapping, auto-derived mitigations, verbatim ACSC ISM
control quoting and a CVSS 3.1 score, rendered as a themed, professional PDF.
No internet connection is required at any point.

Everything is deterministic — the same input always produces the same report —
and the full MITRE ATT&CK matrix and the Australian Government ISM ship inside
the binary, so it runs completely offline (airgap-friendly).

## Features

- **Two report types** — an incident report and a penetration-test report
  (findings-centric, with per-finding CVSS, remediation and retest status),
  switched from a single dropdown; both share the cover, themes and CVSS engine.
- **Import a document or paste** — import a `.txt`, `.docx`, `.doc` or `.pdf`
  (e.g. an existing report) and run it through the same extraction, or paste raw
  logs, alert text, or a report section and extract everything in one click:
  defanged IoCs
  (IPs, URLs, domains, hashes, paths, registry keys, emails), affected hosts
  (name + IP), timeline events (timestamp, host, description, guessed kill-chain
  phase), structured detections (`Detection N: … / Data source / Query /
  Result`, tolerant of PDF page-number artifacts and multi-query blocks), and
  suggested MITRE ATT&CK techniques. Suggested techniques cascade into the
  ATT&CK table, attack map and mitigations.
- **Structured incident model** — enter each fact once (hosts, accounts,
  detections, IoCs, timeline events, techniques); every section is generated
  from it.
- **Attack-path map & ATT&CK coverage matrix** — a kill-chain phase strip and
  host-to-host movement diagram drawn from your timeline, plus a Navigator-style
  tactic×technique coverage matrix built from the mapped techniques.
- **Auto-derived mitigations** — recommended controls ranked by the ATT&CK
  techniques you mapped, with an ACSC Essential Eight rollup.
- **Executive-summary auto-draft** — composes overview, key findings and
  stakeholder impact from the structured data (deterministic, no LLM).
- **Full MITRE ATT&CK v19.1** — 697 techniques with descriptions and official
  mitigations, autocompleted as you type.
- **ACSC ISM quoting** — cite a control (e.g. `ISM-1488`) and its exact text is
  reproduced from the official OSCAL catalog.
- **CVSS 3.1 calculator** — a metric-by-metric builder with a live base score,
  faithful to the FIRST.org specification.
- **Australian frameworks** — ASD/ACSC incident categorisation (C1–C6), an
  Essential Eight maturity matrix, and deterministic reporting-obligation
  helpers for the SOCI Act (12h/72h) and the OAIC Notifiable Data Breaches
  scheme. Advisory decision support, not legal advice.
- **Live report linter** — a checks panel that flags completeness gaps,
  consistency issues (techniques or hosts named in prose but missing from the
  tables), and sanitisation concerns (internal IPs to review before external
  release), updating as you edit.
- **18 palettes × 7 procedural cover-art styles** — 100+ professional looks;
  all cover art is generated (no stock images, no licensing).
- **Save / open & export** — save an engagement to a `.sok` project file (JSON)
  and reopen it later; export a themed **PDF** or an editable **Word (.docx)**
  document (for track-changes review) to `Desktop\IntelScribe Exports\`.

## Stack

- **Rust workspace** — all logic compiled; single binary output
- **Typst** (embedded as a library) — offline PDF typesetting with live preview
- **Tauri 2** — desktop GUI (form editor left, rendered preview right)
- **No runtime network access, no LLM** — deterministic and auditable

## Download & run

### 1. Prerequisites (Windows 10/11)

| Requirement | Install |
| --- | --- |
| **Rust** (stable, MSVC) | `winget install Rustlang.Rustup` — then open a new terminal |
| **Microsoft C++ Build Tools** | `winget install Microsoft.VisualStudio.2022.BuildTools` — select the *Desktop development with C++* workload (MSVC + Windows SDK) |
| **WebView2 runtime** | Preinstalled on Windows 11; on Windows 10 install *Microsoft Edge WebView2 Runtime* |

Rust's linker on Windows needs the C++ Build Tools — the second row is not
optional. On macOS/Linux the Tauri prerequisites differ; see
<https://tauri.app/start/prerequisites/>.

### 2. Get the code

```powershell
git clone https://github.com/xGhst0/intelscribe.git
cd intelscribe
```

### 3. Run

```powershell
cargo run -p intelscribe-app
```

The first build compiles all dependencies (including the Typst engine) and can
take several minutes; subsequent runs are incremental and start in seconds.

The knowledge packs (MITRE ATT&CK, ACSC ISM) are already committed under
`packs/`, so no download step is required — the app is fully functional offline
out of the box. Click **New** to start a blank report; **Export PDF** writes a
themed PDF to `Desktop\IntelScribe Exports\`.

### Build a standalone app

For a polished, double-clickable program (embedded icon, no console window):

```powershell
cargo build --release -p intelscribe-app
```

This produces `target\release\intelscribe-app.exe` — a self-contained app you
can pin to the taskbar or place a shortcut to. To build a Windows installer
(NSIS, per-user, no admin required) install the Tauri CLI once and run:

```powershell
cargo install tauri-cli --version "^2.0" --locked
cargo tauri build
```

The installer is written to `target\release\bundle\nsis\`. The application icon
is generated by `tools\make-icon.ps1`, and `tools\make-shortcut.ps1` places a
Desktop shortcut to the built exe.

> **Windows Smart App Control note:** SAC may block the freshly built,
> unsigned `cargo-tauri.exe`, causing `cargo tauri build` to fail with
> `os error 4551`. The standalone `cargo build --release` exe is unaffected;
> to build the installer, allow the tool through Smart App Control (or disable
> SAC) and re-run. Signing the binaries removes this friction.

### Tests

```powershell
cargo test
```

> **Windows Smart App Control note:** SAC occasionally blocks a freshly
> compiled, unsigned test/proc-macro binary (`os error 4551`/`1602`). If a
> build or test aborts with an "Application Control policy has blocked this
> file" message, delete the named file under `target\debug\deps\` and re-run —
> the second attempt normally succeeds.

## Repository layout

```
crates/core      incident model, themes, templates, knowledge packs, CVSS, autofill
crates/render    Typst world, document builder, cover art, PDF/PNG rendering
crates/app       Tauri desktop application (commands + window)
ui/              static frontend (vanilla HTML/CSS/JS, no Node required)
templates/       report section schemas + boilerplate (data, not code)
themes/          visual theme collection (palettes + cover-art assignments)
packs/           offline knowledge packs (committed, embedded in the binary)
packs/raw/       raw upstream data for regenerating packs (gitignored)
```

There is no bundled example report. The test suite uses a fully fictional
fixture (`crates/render/fixtures/demo_engagement.json`) with invented
identifiers and RFC 5737 documentation IP ranges.

## Regenerating the knowledge packs

The committed packs are small, preprocessed extracts. To refresh them when
MITRE or the ACSC publish updates, download the raw sources into `packs/raw/`
and rebuild:

- MITRE ATT&CK — `enterprise-attack.json` from
  <https://github.com/mitre-attack/attack-stix-data>
- ACSC ISM — `ISM_catalog.json` from
  <https://github.com/AustralianCyberSecurityCentre/ism-oscal>

```powershell
cargo run -p intelscribe-core --example build_packs
```

## Roadmap

- **M1 — done.** Incident-report template, live preview, PDF export.
- **M2 — done.** Full MITRE ATT&CK v19.1, ACSC ISM verbatim quoting, CVSS 3.1.
- **M3 — done.** Attack-path map, auto-derived mitigations, exec-summary
  auto-draft, 18-palette theme engine with procedural cover art.
- **Ingestion — done.** Paste logs → extract IoCs (with defang), affected
  hosts, timeline events (with phase), structured detections, and suggested
  ATT&CK techniques.
- **Australian frameworks — done.** ACSC C1–C6 categorisation, Essential Eight
  maturity matrix, SOCI Act and OAIC NDB reporting-obligation helpers.
- **Report linter — done.** Live completeness, consistency and sanitisation
  checks in the editor.
- **M4 — in progress.** More report types. Penetration-test report done
  (findings with CVSS, remediation and status); threat hunt, threat-intel/actor
  profile and executive one-pager to follow.
- **M5 — in progress.** IoC/host/timeline/detection auto-extraction, report
  linter, `.sok` engagement files and DOCX export are done; evidence vault
  (hashing, redaction) remains.

See [`docs/IDEAS.md`](docs/IDEAS.md) for the wider backlog.

## Licence & attribution

IntelScribe is licensed under the [Apache License 2.0](LICENSE).

Bundled reference data is redistributed under its own terms (see [`NOTICE`](NOTICE)):
MITRE ATT&CK® © The MITRE Corporation (ATT&CK Terms of Use); the Australian
Government Information Security Manual © Commonwealth of Australia, licensed
CC BY 4.0. Always obtain the authoritative versions from their official sources.
