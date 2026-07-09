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

- **Paste-to-extract & auto-mapping** — paste raw logs or alert text to
  auto-extract defanged IoCs (IPs, URLs, domains, hashes, paths, registry keys,
  emails), and suggest MITRE ATT&CK techniques from the text; suggested
  techniques cascade into the ATT&CK table, attack map and mitigations.
- **Structured incident model** — enter each fact once (hosts, accounts,
  detections, IoCs, timeline events, techniques); every section is generated
  from it.
- **Attack-path map** — a kill-chain phase strip and a host-to-host movement
  diagram drawn natively from your timeline.
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
- **18 palettes × 7 procedural cover-art styles** — 100+ professional looks;
  all cover art is generated (no stock images, no licensing).
- **PDF export** — writes to `Desktop\IntelScribe Exports\`.

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
- **Ingestion — done.** Paste logs → IoC extraction (with defang) and ATT&CK
  technique suggestion from incident text.
- **M4 — planned.** More report templates (pentest + retest, threat hunt,
  threat-intel/actor profile, executive one-pager).
- **M5 — planned.** Evidence vault (hashing, redaction), IoC auto-extraction
  from pasted logs, report linter, engagement files, DOCX export.

See [`docs/IDEAS.md`](docs/IDEAS.md) for the wider backlog.

## Licence & attribution

IntelScribe is licensed under the [Apache License 2.0](LICENSE).

Bundled reference data is redistributed under its own terms (see [`NOTICE`](NOTICE)):
MITRE ATT&CK® © The MITRE Corporation (ATT&CK Terms of Use); the Australian
Government Information Security Manual © Commonwealth of Australia, licensed
CC BY 4.0. Always obtain the authoritative versions from their official sources.
