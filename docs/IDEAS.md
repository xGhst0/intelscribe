# IntelScribe — idea backlog

Candidate features beyond the current milestones, grouped into six threads.
This is a whiteboard, not a commitment — items graduate into M4/M5 as they're
picked up.

## 1. Kill the typing — ingestion & auto-extraction

The highest-leverage area: reduce how much the analyst types.

- Paste raw logs/text → auto-extract IoCs (IPs, domains, hashes, file paths,
  registry keys) with automatic defanging.
- Import SIEM exports (Splunk CSV, Elastic JSON, Sentinel) and map columns to
  timeline events.
- Import KAPE / EVTX / Sysmon triage output → auto-populate hosts, timeline
  and IoCs.
- STIX / MISP indicator import.
- Command transcript → suggested techniques.

## 2. Make it think — enrichment & auto-mapping

- Detection ↔ ATT&CK auto-linking (write a detection, get a suggested
  technique; the ATT&CK table, attack map and mitigations then populate
  themselves).
- Suggest ATT&CK data sources / components per technique.
- Auto-draft root-cause and TTP narrative prose from the structured data.
- Diamond Model per intrusion.
- Estimative / confidence language aligned to ICD 203.

## 3. Guardrails — commercial-grade QA

- Report linter: unmapped techniques, timeline gaps, orphaned references,
  missing severities.
- IoC prose-vs-table consistency check and defang consistency.
- Redaction / sanitisation pass (flag real internal IPs, hostnames, usernames
  before export).
- Per-paragraph classification markings (PSPF) with export refusal when a
  paragraph marking exceeds the document marking.
- Acronym-before-definition check.

## 4. The Australian moat — defence / government compliance

Differentiators that generic report tools don't attempt.

- Essential Eight maturity self-assessment matrix (ML1/2/3).
- ACSC incident categorisation (C1–C6).
- OAIC Notifiable Data Breach "serious harm" assessment helper.
- SOCI Act critical-infrastructure reporting timers (12h / 72h).
- ReportCyber-ready export formatting.

## 5. More report types — M4 template taxonomy

The section-schema system is data-driven, so new report types are new schemas.

- Penetration test report with retest / remediation tracking.
- Threat hunt report (hypothesis → queries → findings → coverage).
- Threat intelligence / APT actor profile.
- Executive one-pager brief.
- Vulnerability assessment and purple-team report.

## 6. Show & ship — visuals & output

- ATT&CK Navigator-style heatmap (with layer import/export).
- Risk matrix (likelihood × impact) heatmap.
- Remediation Gantt roadmap.
- DOCX export and version diffing.
- TLP-tiered redacted copies (generate a sanitised partner version).

## Cross-cutting — product & workflow

- Engagement / case library: list, search, clone past reports.
- Reusable snippet library for boilerplate methodology paragraphs.
- Per-client branding / letterhead.
- Project files with autosave and versioning.

## Explicitly parked

- **Live SIEM connectors** (as opposed to file import) — would break the
  offline / airgap guarantee. Stick to file and paste import.
- **Local-LLM prose mode** — reopens the determinism and auditability questions
  that the deterministic engine was chosen to close.
