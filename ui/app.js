"use strict";

/* ---------- Tauri bridge (with browser-preview fallback) ---------- */

const tauriCore = window.__TAURI__ && window.__TAURI__.core;

async function invoke(cmd, args) {
  if (tauriCore) return tauriCore.invoke(cmd, args);
  return mockInvoke(cmd, args);
}

function mockInvoke(cmd) {
  switch (cmd) {
    case "list_themes":
      return [
        { name: "Harbour Teal", primary: "#0b3c49", accent: "#14b8c9" },
        { name: "Midnight Slate", primary: "#1e2a3a", accent: "#5b8def" },
        { name: "Ember", primary: "#2b2b2e", accent: "#e2452d" },
      ];
    case "list_art_styles":
      return ["hexgrid", "circuit", "network", "radar", "binary", "contours", "none"];
    case "pack_info":
      return { attack_version: "—", ism_version: "—", technique_count: 0 };
    case "save_engagement":
    case "open_engagement":
    case "open_project":
    case "draft_pentest_summary":
      return null;
    case "list_projects":
      return [];
    case "add_evidence":
      return null;
    case "import_document":
      throw "Document import needs the IntelScribe desktop app.";
    case "export_docx":
      throw "DOCX export needs the IntelScribe desktop app.";
    case "search_techniques":
    case "search_ism":
    case "extract_iocs":
    case "extract_hosts":
    case "extract_events":
    case "extract_detections":
    case "extract_accounts":
    case "extract_cvss":
    case "extract_findings":
    case "suggest_techniques":
    case "lint_report":
      return [];
    default:
      throw "This action needs the IntelScribe desktop app — run: cargo run -p intelscribe-app";
  }
}

/* ---------- Constants ---------- */

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];

const PHASES = [
  ["Reconnaissance", "Reconnaissance"],
  ["InitialCompromise", "Initial Compromise"],
  ["CommandAndControl", "C2 Communications"],
  ["Enumeration", "Enumeration"],
  ["LateralMovement", "Lateral Movement"],
  ["DataAccess", "Data Access & Exfiltration"],
  ["MalwareActivity", "Malware Deployment & Activity"],
  ["Containment", "Containment"],
  ["Eradication", "Eradication"],
  ["Recovery", "Recovery"],
];

const IOC_TYPES = [
  "IPv4 (C2)", "IPv4", "Domain", "URL", "Filename", "File Path", "Hash",
  "Command Line", "Registry Key", "Named Pipe", "Named-Pipe Pattern",
  "Windows Service", "Scheduled Task", "Email Address", "CVE", "Other",
];

const ACSC_CATEGORIES = [
  ["", "(not categorised)"],
  ["C1", "C1 — national significance"],
  ["C2", "C2 — nationally significant org"],
  ["C3", "C3 — significant org"],
  ["C4", "C4 — small / medium org"],
  ["C5", "C5 — unsuccessful attack"],
  ["C6", "C6 — non-malicious event"],
];

const SOCI_IMPACT = [
  ["", "(not assessed)"],
  ["none", "No reportable impact"],
  ["relevant", "Relevant impact — 72 hours"],
  ["significant", "Significant impact — 12 hours"],
];

const E8_STRATEGIES = [
  "Application control",
  "Patch applications",
  "Configure Microsoft Office macro settings",
  "User application hardening",
  "Restrict administrative privileges",
  "Patch operating systems",
  "Multi-factor authentication",
  "Regular backups",
];

const REPORT_KINDS = [
  ["incident", "Incident report"],
  ["pentest", "Penetration test report"],
];

const FINDING_STATUS = ["Open", "Remediated", "Risk Accepted", "Not Applicable"];

const RISK_LIKELIHOOD = [
  [0, "(not rated)"], [1, "1 — Rare"], [2, "2 — Unlikely"],
  [3, "3 — Possible"], [4, "4 — Likely"], [5, "5 — Almost Certain"],
];
const RISK_IMPACT = [
  [0, "(not rated)"], [1, "1 — Insignificant"], [2, "2 — Minor"],
  [3, "3 — Moderate"], [4, "4 — Major"], [5, "5 — Severe"],
];

/* ---------- State ---------- */

function defaultRegulatory() {
  return {
    critical_infrastructure: false, soci_impact: "", aware_time: "",
    personal_info_involved: false, serious_harm_likely: false,
    remedial_action_prevents_harm: false,
  };
}

function defaultIncident() {
  return {
    incident_id: "", title: "", severity: "Medium", status: "In Progress",
    overview: "", key_findings: [], immediate_actions: [],
    stakeholder_impact: "", root_cause: "",
    hosts: [], accounts: [], detections: [], iocs: [], events: [], techniques: [],
    additional_recommendations: [], ism_controls: [], cvss_vector: "",
    acsc_category: "", regulatory: defaultRegulatory(),
  };
}

function defaultFinding() {
  return {
    title: "", severity: "Medium", cvss_vector: "", category: "", affected: "",
    description: "", impact: "", remediation: "", references: [], status: "Open",
    likelihood: 0, impact_rating: 0,
  };
}

function defaultEngagement() {
  const date = new Date().toLocaleDateString("en-AU", {
    day: "numeric", month: "long", year: "numeric",
  });
  return {
    title: "Security Incident Report",
    client: "", analyst: "", analyst_title: "Security Analyst",
    date, version: "1.0", classification: "OFFICIAL: Sensitive",
    incidents: [defaultIncident()],
    essential_eight: [], evidence: [],
    report_kind: "incident", executive_summary: "", scope: "", methodology: "",
    findings: [],
  };
}

function humanSizeJS(b) {
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  return (b / 1048576).toFixed(1) + " MB";
}

let state = defaultEngagement();

/* ---------- DOM helpers ---------- */

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  node.append(...children);
  return node;
}

function wrapField(label, input) {
  return el("div", { class: "field" }, el("label", {}, label), input);
}

function field(obj, key, label, kind = "text", options = null) {
  let input;
  if (kind === "textarea") {
    input = el("textarea");
    input.value = obj[key] || "";
  } else if (kind === "select") {
    input = el("select");
    for (const opt of options) {
      const [value, text] = Array.isArray(opt) ? opt : [opt, opt];
      input.append(el("option", { value }, text));
    }
    input.value = obj[key] || (Array.isArray(options[0]) ? options[0][0] : options[0]);
  } else {
    input = el("input", { type: "text" });
    input.value = obj[key] || "";
  }
  input.addEventListener("input", () => { obj[key] = input.value; schedule(); });
  // Also render immediately when leaving the field or picking from a select.
  input.addEventListener("change", () => { obj[key] = input.value; requestRender(); });
  return wrapField(label, input);
}

function row(...fields) {
  return el("div", { class: "row" }, ...fields);
}

function checkboxField(obj, key, label) {
  const input = el("input", { type: "checkbox" });
  input.checked = !!obj[key];
  input.addEventListener("change", () => { obj[key] = input.checked; schedule(); });
  const wrap = el("label", { class: "check" }, input, document.createTextNode(" " + label));
  return el("div", { class: "field" }, wrap);
}

/* Numeric select storing a Number, from [value, label] option pairs. */
function numSelectField(obj, key, label, options) {
  const input = el("select");
  for (const [v, t] of options) input.append(el("option", { value: String(v) }, t));
  input.value = String(obj[key] ?? 0);
  input.addEventListener("change", () => { obj[key] = parseInt(input.value, 10); schedule(); });
  return wrapField(label, input);
}

/* Maturity-level select (ML0–ML3) that stores a Number, not a string. */
function levelField(obj, key, label) {
  const input = el("select");
  for (let i = 0; i <= 3; i++) input.append(el("option", { value: String(i) }, "ML" + i));
  input.value = String(obj[key] ?? 0);
  input.addEventListener("change", () => { obj[key] = parseInt(input.value, 10); schedule(); });
  return wrapField(label, input);
}

/* Generic editable list of objects. */
function itemList(arr, buildFields, factory, addLabel) {
  const wrap = el("div");
  const listBox = el("div");
  function renderList() {
    listBox.innerHTML = "";
    arr.forEach((item, idx) => {
      const box = el("div", { class: "item" });
      box.append(el("button", {
        class: "remove", type: "button", title: "Remove",
        onclick: () => { arr.splice(idx, 1); renderList(); schedule(); },
      }, "✕"));
      buildFields(box, item);
      listBox.append(box);
    });
  }
  renderList();
  wrap.append(listBox, el("button", {
    class: "add", type: "button",
    onclick: () => { arr.push(factory()); renderList(); schedule(); },
  }, addLabel));
  return wrap;
}

/* Editable list of plain strings (findings, actions). */
function stringList(arr, addLabel) {
  const wrap = el("div");
  const listBox = el("div");
  function renderList() {
    listBox.innerHTML = "";
    arr.forEach((_, idx) => {
      const box = el("div", { class: "item" });
      box.append(el("button", {
        class: "remove", type: "button", title: "Remove",
        onclick: () => { arr.splice(idx, 1); renderList(); schedule(); },
      }, "✕"));
      const input = el("textarea");
      input.value = arr[idx] || "";
      input.addEventListener("input", () => { arr[idx] = input.value; schedule(); });
      box.append(el("div", { class: "field" }, input));
      listBox.append(box);
    });
  }
  renderList();
  wrap.append(listBox, el("button", {
    class: "add", type: "button",
    onclick: () => { arr.push(""); renderList(); schedule(); },
  }, addLabel));
  return wrap;
}

function section(title, open, ...content) {
  const d = el("details", { class: "section" });
  if (open) d.setAttribute("open", "");
  d.append(el("summary", {}, title), el("div", { class: "section-body" }, ...content));
  return d;
}

/* ---------- Technique autocomplete ---------- */

async function refreshTechList(query) {
  try {
    const matches = await invoke("search_techniques", { query: query || "" });
    const list = $("#tech-list");
    list.innerHTML = "";
    for (const m of matches) {
      list.append(el("option", { value: m.id }, `${m.name} (${m.tactic})`));
    }
  } catch (_) { /* non-fatal */ }
}

/* ---------- CVSS 3.1 builder ---------- */

const CVSS_METRICS = [
  ["AV", "Attack Vector", [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]]],
  ["AC", "Attack Complexity", [["L", "Low"], ["H", "High"]]],
  ["PR", "Privileges Required", [["N", "None"], ["L", "Low"], ["H", "High"]]],
  ["UI", "User Interaction", [["N", "None"], ["R", "Required"]]],
  ["S", "Scope", [["U", "Unchanged"], ["C", "Changed"]]],
  ["C", "Confidentiality", [["H", "High"], ["L", "Low"], ["N", "None"]]],
  ["I", "Integrity", [["H", "High"], ["L", "Low"], ["N", "None"]]],
  ["A", "Availability", [["H", "High"], ["L", "Low"], ["N", "None"]]],
];

function parseCvss(vector) {
  const map = {};
  for (const part of (vector || "").split("/")) {
    const [k, v] = part.split(":");
    if (k && v && k.toUpperCase() !== "CVSS") map[k.toUpperCase()] = v.toUpperCase();
  }
  return map;
}

function cvssBuilder(inc) {
  const wrap = el("div");
  const scoreBadge = el("span", { class: "cvss-score" }, "—");

  async function recompute() {
    const parts = CVSS_METRICS.map(([k]) => `${k}:${selects[k].value}`);
    inc.cvss_vector = "CVSS:3.1/" + parts.join("/");
    schedule();
    try {
      const res = await invoke("score_cvss", { vector: inc.cvss_vector });
      scoreBadge.textContent = `${res.score} ${res.rating}`;
      scoreBadge.className = "cvss-score sev-" + res.rating.toLowerCase();
    } catch (err) {
      scoreBadge.textContent = "invalid";
      scoreBadge.className = "cvss-score";
    }
  }

  const existing = parseCvss(inc.cvss_vector);
  const selects = {};
  const grid = el("div", { class: "cvss-grid" });
  for (const [key, label, opts] of CVSS_METRICS) {
    const sel = el("select");
    for (const [v, text] of opts) sel.append(el("option", { value: v }, text));
    sel.value = existing[key] || opts[0][0];
    sel.addEventListener("change", recompute);
    selects[key] = sel;
    grid.append(wrapField(label + " (" + key + ")", sel));
  }

  const header = el("div", { class: "cvss-header" },
    el("span", {}, "CVSS 3.1 base score"), scoreBadge);
  const clearBtn = el("button", {
    class: "add", type: "button",
    onclick: () => { inc.cvss_vector = ""; scoreBadge.textContent = "—"; scoreBadge.className = "cvss-score"; schedule(); },
  }, "Clear CVSS (omit from report)");

  wrap.append(header, grid, clearBtn);
  if (inc.cvss_vector) recompute();
  return wrap;
}

/* ---------- ISM control autocomplete ---------- */

async function refreshIsmList(query) {
  try {
    const matches = await invoke("search_ism", { query: query || "" });
    const list = $("#ism-list");
    list.innerHTML = "";
    for (const c of matches) {
      list.append(el("option", { value: c.id }, `${c.id} — ${c.topic}`));
    }
  } catch (_) { /* non-fatal */ }
}

/* Editable list of ISM control ids (array of strings) with autocomplete
   and a live preview of the resolved control text. */
function ismList(arr) {
  const wrap = el("div");
  const listBox = el("div");
  function renderList() {
    listBox.innerHTML = "";
    arr.forEach((_, idx) => {
      const box = el("div", { class: "item" });
      box.append(el("button", {
        class: "remove", type: "button", title: "Remove",
        onclick: () => { arr.splice(idx, 1); renderList(); schedule(); },
      }, "✕"));
      const input = el("input", { type: "text", list: "ism-list", placeholder: "ISM-1490" });
      input.value = arr[idx] || "";
      const preview = el("div", { class: "ism-preview" });
      async function updatePreview() {
        const matches = await invoke("search_ism", { query: input.value }).catch(() => []);
        const hit = matches.find((c) => c.id.toLowerCase() === input.value.trim().toLowerCase());
        preview.textContent = hit ? hit.text : "";
      }
      input.addEventListener("input", () => {
        arr[idx] = input.value.trim().toUpperCase();
        schedule();
        refreshIsmList(input.value);
        updatePreview();
      });
      box.append(el("div", { class: "field" }, input), preview);
      if (input.value) updatePreview();
      listBox.append(box);
    });
  }
  renderList();
  wrap.append(listBox, el("button", {
    class: "add", type: "button",
    onclick: () => { arr.push(""); renderList(); schedule(); },
  }, "+ Add ISM control"));
  return wrap;
}

function techniqueFields(box, t) {
  const idInput = el("input", { type: "text", list: "tech-list", placeholder: "T1566.001" });
  idInput.value = t.id || "";
  const nameInput = el("input", { type: "text" });
  nameInput.value = t.name || "";
  const tacticInput = el("input", { type: "text" });
  tacticInput.value = t.tactic || "";

  idInput.addEventListener("input", async () => {
    t.id = idInput.value;
    schedule();
    refreshTechList(idInput.value);
    try {
      const matches = await invoke("search_techniques", { query: idInput.value });
      const hit = matches.find((m) => m.id.toLowerCase() === idInput.value.trim().toLowerCase());
      if (hit) {
        t.name = hit.name;
        t.tactic = hit.tactic;
        nameInput.value = hit.name;
        tacticInput.value = hit.tactic;
        schedule();
      }
    } catch (_) { /* offline pack lookup is best-effort */ }
  });
  nameInput.addEventListener("input", () => { t.name = nameInput.value; schedule(); });
  tacticInput.addEventListener("input", () => { t.tactic = tacticInput.value; schedule(); });

  box.append(
    row(wrapField("Technique ID", idInput), wrapField("Tactic", tacticInput)),
    wrapField("Name", nameInput),
  );
}

/* ---------- Form ---------- */

async function autoDraft(inc) {
  try {
    const draft = await invoke("draft_summary", { incident: inc });
    const filled = [];
    if (!inc.overview.trim()) { inc.overview = draft.overview; filled.push("overview"); }
    if (!inc.key_findings.length) { inc.key_findings = draft.key_findings; filled.push("key findings"); }
    if (!inc.stakeholder_impact.trim()) {
      inc.stakeholder_impact = draft.stakeholder_impact;
      filled.push("stakeholder impact");
    }
    if (filled.length) {
      rebuild();
      schedule();
      setStatus("Auto-drafted: " + filled.join(", ") + ". Review and edit — it's your report.");
    } else {
      setStatus("Nothing to draft — overview, key findings and stakeholder impact already have content.");
    }
  } catch (err) {
    setStatus(String(err), true);
  }
}

/* ---------- Ingestion & auto-mapping ---------- */

function mergeIocs(inc, incoming) {
  let added = 0;
  for (const ioc of incoming) {
    const dup = inc.iocs.some(
      (x) => x.ioc_type === ioc.ioc_type &&
             x.indicator.toLowerCase() === ioc.indicator.toLowerCase(),
    );
    if (!dup) { inc.iocs.push(ioc); added++; }
  }
  return added;
}

function mergeTechniques(inc, incoming) {
  let added = 0;
  for (const t of incoming) {
    const dup = inc.techniques.some((x) => x.id.toLowerCase() === t.id.toLowerCase());
    if (!dup) { inc.techniques.push({ id: t.id, name: t.name, tactic: t.tactic }); added++; }
  }
  return added;
}

function mergeHosts(inc, incoming) {
  let added = 0;
  for (const h of incoming) {
    const existing = inc.hosts.find((x) => x.name.toLowerCase() === h.name.toLowerCase());
    if (existing) {
      if (!existing.ip.trim() && h.ip) existing.ip = h.ip;
    } else {
      inc.hosts.push(h);
      added++;
    }
  }
  return added;
}

function mergeAccounts(inc, incoming) {
  let added = 0;
  for (const a of incoming) {
    const dup = inc.accounts.some((x) => x.name.toLowerCase() === a.name.toLowerCase());
    if (!dup) { inc.accounts.push(a); added++; }
  }
  return added;
}

function mergeEvents(inc, incoming) {
  let added = 0;
  for (const ev of incoming) {
    const dup = inc.events.some((x) => x.timestamp === ev.timestamp && x.description === ev.description);
    if (!dup) { inc.events.push(ev); added++; }
  }
  return added;
}

function mergeDetections(inc, incoming) {
  let added = 0;
  for (const d of incoming) {
    const dup = inc.detections.some((x) =>
      x.title.trim().toLowerCase() === d.title.trim().toLowerCase() && x.result === d.result);
    if (!dup) { inc.detections.push(d); added++; }
  }
  return added;
}

/* Paste box: extract IoCs, hosts, timeline events and ATT&CK techniques from
   raw text — individually or all at once. */
function quickImport(inc) {
  const wrap = el("div");
  const ta = el("textarea", { placeholder: "Paste logs, alert text, or command output…" });
  ta.style.minHeight = "96px";

  function text() { return ta.value.trim(); }

  async function run(cmd, merge, noun) {
    if (!text()) { setStatus("Paste some text into the import box first."); return; }
    try {
      const items = await invoke(cmd, { text: text() });
      const added = merge(inc, items);
      rebuild();
      schedule();
      setStatus(`${noun}: found ${items.length}, added ${added} new (duplicates skipped). Review and prune.`);
    } catch (err) {
      setStatus(String(err), true);
    }
  }

  async function runCvss() {
    if (!text()) { setStatus("Paste some text into the import box first."); return; }
    try {
      const vectors = await invoke("extract_cvss", { text: text() });
      if (!vectors.length) { setStatus("No CVSS vector found in the pasted text."); return; }
      inc.cvss_vector = vectors[0];
      rebuild();
      schedule();
      const extra = vectors.length > 1 ? ` (${vectors.length - 1} other vector(s) ignored)` : "";
      setStatus(`CVSS: adopted ${vectors[0]}${extra}. Review in the CVSS 3.1 section.`);
    } catch (err) {
      setStatus(String(err), true);
    }
  }

  async function runAll(t) {
    if (!t || !t.trim()) { setStatus("No text to extract from."); return; }
    try {
      const [iocs, hosts, events, dets, accts, cvss, techs] = await Promise.all([
        invoke("extract_iocs", { text: t }),
        invoke("extract_hosts", { text: t }),
        invoke("extract_events", { text: t }),
        invoke("extract_detections", { text: t }),
        invoke("extract_accounts", { text: t }),
        invoke("extract_cvss", { text: t }),
        invoke("suggest_techniques", { text: t }),
      ]);
      const h = mergeHosts(inc, hosts);
      const ev = mergeEvents(inc, events);
      const de = mergeDetections(inc, dets);
      const io = mergeIocs(inc, iocs);
      const ac = mergeAccounts(inc, accts);
      const te = mergeTechniques(inc, techs);
      // Adopt a CVSS vector found in the source only if none is set yet.
      let cvssNote = "";
      if (cvss.length && !inc.cvss_vector.trim()) {
        inc.cvss_vector = cvss[0];
        cvssNote = `, CVSS vector ${cvss[0]}`;
      }
      rebuild();
      schedule();
      setStatus(`Extracted — ${h} hosts, ${ac} accounts, ${ev} timeline events, ${de} detections, ${io} IoCs, ${te} techniques${cvssNote} added (duplicates skipped). Review and prune.`);
    } catch (err) {
      setStatus(String(err), true);
    }
  }

  function extractEverything() {
    if (!text()) { setStatus("Paste some text into the import box first."); return; }
    runAll(text());
  }

  async function importFile() {
    setStatus("Reading document…");
    try {
      const t = await invoke("import_document");
      if (t === null) { setStatus("Import cancelled."); return; }
      if (!t.trim()) { setStatus("No readable text found in that file."); return; }
      ta.value = t;
      await runAll(t);
    } catch (err) {
      setStatus(String(err), true);
    }
  }

  wrap.append(
    el("div", { class: "import-hint" },
      "Import a document (.txt, .docx, .doc, .pdf) or paste text — IntelScribe extracts what it can, then you review."),
    el("button", { class: "add import-primary", type: "button", onclick: importFile },
      "📄 Import document → extract"),
    ta,
    el("button", { class: "add import-primary", type: "button", onclick: extractEverything },
      "⚡ Extract everything from paste"),
    el("div", { class: "import-grid" },
      el("button", { class: "add", type: "button",
        onclick: () => run("extract_hosts", mergeHosts, "Host extraction") }, "🖥 Hosts"),
      el("button", { class: "add", type: "button",
        onclick: () => run("extract_events", mergeEvents, "Timeline extraction") }, "🕓 Timeline"),
      el("button", { class: "add", type: "button",
        onclick: () => run("extract_detections", mergeDetections, "Detection extraction") }, "🔎 Detections"),
      el("button", { class: "add", type: "button",
        onclick: () => run("extract_iocs", mergeIocs, "IoC extraction") }, "⬇ IoCs"),
      el("button", { class: "add", type: "button",
        onclick: () => run("extract_accounts", mergeAccounts, "Account extraction") }, "👤 Accounts"),
      el("button", { class: "add", type: "button", onclick: runCvss }, "🎯 CVSS"),
      el("button", { class: "add", type: "button",
        onclick: () => run("suggest_techniques", mergeTechniques, "ATT&CK suggestions") }, "✨ ATT&CK"),
    ),
  );
  return wrap;
}

/* Scan everything already written in this incident and suggest techniques. */
async function suggestFromIncident(inc) {
  const parts = [inc.overview, inc.root_cause, ...(inc.key_findings || []), ...(inc.immediate_actions || [])];
  for (const d of inc.detections) parts.push(d.title, d.data_source, d.query, d.result);
  for (const ev of inc.events) parts.push(ev.description);
  const text = parts.filter(Boolean).join("\n");
  if (!text.trim()) { setStatus("Nothing to scan yet — add an overview or some detections first."); return; }
  try {
    const techs = await invoke("suggest_techniques", { text });
    const added = mergeTechniques(inc, techs);
    rebuild();
    schedule();
    setStatus(`Scanned incident text — suggested ${techs.length} technique(s), added ${added} new. Review and prune.`);
  } catch (err) {
    setStatus(String(err), true);
  }
}

function incidentSection(inc, idx) {
  const label = `Incident ${idx + 1}${inc.title ? " — " + inc.title : ""}`;
  return section(label, idx === 0,
    el("button", {
      class: "add", type: "button",
      onclick: () => autoDraft(inc),
    }, "✨ Auto-draft exec summary from the data below"),
    section("Quick import — paste logs → extract", false, quickImport(inc)),
    field(inc, "title", "Incident title"),
    row(
      field(inc, "incident_id", "Incident ID"),
      field(inc, "status", "Status"),
    ),
    field(inc, "severity", "Severity", "select", SEVERITIES),
    field(inc, "overview", "Incident overview", "textarea"),
    field(inc, "stakeholder_impact", "Stakeholder impact", "textarea"),
    field(inc, "root_cause", "Root cause analysis", "textarea"),

    section("Key findings", false, stringList(inc.key_findings, "+ Add finding")),
    section("Immediate actions", false, stringList(inc.immediate_actions, "+ Add action")),

    section("Affected hosts", false, itemList(inc.hosts, (box, h) => {
      box.append(
        row(field(h, "name", "Host name"), field(h, "ip", "IP / network")),
        field(h, "description", "What happened on this host", "textarea"),
      );
    }, () => ({ name: "", ip: "", description: "" }), "+ Add host")),

    section("Affected accounts", false, itemList(inc.accounts, (box, a) => {
      box.append(
        field(a, "name", "Account"),
        field(a, "description", "Exposure / role in the incident"),
      );
    }, () => ({ name: "", description: "" }), "+ Add account")),

    section("Detections", false, itemList(inc.detections, (box, d) => {
      box.append(
        field(d, "title", "Detection title"),
        field(d, "data_source", "Data source"),
        field(d, "query", "SIEM query / tool command", "textarea"),
        field(d, "result", "Result", "textarea"),
      );
    }, () => ({ title: "", data_source: "", query: "", result: "" }), "+ Add detection")),

    section("Indicators of compromise", false, itemList(inc.iocs, (box, ioc) => {
      box.append(
        field(ioc, "indicator", "Indicator"),
        row(
          field(ioc, "ioc_type", "Type", "select", IOC_TYPES),
          field(ioc, "context", "Context"),
        ),
      );
    }, () => ({ indicator: "", ioc_type: "IPv4", context: "" }), "+ Add IoC")),

    section("Timeline events", false, itemList(inc.events, (box, ev) => {
      box.append(
        row(
          field(ev, "timestamp", "Time (dd-mm-yy hh:mm:ss)"),
          field(ev, "host", "Host"),
        ),
        field(ev, "phase", "Kill-chain phase", "select", PHASES),
        field(ev, "description", "Activity", "textarea"),
      );
    }, () => ({ timestamp: "", phase: "Reconnaissance", host: "", description: "" }), "+ Add event")),

    section("MITRE ATT&CK techniques", false,
      el("button", { class: "add", type: "button", onclick: () => suggestFromIncident(inc) },
        "✨ Suggest from incident text"),
      itemList(
        inc.techniques, techniqueFields,
        () => ({ id: "", name: "", tactic: "" }), "+ Add technique",
      )),

    section("Analyst recommendations", false,
      stringList(inc.additional_recommendations, "+ Add recommendation")),

    section("CVSS 3.1 severity", false, cvssBuilder(inc)),

    section("ISM controls (quoted verbatim)", false, ismList(inc.ism_controls)),

    field(inc, "acsc_category", "ASD / ACSC incident category", "select", ACSC_CATEGORIES),

    section("Regulatory & reporting (SOCI · OAIC NDB)", false,
      checkboxField(inc.regulatory, "critical_infrastructure",
        "Asset is critical infrastructure (SOCI Act applies)"),
      field(inc.regulatory, "soci_impact", "SOCI impact assessment", "select", SOCI_IMPACT),
      field(inc.regulatory, "aware_time", "Time the entity became aware"),
      checkboxField(inc.regulatory, "personal_info_involved",
        "Personal information was involved (engages OAIC NDB)"),
      checkboxField(inc.regulatory, "serious_harm_likely",
        "Serious harm to individuals is assessed as likely"),
      checkboxField(inc.regulatory, "remedial_action_prevents_harm",
        "Remedial action has prevented the likely serious harm"),
    ),
  );
}

/* Essential Eight maturity assessment editor (engagement-level). */
function e8Section() {
  const populate = el("button", { class: "add", type: "button",
    onclick: () => {
      state.essential_eight = E8_STRATEGIES.map((s) => ({
        strategy: s, current_level: 0, target_level: 3, notes: "",
      }));
      rebuild();
      schedule();
    } }, "Populate all 8 strategies");
  const list = itemList(state.essential_eight, (box, item) => {
    box.append(
      field(item, "strategy", "Strategy", "select", E8_STRATEGIES),
      row(levelField(item, "current_level", "Current maturity"),
          levelField(item, "target_level", "Target maturity")),
      field(item, "notes", "Notes", "textarea"),
    );
  }, () => ({ strategy: E8_STRATEGIES[0], current_level: 0, target_level: 3, notes: "" }),
    "+ Add strategy");
  return el("div", {}, populate, list);
}

/* Report-type selector — switching rebuilds the whole form. */
function reportKindField() {
  const input = el("select");
  for (const [v, t] of REPORT_KINDS) input.append(el("option", { value: v }, t));
  input.value = state.report_kind || "incident";
  input.addEventListener("change", () => {
    state.report_kind = input.value;
    rebuild();
    schedule();
  });
  return wrapField("Report type", input);
}

async function pentestAutoDraft() {
  try {
    const summary = await invoke("draft_pentest_summary", { engagement: state });
    if (!summary) { setStatus("Add some findings first, then auto-draft."); return; }
    if (state.executive_summary.trim()) {
      setStatus("Executive summary already has content — clear it first to auto-draft.");
      return;
    }
    state.executive_summary = summary;
    rebuild();
    schedule();
    setStatus("Auto-drafted the executive summary from the findings. Review and edit.");
  } catch (err) {
    setStatus(String(err), true);
  }
}

function mergeFindings(incoming) {
  let added = 0;
  for (const f of incoming) {
    const dup = state.findings.some(
      (x) => x.title.trim().toLowerCase() === f.title.trim().toLowerCase());
    if (!dup) {
      // Fill in defaults the extractor leaves unset so the form stays consistent.
      state.findings.push(Object.assign(defaultFinding(), f));
      added++;
    }
  }
  return added;
}

/* Paste a structured pentest report → extract findings (title, severity, CVSS,
   category, affected, description, impact, remediation, status). */
function pentestQuickImport() {
  const wrap = el("div");
  const ta = el("textarea", {
    placeholder: "Paste findings — e.g.\nFinding 1: SQL Injection\nSeverity: High\nCVSS: CVSS:3.1/AV:N/...\nAffected: /login\nDescription: …\nRemediation: …",
  });
  ta.style.minHeight = "96px";

  async function run(t) {
    const text = (t || ta.value).trim();
    if (!text) { setStatus("Paste some findings text first."); return; }
    try {
      const items = await invoke("extract_findings", { text });
      const added = mergeFindings(items);
      rebuild();
      schedule();
      setStatus(`Findings: parsed ${items.length}, added ${added} new (duplicates skipped). Review and prune.`);
    } catch (err) {
      setStatus(String(err), true);
    }
  }

  async function importFile() {
    setStatus("Reading document…");
    try {
      const t = await invoke("import_document");
      if (t === null) { setStatus("Import cancelled."); return; }
      if (!t.trim()) { setStatus("No readable text found in that file."); return; }
      ta.value = t;
      await run(t);
    } catch (err) {
      setStatus(String(err), true);
    }
  }

  wrap.append(
    el("div", { class: "import-hint" },
      "Import a document (.txt, .docx, .doc, .pdf) or paste structured findings — IntelScribe parses each into a finding, then you review."),
    el("button", { class: "add import-primary", type: "button", onclick: importFile },
      "📄 Import document → extract findings"),
    ta,
    el("button", { class: "add import-primary", type: "button", onclick: () => run() },
      "⚡ Extract findings from paste"),
  );
  return wrap;
}

/* Penetration-test form: exec summary, scope, methodology, findings. */
function pentestForm() {
  return el("div", {},
    section("Quick import — paste report → extract findings", false, pentestQuickImport()),
    el("button", { class: "add", type: "button", onclick: pentestAutoDraft },
      "✨ Auto-draft executive summary from findings"),
    field(state, "executive_summary", "Executive summary", "textarea"),
    field(state, "scope", "Scope", "textarea"),
    field(state, "methodology", "Methodology", "textarea"),
    section("Findings", true, itemList(state.findings, (box, f) => {
      box.append(
        field(f, "title", "Finding title"),
        row(field(f, "severity", "Severity", "select", SEVERITIES),
            field(f, "status", "Status", "select", FINDING_STATUS)),
        row(field(f, "category", "Category"), field(f, "affected", "Affected assets")),
        row(numSelectField(f, "likelihood", "Likelihood", RISK_LIKELIHOOD),
            numSelectField(f, "impact_rating", "Consequence", RISK_IMPACT)),
        section("CVSS 3.1 severity", false, cvssBuilder(f)),
        field(f, "description", "Description", "textarea"),
        field(f, "impact", "Impact", "textarea"),
        field(f, "remediation", "Remediation", "textarea"),
        section("ISM references (quoted verbatim)", false, ismList(f.references)),
      );
    }, defaultFinding, "+ Add finding")),
  );
}

/* Evidence vault (engagement-level): attach files, hash them, edit metadata. */
function evidenceSection() {
  const wrap = el("div");
  const listBox = el("div");
  function renderList() {
    listBox.innerHTML = "";
    state.evidence.forEach((ev, idx) => {
      const box = el("div", { class: "item" });
      box.append(el("button", {
        class: "remove", type: "button", title: "Remove",
        onclick: () => { state.evidence.splice(idx, 1); renderList(); schedule(); },
      }, "✕"));
      const meta = `${ev.filename} · ${humanSizeJS(ev.size_bytes || 0)} · SHA-256 ${(ev.sha256 || "").slice(0, 20)}…` +
        (ev.image_ext ? " · 🖼 embedded" : "");
      box.append(
        field(ev, "title", "Description"),
        field(ev, "captured", "Collected (when / where)"),
        field(ev, "notes", "Notes", "textarea"),
        el("div", { class: "ism-preview" }, meta),
      );
      listBox.append(box);
    });
  }
  renderList();
  const add = el("button", { class: "add", type: "button", onclick: async () => {
    setStatus("Select a file to attach…");
    try {
      const ev = await invoke("add_evidence");
      if (ev) {
        state.evidence.push(ev);
        renderList();
        schedule();
        setStatus(`Attached ${ev.filename} — SHA-256 computed${ev.image_ext ? ", image embedded" : ""}.`);
      } else {
        setStatus("Attach cancelled.");
      }
    } catch (err) {
      setStatus(String(err), true);
    }
  } }, "📎 Add evidence file (hashes it)");
  wrap.append(listBox, add);
  return wrap;
}

function rebuild() {
  const form = $("#form");
  form.innerHTML = "";
  form.append(
    section("Engagement", true,
      field(state, "title", "Report title"),
      field(state, "client", "Client / organisation"),
      row(
        field(state, "analyst", "Analyst"),
        field(state, "analyst_title", "Analyst title"),
      ),
      row(
        field(state, "date", "Date"),
        field(state, "version", "Version"),
      ),
      field(state, "classification", "Classification marking"),
      reportKindField(),
    ),
    section("Evidence (chain of custody)", false, evidenceSection()),
  );

  if ((state.report_kind || "incident") === "pentest") {
    form.append(pentestForm());
    return;
  }

  form.append(section("Essential Eight maturity (engagement-level)", false, e8Section()));
  state.incidents.forEach((inc, idx) => form.append(incidentSection(inc, idx)));
  form.append(el("button", {
    class: "add", type: "button",
    onclick: () => { state.incidents.push(defaultIncident()); rebuild(); schedule(); },
  }, "+ Add incident"));
}

/* ---------- Preview ---------- */

let renderSeq = 0;
let timer = null;
let rendering = false;
let pending = false;

/* Kick a render now, coalescing with any in-flight one. If a render is already
   running, mark the state dirty so a single trailing render fires when it
   finishes — this guarantees the latest edits always paint and prevents fast
   edits from piling up overlapping renders. */
function requestRender() {
  clearTimeout(timer);
  if (rendering) { pending = true; return; }
  renderPreview();
}

function setStatus(text, isError = false) {
  const s = $("#status");
  s.textContent = text;
  s.className = "status" + (isError ? " error" : "");
}

/* ---------- Report linter panel ---------- */

function renderLint(findings) {
  const box = $("#lint");
  box.innerHTML = "";
  if (!findings.length) {
    box.className = "lint clean";
    box.textContent = "✓ No report issues detected";
    return;
  }
  box.className = "lint";
  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of findings) counts[f.level] = (counts[f.level] || 0) + 1;
  box.append(el("div", { class: "lint-head" },
    `Report checks — ${counts.error} error${counts.error === 1 ? "" : "s"}, ` +
    `${counts.warning} warning${counts.warning === 1 ? "" : "s"}, ${counts.info} info`));
  const list = el("ul", { class: "lint-list" });
  for (const f of findings) {
    list.append(el("li", { class: "lint-item lvl-" + f.level },
      el("span", { class: "lint-dot" }),
      el("span", { class: "lint-loc" }, f.location + ": "),
      document.createTextNode(f.message)));
  }
  box.append(list);
}

async function runLint() {
  try {
    renderLint(await invoke("lint_report", { engagement: state }));
  } catch (_) { /* mock mode or transient error */ }
}

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(requestRender, 250);
}

async function renderPreview() {
  rendering = true;
  pending = false;
  const seq = ++renderSeq;
  runLint();
  setStatus("Rendering…");
  try {
    const res = await invoke("render_preview", {
      engagement: state,
      theme_name: $("#theme-select").value,
      art_style: $("#art-select").value || "auto",
    });
    if (seq !== renderSeq) return;
    const pages = $("#pages");
    pages.innerHTML = "";
    for (const b64 of res.pages) {
      const img = new Image();
      img.src = "data:image/png;base64," + b64;
      pages.append(img);
    }
    if (res.warnings && res.warnings.length) {
      setStatus("⚠ " + res.warnings.join("\n"));
    } else {
      setStatus(`Up to date — ${res.pages.length} page${res.pages.length === 1 ? "" : "s"}`);
    }
  } catch (err) {
    if (seq === renderSeq) setStatus(String(err), true);
  } finally {
    rendering = false;
    // Edits that arrived while this render was in flight → paint them now.
    if (pending) renderPreview();
  }
}

/* ---------- Init ---------- */

async function init() {
  const themeSelect = $("#theme-select");
  try {
    const themes = await invoke("list_themes");
    themeSelect.innerHTML = "";
    for (const t of themes) themeSelect.append(el("option", { value: t.name }, t.name));
  } catch (_) { /* keep empty select */ }
  themeSelect.addEventListener("change", schedule);

  const artSelect = $("#art-select");
  artSelect.append(el("option", { value: "auto" }, "Cover art: theme default"));
  try {
    const styles = await invoke("list_art_styles");
    for (const style of styles) {
      artSelect.append(el("option", { value: style }, "Cover art: " + style));
    }
  } catch (_) { /* keep default option */ }
  artSelect.addEventListener("change", schedule);

  $("#btn-new").addEventListener("click", () => {
    if (!confirm("Start a new, empty report? Unsaved changes will be lost.")) return;
    state = defaultEngagement();
    rebuild();
    requestRender();
  });

  $("#btn-save").addEventListener("click", async () => {
    try {
      const path = await invoke("save_engagement", { engagement: state });
      if (path) { setStatus("Saved: " + path); refreshRecent(); }
    } catch (err) {
      setStatus(String(err), true);
    }
  });

  const recentSelect = $("#recent-select");
  recentSelect.addEventListener("change", async () => {
    const path = recentSelect.value;
    recentSelect.value = "";
    if (!path) return;
    try {
      const engagement = await invoke("open_project", { path });
      if (engagement) {
        state = engagement;
        rebuild();
        requestRender();
        setStatus("Opened " + (state.title || "report") + ".");
      }
    } catch (err) {
      setStatus(String(err), true);
    }
  });

  $("#btn-open").addEventListener("click", async () => {
    try {
      const engagement = await invoke("open_engagement");
      if (engagement) {
        state = engagement;
        rebuild();
        requestRender();
        setStatus("Opened " + (state.title || "report") + ".");
      }
    } catch (err) {
      setStatus(String(err), true);
    }
  });

  $("#btn-export").addEventListener("click", async () => {
    setStatus("Exporting PDF…");
    try {
      const path = await invoke("export_pdf", {
        engagement: state,
        theme_name: themeSelect.value,
        art_style: $("#art-select").value || "auto",
      });
      setStatus("Saved: " + path);
    } catch (err) {
      setStatus(String(err), true);
    }
  });

  $("#btn-export-docx").addEventListener("click", async () => {
    setStatus("Exporting DOCX…");
    try {
      const path = await invoke("export_docx", {
        engagement: state,
        theme_name: themeSelect.value,
      });
      setStatus("Saved: " + path);
    } catch (err) {
      setStatus(String(err), true);
    }
  });

  try {
    const info = await invoke("pack_info");
    if (info.technique_count > 0) {
      setStatus(`Knowledge packs loaded — MITRE ATT&CK v${info.attack_version} (${info.technique_count} techniques), ACSC ISM ${info.ism_version}.`);
    }
  } catch (_) { /* non-fatal */ }

  refreshTechList("");
  refreshIsmList("");
  refreshRecent();
  rebuild();
  requestRender();
}

async function refreshRecent() {
  const sel = $("#recent-select");
  if (!sel) return;
  try {
    const projects = await invoke("list_projects");
    sel.innerHTML = "";
    sel.append(el("option", { value: "" }, "Recent…"));
    for (const p of projects) sel.append(el("option", { value: p.path }, p.name));
    sel.style.display = projects.length ? "" : "none";
  } catch (_) {
    sel.style.display = "none";
  }
}

init();
