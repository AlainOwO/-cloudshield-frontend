<div align="center">

# 🛡️ CloudShield — Frontend

**The dashboard for CloudShield.** Paste in a GitHub repo, watch it get scanned in real time tool-by-tool, and browse the findings with AI-suggested fixes.

[![React](https://img.shields.io/badge/React-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org/)

</div>

---

## What this actually does

This isn't just a form that submits and shows a spinner. When you click **Run scan**, here's what's really happening:

1. It sends the repo URL to the backend, which immediately hands back a job ID (the scan itself runs in the background)
2. The frontend opens a live connection to the backend and **listens for real progress updates** as they happen — not a fake loading animation
3. Each of the 4 security tools lights up as **queued → running → done**, one at a time, exactly matching what's actually happening on the server
4. Once it's done, findings show up as expandable cards — each one tagged with the real tool that found it, color-coded by severity, with a copy-able AI-suggested fix

## What makes this more than a form

- **The progress bar isn't lying to you.** Older versions of this dashboard simulated progress with a fake timer. This one is wired to the backend's real [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) stream — if a scan is slow, the UI is slow too, honestly.
- **Tool attribution is real, not guessed.** Each finding shows which of the 4 scanners (gitleaks / semgrep / trivy / checkov) actually produced it, straight from the backend. Older findings that predate this feature show a dashed "?" badge instead of a solid one — a small but honest distinction between "we know" and "we're guessing."
- **The health score means something.** Rather than just subtracting points per finding, the score:
  - Weighs findings from your own code (secrets, static analysis, Dockerfile issues) more heavily than findings from third-party dependencies, which are often noisier and less directly your fault
  - Applies diminishing returns — the 10th medium-severity finding doesn't hurt as much as the 1st
  - Automatically caps the grade if there's a genuine, high-confidence critical finding — a single real leaked secret can't be diluted into a good score by a pile of minor dependency warnings

---

## 🧰 Requirements

- **Node.js** and **npm**
- The [CloudShield backend](../cloudshield-backend) running on `http://localhost:8080` — this dashboard doesn't do anything without it

## 🚀 Getting started

```bash
npm install
npm start
```

Opens at `http://localhost:3000`.

---

## ✨ Features tour

| Feature | What it looks like |
|---|---|
| **Live scan terminal** | Each tool shown as a row that transitions from queued → running (with a spinner) → done (with a checkmark), plus a real elapsed-time counter |
| **Repo health score** | A letter grade (A–F) and 0–100 score, calculated with real weighting logic, not flat point deduction |
| **Severity filters** | Click a chip to filter findings down to just CRITICAL, HIGH, MEDIUM, or LOW |
| **Tool badges** | Every finding shows which scanner found it, with a tooltip explaining whether that's confirmed or inferred |
| **Copy / export** | Copy an AI patch to clipboard, or export any finding as a JSON file |
| **Scan history** | Browse every past finding, with a confirm-before-delete modal for clearing it |
| **Command palette** | Press `⌘K` / `Ctrl+K` for quick actions (new scan, view history, clear history) |
| **Toasts** | Real error messages when something fails — no `alert()` popups |

---

## 📁 Project structure

```
src/
├── App.js       # Everything lives here for now: scan flow, SSE handling,
│                # findings list, health score, command palette
└── App.css      # All styling — custom CSS, no framework dependency
```

Yes, it's a single large component file rather than split into many small ones — that's a reasonable tradeoff for a project this size, but worth splitting up (e.g. separate files per component) if it keeps growing.

---

## 🔌 Connecting to a different backend

All API calls point to `http://localhost:8080` directly inside `App.js`. If you deploy the backend somewhere else, search for that URL and replace it — there's no environment variable or config file for it yet.

---

## ⚠️ Known limitations (honest list)

- **No tests** — nothing here is covered by unit or component tests yet
- **Hardcoded backend URL** — see above, not configurable via `.env` yet
- **No authentication UI** — matches the backend, which also has none yet
- **Single component file** — works fine now, but would benefit from being split up as more features get added

---

## 📄 License

Personal/educational project. No license specified yet.
