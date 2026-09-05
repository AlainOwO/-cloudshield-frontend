# CloudShield Frontend

The dashboard for [CloudShield](https://github.com/AlainOwO/cloudshield-backend) — a DevSecOps scanning tool. Lets you kick off a repository scan, watch it run, and browse findings with AI-suggested remediation patches.

## What it does

- Submit a public GitHub repo URL and run a security scan
- Live progress view while the scan runs (cloning, static analysis, CVE cross-referencing, AI patch generation)
- Findings shown as expandable cards with severity badges, filterable by severity
- Copy or export any AI-suggested patch
- Browse and clear past scan history

## Requirements

- Node.js and npm
- The [CloudShield backend](https://github.com/AlainOwO/cloudshield-backend) running locally on `http://localhost:8080` — this app expects it to already be up.

## Setup

```bash
npm install
```

## Run

```bash
npm start
```

Opens on `http://localhost:3000`.

## Notes

- All API calls go to `http://localhost:8080` directly (see `App.js`). If you deploy the backend elsewhere, update those URLs accordingly.
- Built with React, [lucide-react](https://lucide.dev/) for icons, and plain CSS (no Tailwind).
