import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  ShieldAlert, Loader2, History, PlusCircle, Trash2, Download,
  Check, ChevronDown, Copy, Radar, GitBranch, X, AlertTriangle,
  KeyRound, ScanSearch, Bug, FileCog, Command, Search,
} from 'lucide-react';
import './App.css';

// Bookend pipeline steps, shown as the classic checklist log lines,
// with the tool terminal sandwiched between them.
const PRE_STEPS = ['Cloning repository', 'Walking file tree'];
const POST_STEPS = ['Generating AI remediation patches'];

// Each tool that runs during a scan, in execution order.
// icon + accentVar drive the terminal row + the glow color while it runs.
const SCAN_TOOLS = [
  {
    id: 'gitleaks',
    name: 'gitleaks',
    task: 'scanning commit history for exposed secrets',
    icon: KeyRound,
    accentVar: '--tool-gitleaks',
  },
  {
    id: 'semgrep',
    name: 'semgrep',
    task: 'running static analysis rule sets',
    icon: ScanSearch,
    accentVar: '--tool-semgrep',
  },
  {
    id: 'trivy',
    name: 'trivy',
    task: 'cross-referencing dependencies against CVE database',
    icon: Bug,
    accentVar: '--tool-trivy',
  },
  {
    id: 'checkov',
    name: 'checkov',
    task: 'auditing infrastructure-as-code against policy baseline',
    icon: FileCog,
    accentVar: '--tool-checkov',
  },
];

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const SEVERITY_STYLE = {
  CRITICAL: { var: '--critical', bg: '--critical-bg' },
  HIGH: { var: '--high', bg: '--high-bg' },
  MEDIUM: { var: '--medium', bg: '--medium-bg' },
  LOW: { var: '--low', bg: '--low-bg' },
};

// Attributes a finding to the tool that most plausibly produced it, based
// on the real naming conventions each tool uses for its rule IDs:
//   - Checkov:  CKV_AWS_79, CKV2_K8S_6, CKV_DOCKER_2 ...
//   - Trivy:    CVE-2024-12345, GHSA-xxxx-xxxx-xxxx, or its own AVD-* IDs
//   - Semgrep:  dotted rule-id paths, e.g. python.django.security.audit.xss
//   - Gitleaks: no fixed prefix — rule names use secret vocabulary
//     (aws-access-key, generic-api-key, private-key, ...)
// This is still an inference, not ground truth — a finding only carries a
// severity/rule/path in this payload, not which process emitted it. When
// nothing matches by rule name we fall back to file-type signals, and mark
// the result as a "guess" so the UI doesn't overstate its confidence.
// The reliable fix is having the backend tag findings with their source
// tool at scan time and reading finding.tool directly instead of this.
function classifyTool(finding) {
  const rule = (finding.ruleName || '').trim();
  const file = (finding.filePath || '').trim();

  if (/^CKV2?_[A-Z0-9]+_\d+/i.test(rule)) {
    return { id: 'checkov', confidence: 'high' };
  }

  if (/^(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|AVD-[A-Z]+-\d+)/i.test(rule)) {
    return { id: 'trivy', confidence: 'high' };
  }

  if (/^[a-z0-9_]+(\.[a-z0-9_-]+){2,}$/i.test(rule)) {
    return { id: 'semgrep', confidence: 'high' };
  }

  if (/(secret|api[-_]?key|access[-_]?key|token|password|private[-_]?key|credential)/i.test(rule)) {
    return { id: 'gitleaks', confidence: 'high' };
  }

  if (/\.(tf|tfvars)$|\.ya?ml$|Dockerfile$|docker-compose/i.test(file)) {
    return { id: 'checkov', confidence: 'guess' };
  }
  if (/package-lock\.json$|requirements.*\.txt$|go\.sum$|Pipfile\.lock$|Gemfile\.lock$|pom\.xml$|\.csproj$/i.test(file)) {
    return { id: 'trivy', confidence: 'guess' };
  }

  // Last resort: most general-purpose SAST tool, explicitly flagged unsure.
  return { id: 'semgrep', confidence: 'guess' };
}

function getSeverityStyle(sev) {
  const key = SEVERITY_STYLE[sev] ? sev : 'LOW';
  const s = SEVERITY_STYLE[key];
  return {
    color: `var(${s.var})`,
    background: `var(${s.bg})`,
    borderColor: `var(${s.var})`,
  };
}

function countSeverity(list, sev) {
  return list.filter((f) => f.severity === sev).length;
}

function StatCard({ label, value, color, max }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let raf;
    const start = performance.now();
    const duration = 600;
    const tick = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      setDisplay(Math.round(value * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);

  const pct = max > 0 ? Math.round((value / max) * 100) : 0;

  return (
    <div className="cs-stat-card">
      <div className="cs-stat-label">{label}</div>
      <div className="cs-stat-value" style={{ color }}>{display}</div>
      <div className="cs-stat-bar-track">
        <div className="cs-stat-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

function FindingCard({ finding, index, onExport, onCopied }) {
  const [open, setOpen] = useState(index === 0);
  const style = getSeverityStyle(finding.severity);
  const attribution = classifyTool(finding);
  const tool = SCAN_TOOLS.find((t) => t.id === attribution.id);
  const ToolIcon = tool.icon;
  const isGuess = attribution.confidence === 'guess';

  const handleCopy = async (e) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(finding.aiSuggestedPatch || '');
      onCopied();
    } catch {
      /* clipboard unavailable, silently ignore */
    }
  };

  return (
    <div className="cs-finding-card" style={{ borderLeftColor: style.color }}>
      <button className="cs-finding-head" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <div>
          <div className="cs-finding-title">
            <h3>{finding.ruleName}</h3>
            <span className="cs-sev-badge" style={{ color: style.color, background: style.background }}>
              {finding.severity}
            </span>
            <span
              className={`cs-tool-badge ${isGuess ? 'cs-tool-badge--guess' : ''}`}
              style={{ color: `var(${tool.accentVar})` }}
              title={isGuess
                ? 'Inferred from file type — rule name didn\'t match a known pattern, so this is a guess.'
                : `Rule ID matches ${tool.name}'s naming convention.`}
            >
              <ToolIcon size={11} /> {tool.name}{isGuess && <span className="cs-tool-badge-q">?</span>}
            </span>
          </div>
          <div className="cs-finding-path">{finding.filePath} : {finding.lineNumber}</div>
        </div>
        <ChevronDown size={18} className={`cs-chevron ${open ? 'open' : ''}`} />
      </button>

      {open && (
        <div className="cs-finding-body">
          <div className="cs-patch-label">
            <span>AI-suggested remediation patch</span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button className="cs-icon-btn" onClick={handleCopy}>
                <Copy size={12} /> Copy
              </button>
              {finding.id && (
                <button className="cs-icon-btn" onClick={(e) => { e.stopPropagation(); onExport(finding.id); }}>
                  <Download size={12} /> Export JSON
                </button>
              )}
            </div>
          </div>
          <pre className="cs-patch-code"><code>{finding.aiSuggestedPatch}</code></pre>
        </div>
      )}
    </div>
  );
}

function EmptyState({ icon, title, hint }) {
  return (
    <div className="cs-empty">
      <div className="cs-empty-icon">{icon}</div>
      <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}>{title}</div>
      <div>{hint}</div>
    </div>
  );
}

// Total pipeline: [clone, walk tree, ...4 tools, generate patches]
const TOTAL_STEPS = PRE_STEPS.length + SCAN_TOOLS.length + POST_STEPS.length;
const TOOLS_START = PRE_STEPS.length;
const TOOLS_END = PRE_STEPS.length + SCAN_TOOLS.length; // exclusive
const POST_START = TOOLS_END;

function LogLine({ label, state }) {
  return (
    <div className={`cs-log-line ${state}`}>
      <span className="cs-log-check">
        {state === 'done' && <Check size={12} />}
        {state === 'active' && <Loader2 size={12} className="animate-spin" />}
      </span>
      {label}...
    </div>
  );
}

// The scan terminal: classic checklist lines for clone/walk-tree, a
// tool-by-tool matrix in the middle (gitleaks -> semgrep -> trivy ->
// checkov), then a closing "generating patches" line — all driven off
// one linear step counter so the whole thing reads as one pipeline.
function ScanTerminal({ overallStep, filesScanned, repoUrl }) {
  const toolIndex = Math.min(Math.max(overallStep - TOOLS_START, 0), SCAN_TOOLS.length);

  return (
    <div className="cs-terminal">
      <div className="cs-terminal-topbar">
        <span className="cs-terminal-dot cs-dot-r" />
        <span className="cs-terminal-dot cs-dot-y" />
        <span className="cs-terminal-dot cs-dot-g" />
        <span className="cs-terminal-path">cloudshield --target {repoUrl || 'repository'}</span>
      </div>

      <div className="cs-terminal-log">
        {PRE_STEPS.map((label, i) => (
          <LogLine
            key={label}
            label={label}
            state={overallStep > i ? 'done' : overallStep === i ? 'active' : 'pending'}
          />
        ))}
      </div>

      {overallStep >= TOOLS_START && (
        <div className="cs-terminal-body">
          {SCAN_TOOLS.map((tool, i) => {
            const state = i < toolIndex ? 'done' : i === toolIndex && overallStep < TOOLS_END ? 'running' : overallStep >= TOOLS_END ? 'done' : 'pending';
            const Icon = tool.icon;
            return (
              <div key={tool.id} className={`cs-tool-row cs-tool-row--${state}`}>
                <span
                  className="cs-tool-icon"
                  style={{
                    color: state === 'pending' ? 'var(--text-dim)' : `var(${tool.accentVar})`,
                    borderColor: state === 'pending' ? 'var(--border)' : `var(${tool.accentVar})`,
                    boxShadow: state === 'running' ? `0 0 0 3px var(${tool.accentVar}-glow)` : 'none',
                  }}
                >
                  <Icon size={13} />
                </span>

                <div className="cs-tool-text">
                  <span className="cs-tool-name">{tool.name}</span>
                  <span className="cs-tool-task">{tool.task}</span>
                </div>

                <span className="cs-tool-status">
                  {state === 'done' && (
                    <span className="cs-tool-check" style={{ color: `var(${tool.accentVar})` }}>
                      <Check size={13} /> done
                    </span>
                  )}
                  {state === 'running' && (
                    <span className="cs-tool-running" style={{ color: `var(${tool.accentVar})` }}>
                      <Loader2 size={12} className="animate-spin" /> running
                    </span>
                  )}
                  {state === 'pending' && <span className="cs-tool-pending">queued</span>}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {overallStep >= TOOLS_END && (
        <div className="cs-terminal-log cs-terminal-log--post">
          {POST_STEPS.map((label, i) => (
            <LogLine
              key={label}
              label={label}
              state={overallStep > POST_START + i ? 'done' : overallStep === POST_START + i ? 'active' : 'pending'}
            />
          ))}
        </div>
      )}

      <div className="cs-terminal-footer">
        <span className="cs-terminal-caret" />
        {filesScanned} files analyzed
      </div>
    </div>
  );
}

// Weighted 0-100 health score from the severity mix, mapped to a letter
// grade. Purely a summarizing device — it does not affect the findings.
function computeHealthScore(findings) {
  const penalty = countSeverity(findings, 'CRITICAL') * 18
    + countSeverity(findings, 'HIGH') * 9
    + countSeverity(findings, 'MEDIUM') * 4
    + countSeverity(findings, 'LOW') * 1.5;
  const score = Math.max(4, Math.round(100 - penalty));
  let grade = 'A';
  let colorVar = '--medium';
  if (score < 50) { grade = 'F'; colorVar = '--critical'; }
  else if (score < 65) { grade = 'D'; colorVar = '--critical'; }
  else if (score < 78) { grade = 'C'; colorVar = '--high'; }
  else if (score < 90) { grade = 'B'; colorVar = '--medium'; }
  return { score, grade, colorVar };
}

function HealthScoreCard({ findings }) {
  const { score, grade, colorVar } = computeHealthScore(findings);
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let raf;
    const start = performance.now();
    const duration = 700;
    const tick = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      setDisplay(Math.round(score * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [score]);

  return (
    <div className="cs-health-card">
      <div
        className="cs-health-ring"
        style={{ '--pct': display, '--ring-color': `var(${colorVar})` }}
      >
        <span className="cs-health-grade" style={{ color: `var(${colorVar})` }}>{grade}</span>
      </div>
      <div className="cs-health-text">
        <div className="cs-health-label">Repo health score</div>
        <div className="cs-health-value" style={{ color: `var(${colorVar})` }}>{display}<span>/100</span></div>
      </div>
    </div>
  );
}

// Cmd/Ctrl+K command palette for quick actions.
function CommandPalette({ open, onClose, actions }) {
  const [query, setQuery] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  if (!open) return null;

  const filtered = actions.filter((a) => a.label.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="cs-modal-overlay" onClick={onClose}>
      <div className="cs-palette" onClick={(e) => e.stopPropagation()}>
        <div className="cs-palette-search">
          <Search size={15} />
          <input
            ref={inputRef}
            className="cs-palette-input"
            placeholder="Type a command..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <span className="cs-palette-esc">esc</span>
        </div>
        <div className="cs-palette-list">
          {filtered.length === 0 && <div className="cs-palette-empty">No matching commands</div>}
          {filtered.map((a) => (
            <button
              key={a.label}
              className="cs-palette-item"
              onClick={() => { a.action(); onClose(); }}
            >
              <a.icon size={14} />
              {a.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [view, setView] = useState('scan');
  const [historyData, setHistoryData] = useState([]);
  const [overallStep, setOverallStep] = useState(0);
  const [filesScanned, setFilesScanned] = useState(0);
  const [activeSeverity, setActiveSeverity] = useState('ALL');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toasts, setToasts] = useState([]);
  const stepTimer = useRef(null);
  const filesTimer = useRef(null);
  const repoInputRef = useRef(null);

  const pushToast = (message) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, message }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200);
  };

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setScanResult(null);
    setActiveSeverity('ALL');
    setOverallStep(0);
    setFilesScanned(0);

    // Advances clone -> walk tree -> each tool -> generate patches.
    // Holds on the last step (spinner stays up) until the request resolves.
    stepTimer.current = setInterval(() => {
      setOverallStep((i) => Math.min(i + 1, TOTAL_STEPS - 1));
    }, 850);

    filesTimer.current = setInterval(() => {
      setFilesScanned((n) => n + Math.ceil(Math.random() * 9));
    }, 140);

    try {
      const response = await axios.post('http://localhost:8080/start', { repoUrl });
      setScanResult(response.data);
    } catch (err) {
      pushToast('Scan failed to run. Check the backend logs.');
    } finally {
      clearInterval(stepTimer.current);
      clearInterval(filesTimer.current);
      setOverallStep(TOTAL_STEPS);
      setLoading(false);
    }
  };

  const fetchHistory = async () => {
    try {
      const response = await axios.get('http://localhost:8080/history');
      setHistoryData(response.data.findings || []);
    } catch (err) {
      pushToast('Could not load scan history.');
    }
  };

  const handleClearHistory = async () => {
    setConfirmOpen(false);
    try {
      await axios.delete('http://localhost:8080/history/clear');
      setHistoryData([]);
      pushToast('Scan history cleared.');
    } catch (err) {
      pushToast('Failed to clear history.');
    }
  };

  const handleExport = (id) => {
    window.open(`http://localhost:8080/export/${id}`, '_blank');
  };

  useEffect(() => {
    if (view === 'history') fetchHistory();
    return () => {
      clearInterval(stepTimer.current);
      clearInterval(filesTimer.current);
    };
  }, [view]);

  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const paletteActions = [
    { label: 'New scan', icon: PlusCircle, action: () => { setView('scan'); setTimeout(() => repoInputRef.current?.focus(), 0); } },
    { label: 'View scan history', icon: History, action: () => setView('history') },
    ...(historyData.length > 0 ? [{ label: 'Clear scan history', icon: Trash2, action: () => setConfirmOpen(true) }] : []),
  ];

  const activeFindings = view === 'scan' ? (scanResult?.findings || []) : historyData;
  const visibleFindings = activeSeverity === 'ALL'
    ? activeFindings
    : activeFindings.filter((f) => f.severity === activeSeverity);
  const maxSeverityCount = Math.max(1, ...SEVERITY_ORDER.map((s) => countSeverity(activeFindings, s)));

  return (
    <div className="cs-app">
      <div className="cs-grid-overlay" aria-hidden="true" />

      <aside className="cs-sidebar">
        <div className="cs-brand">
          <div className={`cs-brand-mark ${loading ? 'cs-brand-mark--active' : ''}`}><ShieldAlert size={18} /></div>
          <div className="cs-brand-text">
            <h1>CloudShield</h1>
            <span>DevSecOps Orchestrator</span>
          </div>
        </div>

        <div className="cs-status">
          <span className={`cs-status-dot ${loading ? 'cs-status-dot--busy' : ''}`} />
          {loading ? 'Scan in progress' : 'Scanner online'}
        </div>

        <nav className="cs-nav">
          <button
            className={`cs-nav-item ${view === 'scan' ? 'active' : ''}`}
            onClick={() => setView('scan')}
          >
            <PlusCircle size={16} /> New scan
          </button>
          <button
            className={`cs-nav-item ${view === 'history' ? 'active' : ''}`}
            onClick={() => setView('history')}
          >
            <History size={16} /> Scan history
            {historyData.length > 0 && <span className="cs-nav-count">{historyData.length}</span>}
          </button>
        </nav>

        <div className="cs-sidebar-tools">
          <div className="cs-sidebar-tools-label">Toolchain</div>
          {SCAN_TOOLS.map((tool) => {
            const Icon = tool.icon;
            return (
              <div key={tool.id} className="cs-sidebar-tool">
                <span className="cs-sidebar-tool-dot" style={{ background: `var(${tool.accentVar})` }} />
                <Icon size={12} />
                {tool.name}
              </div>
            );
          })}
        </div>

        <button className="cs-cmdk-hint" onClick={() => setPaletteOpen(true)}>
          <Command size={12} /> Quick actions <span className="cs-cmdk-key">⌘K</span>
        </button>

        <div className="cs-sidebar-foot">
          Findings are generated by static analysis rules plus an AI remediation pass. Review every patch before merging.
        </div>
      </aside>

      <main className="cs-main">
        {view === 'scan' && (
          <>
            <div className="cs-header">
              <h2>Run a repository scan</h2>
              <p>Point CloudShield at a public GitHub repository to surface vulnerabilities and get AI-drafted fixes.</p>
            </div>

            <div className="cs-scan-panel">
              <form className="cs-scan-form" onSubmit={handleScan}>
                <input
                  ref={repoInputRef}
                  type="text"
                  placeholder="github.com/org/repository"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="cs-input"
                  required
                  disabled={loading}
                />
                <button type="submit" className="cs-run-btn" disabled={loading}>
                  {loading ? <Loader2 size={16} className="animate-spin" /> : <Radar size={16} />}
                  {loading ? 'Scanning' : 'Run scan'}
                </button>
              </form>

              {loading && (
                <div className="cs-scan-progress">
                  <div className="cs-beam-track"><div className="cs-beam" /></div>
                  <ScanTerminal overallStep={overallStep} filesScanned={filesScanned} repoUrl={repoUrl} />
                </div>
              )}
            </div>

            {scanResult && (
              <>
                <div className="cs-stats-row cs-stats-row--with-health">
                  <HealthScoreCard findings={scanResult.findings} />
                  <StatCard label="Total findings" value={scanResult.findingsCount ?? scanResult.findings.length} color="var(--text-primary)" max={maxSeverityCount} />
                  <StatCard label="Critical" value={countSeverity(scanResult.findings, 'CRITICAL')} color="var(--critical)" max={maxSeverityCount} />
                  <StatCard label="High" value={countSeverity(scanResult.findings, 'HIGH')} color="var(--high)" max={maxSeverityCount} />
                  <StatCard label="Medium" value={countSeverity(scanResult.findings, 'MEDIUM')} color="var(--medium)" max={maxSeverityCount} />
                </div>

                <FindingsSection
                  findings={scanResult.findings}
                  visibleFindings={visibleFindings}
                  activeSeverity={activeSeverity}
                  setActiveSeverity={setActiveSeverity}
                  onExport={handleExport}
                  onCopied={() => pushToast('Patch copied to clipboard.')}
                  emptyIcon={<ShieldAlert size={28} />}
                  emptyTitle="No findings for this filter"
                  emptyHint="Try a different severity, or clear the filter."
                />
              </>
            )}

            {!loading && !scanResult && (
              <EmptyState
                icon={<GitBranch size={28} />}
                title="No scan running yet"
                hint="Paste a repository URL above and run a scan to see results here."
              />
            )}
          </>
        )}

        {view === 'history' && (
          <>
            <div className="cs-view-head">
              <div className="cs-header" style={{ marginBottom: 0 }}>
                <h2>Scan history</h2>
                <p>{historyData.length} past finding{historyData.length === 1 ? '' : 's'} stored.</p>
              </div>
              {historyData.length > 0 && (
                <button className="cs-danger-btn" onClick={() => setConfirmOpen(true)}>
                  <Trash2 size={14} /> Clear history
                </button>
              )}
            </div>

            {historyData.length === 0 ? (
              <EmptyState
                icon={<History size={28} />}
                title="No past scans found"
                hint="Findings from previous scans will show up here."
              />
            ) : (
              <FindingsSection
                findings={historyData}
                visibleFindings={visibleFindings}
                activeSeverity={activeSeverity}
                setActiveSeverity={setActiveSeverity}
                onExport={handleExport}
                onCopied={() => pushToast('Patch copied to clipboard.')}
                emptyIcon={<ShieldAlert size={28} />}
                emptyTitle="No findings for this filter"
                emptyHint="Try a different severity, or clear the filter."
              />
            )}
          </>
        )}
      </main>

      {confirmOpen && (
        <div className="cs-modal-overlay" onClick={() => setConfirmOpen(false)}>
          <div className="cs-modal" onClick={(e) => e.stopPropagation()}>
            <AlertTriangle size={20} color="var(--critical)" />
            <h4>Clear all scan history?</h4>
            <p>This permanently deletes every stored finding from the database. This can't be undone.</p>
            <div className="cs-modal-actions">
              <button className="cs-btn-ghost" onClick={() => setConfirmOpen(false)}>Cancel</button>
              <button className="cs-btn-danger" onClick={handleClearHistory}>Delete everything</button>
            </div>
          </div>
        </div>
      )}

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} actions={paletteActions} />

      <div className="cs-toast-stack">
        {toasts.map((t) => (
          <div key={t.id} className="cs-toast">
            <AlertTriangle size={14} color="var(--critical)" />
            {t.message}
            <button
              className="cs-icon-btn"
              style={{ marginLeft: 'auto', padding: '3px' }}
              onClick={() => setToasts((ts) => ts.filter((x) => x.id !== t.id))}
            >
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsSection({ findings, visibleFindings, activeSeverity, setActiveSeverity, onExport, onCopied, emptyIcon, emptyTitle, emptyHint }) {
  return (
    <>
      <div className="cs-filter-row">
        <button className={`cs-chip ${activeSeverity === 'ALL' ? 'active' : ''}`} onClick={() => setActiveSeverity('ALL')}>
          All ({findings.length})
        </button>
        {SEVERITY_ORDER.map((sev) => {
          const count = countSeverity(findings, sev);
          if (count === 0) return null;
          return (
            <button
              key={sev}
              className={`cs-chip ${activeSeverity === sev ? 'active' : ''}`}
              onClick={() => setActiveSeverity(sev)}
            >
              {sev} ({count})
            </button>
          );
        })}
      </div>

      {visibleFindings.length === 0 ? (
        <EmptyState icon={emptyIcon} title={emptyTitle} hint={emptyHint} />
      ) : (
        <div className="cs-findings-list">
          {visibleFindings.map((f, i) => (
            <FindingCard key={f.id ?? i} finding={f} index={i} onExport={onExport} onCopied={onCopied} />
          ))}
        </div>
      )}
    </>
  );
}
