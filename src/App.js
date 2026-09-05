import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  ShieldAlert, Loader2, History, PlusCircle, Trash2, Download,
  Check, ChevronDown, Copy, Radar, GitBranch, X, AlertTriangle,
  KeyRound, ScanSearch, Bug, FileCog, Command, Search,
} from 'lucide-react';
import './App.css';

// Each tool that runs during a scan, in execution order. icon + accentVar
// drive the terminal row + the glow color while it runs. The "id" here must
// match the tool ids the backend sends in SSE progress events and stores on
// each SecretFinding (see SecretScannerService.java / ScanOrchestratorService.java).
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
const TOOL_BY_ID = Object.fromEntries(SCAN_TOOLS.map((t) => [t.id, t]));

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const SEVERITY_STYLE = {
  CRITICAL: { var: '--critical', bg: '--critical-bg' },
  HIGH: { var: '--high', bg: '--high-bg' },
  MEDIUM: { var: '--medium', bg: '--medium-bg' },
  LOW: { var: '--low', bg: '--low-bg' },
};

// Legacy fallback ONLY: findings scanned before the backend tagged them with
// a real `tool` field (see SecretFinding.java) won't have one. For those old
// rows, guess from the rule-name convention so old history doesn't look
// broken. Any finding from a fresh scan has finding.tool set directly by the
// backend and never touches this function.
function guessToolFromRuleName(finding) {
  const rule = (finding.ruleName || '').trim();
  const file = (finding.filePath || '').trim();

  if (/^\[?Likely test data]?\s*Secret:|^Secret:/i.test(rule)) return 'gitleaks';
  if (/^SAST:/i.test(rule)) return 'semgrep';
  if (/^SCA:/i.test(rule)) return 'trivy';
  if (/^IaC:/i.test(rule)) return 'checkov';

  if (/\.(tf|tfvars)$|\.ya?ml$|Dockerfile$|docker-compose/i.test(file)) return 'checkov';
  if (/package-lock\.json$|requirements.*\.txt$|go\.sum$|Pipfile\.lock$|Gemfile\.lock$|pom\.xml$|\.csproj$/i.test(file)) return 'trivy';

  return 'semgrep';
}

// Resolves which tool badge to show: real backend data first, legacy guess
// as a fallback for old history rows, flagged so the UI can visually
// distinguish "we know" from "we're guessing."
function resolveToolAttribution(finding) {
  if (finding.tool && TOOL_BY_ID[finding.tool]) {
    return { id: finding.tool, confidence: 'known' };
  }
  return { id: guessToolFromRuleName(finding), confidence: 'guess' };
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
  const attribution = resolveToolAttribution(finding);
  const tool = TOOL_BY_ID[attribution.id];
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
                ? 'This finding predates tool tagging, so this is inferred from the rule name, not reported directly by the backend.'
                : `Reported directly by ${tool.name}.`}
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

function LogLine({ label, state }) {
  return (
    <div className={`cs-log-line ${state}`}>
      <span className="cs-log-check">
        {state === 'done' && <Check size={12} />}
        {state === 'active' && <Loader2 size={12} className="animate-spin" />}
      </span>
      {label}
    </div>
  );
}

// The scan terminal, now driven entirely by real backend state instead of a
// simulated timer:
//   - phase: the job's current ScanJob.Status ('PENDING'|'CLONING'|'SCANNING'|'ENRICHING'|'SAVING'|'COMPLETE'|'ERROR')
//   - toolStatus: { gitleaks: 'pending'|'running'|'done', ... } built from real SSE "tool" fields
//   - liveStepLabel: the exact text the backend sent for the current step
//     (e.g. "Generating AI remediation patch (3/12)") - no fabricated counters.
function ScanTerminal({ phase, toolStatus, liveStepLabel, elapsedSeconds, repoUrl }) {
  const cloneState = phase === 'PENDING' ? 'pending' : phase === 'CLONING' ? 'active' : 'done';
  const showTools = phase !== 'PENDING' && phase !== 'CLONING';
  const showLiveLine = phase === 'ENRICHING' || phase === 'SAVING';

  return (
    <div className="cs-terminal">
      <div className="cs-terminal-topbar">
        <span className="cs-terminal-dot cs-dot-r" />
        <span className="cs-terminal-dot cs-dot-y" />
        <span className="cs-terminal-dot cs-dot-g" />
        <span className="cs-terminal-path">cloudshield --target {repoUrl || 'repository'}</span>
      </div>

      <div className="cs-terminal-log">
        <LogLine label="Cloning repository" state={cloneState} />
      </div>

      {showTools && (
        <div className="cs-terminal-body">
          {SCAN_TOOLS.map((tool) => {
            // Once we've moved past SCANNING entirely, every tool is done
            // regardless of what the last known per-tool state was.
            const state = (phase === 'ENRICHING' || phase === 'SAVING' || phase === 'COMPLETE')
              ? 'done'
              : (toolStatus[tool.id] || 'pending');
            const Icon = tool.icon;
            return (
              <div key={tool.id} className={`cs-tool-row cs-tool-row--${state === 'running' ? 'running' : state === 'done' ? 'done' : 'pending'}`}>
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

      {showLiveLine && (
        <div className="cs-terminal-log cs-terminal-log--post">
          <LogLine label={liveStepLabel} state="active" />
        </div>
      )}

      <div className="cs-terminal-footer">
        <span className="cs-terminal-caret" />
        {elapsedSeconds}s elapsed
      </div>
    </div>
  );
}

// Weighted 0-100 health score from the severity mix, mapped to a letter
// grade. Purely a summarizing device - it does not affect the findings.
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
  const [activeSeverity, setActiveSeverity] = useState('ALL');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toasts, setToasts] = useState([]);

  // Real scan state, driven by SSE events - nothing here is simulated.
  const [phase, setPhase] = useState('PENDING');
  const [toolStatus, setToolStatus] = useState({});
  const [liveStepLabel, setLiveStepLabel] = useState('');
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  const eventSourceRef = useRef(null);
  const elapsedTimerRef = useRef(null);
  const repoInputRef = useRef(null);

  const pushToast = (message) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, message }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200);
  };

  const closeStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (elapsedTimerRef.current) {
      clearInterval(elapsedTimerRef.current);
      elapsedTimerRef.current = null;
    }
  };

  const applyProgress = (data) => {
    setPhase(data.status);
    setLiveStepLabel(data.step);

    if (data.tool) {
      // Mark any previously-running tool as done, then start the new one.
      setToolStatus((prev) => {
        const next = { ...prev };
        Object.keys(next).forEach((id) => {
          if (next[id] === 'running') next[id] = 'done';
        });
        next[data.tool] = 'running';
        return next;
      });
    }
  };

  const fetchJobResult = async (jobId) => {
    try {
      const response = await axios.get(`http://localhost:8080/scan/${jobId}`);
      setScanResult(response.data);
    } catch (err) {
      pushToast('Scan finished, but results could not be loaded.');
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setScanResult(null);
    setActiveSeverity('ALL');
    setPhase('PENDING');
    setToolStatus({});
    setLiveStepLabel('');
    setElapsedSeconds(0);
    closeStream();

    const startedAt = Date.now();
    elapsedTimerRef.current = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);

    try {
      const startResponse = await axios.post('http://localhost:8080/start', { repoUrl });
      const jobId = startResponse.data.jobId;

      const es = new EventSource(`http://localhost:8080/scan/${jobId}/stream`);
      eventSourceRef.current = es;

      es.addEventListener('progress', (evt) => {
        applyProgress(JSON.parse(evt.data));
      });

      es.addEventListener('complete', () => {
        setPhase('COMPLETE');
        closeStream();
        fetchJobResult(jobId);
      });

      es.addEventListener('error', (evt) => {
        let message = 'Scan failed to run. Check the backend logs.';
        try {
          const data = JSON.parse(evt.data);
          if (data.message) message = data.message;
        } catch { /* non-JSON error frame, use default */ }
        pushToast(message);
        setPhase('ERROR');
        closeStream();
        setLoading(false);
      });

      // Underlying connection dropped unexpectedly (not a scan-level error).
      es.onerror = () => {
        if (eventSourceRef.current) {
          pushToast('Lost connection to the scan. It may still be running on the backend.');
          closeStream();
          setLoading(false);
        }
      };
    } catch (err) {
      pushToast('Scan failed to start. Check the backend logs.');
      closeStream();
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
    return () => closeStream();
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
                  <ScanTerminal
                    phase={phase}
                    toolStatus={toolStatus}
                    liveStepLabel={liveStepLabel}
                    elapsedSeconds={elapsedSeconds}
                    repoUrl={repoUrl}
                  />
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
