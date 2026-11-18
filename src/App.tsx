import { useCallback, useEffect, useMemo, useState } from 'react';
import { redactText, type RedactionResult } from './lib/redact';
import {
  cloudTriage,
  detectNanoAvailability,
  semanticSweep,
  type EngineBadge,
  type HybridMode,
  type RequestLogEntry,
  type SweepResult,
  type TriageResult,
} from './lib/hybrid';
import {
  ensureAnonymousAuth,
  getFirebase,
  isFirebaseConfigured,
  refreshRemoteConfig,
  signInWithGoogle,
  REMOTE_CONFIG_DEFAULTS,
  type RemoteConfigValues,
} from './lib/firebase';
import {
  deleteReport,
  listReports,
  saveReport,
  type SavedReport,
} from './lib/store';
import { downloadText, reportToMarkdown } from './lib/exporter';
import { SAMPLE_PASTES } from './lib/samples';

type NanoStatus = 'available' | 'unavailable' | 'unknown' | 'checking';

const MODE_LABELS: Record<HybridMode, string> = {
  'prefer-on-device': 'Prefer on-device',
  'only-on-device': 'Only on-device',
  'prefer-in-cloud': 'Prefer cloud',
  'only-in-cloud': 'Only in cloud',
};

function Badge({ badge }: { badge: EngineBadge }) {
  const cls =
    badge.engine === 'on-device'
      ? 'badge on-device'
      : badge.engine === 'cloud'
        ? 'badge cloud'
        : badge.engine === 'mock'
          ? 'badge mock'
          : 'badge local';
  const label =
    badge.engine === 'on-device'
      ? 'On-device'
      : badge.engine === 'cloud'
        ? 'Cloud'
        : badge.engine === 'mock'
          ? 'Mock'
          : 'Local';
  return (
    <span className={cls} title={badge.note ?? badge.model}>
      {label} · {badge.model} · {badge.latencyMs} ms · {badge.cost}
    </span>
  );
}

function SeverityChip({ severity }: { severity: string }) {
  return <span className={`severity ${severity}`}>{severity.toUpperCase()}</span>;
}

export default function App() {
  const demoMode = !isFirebaseConfigured();
  const [input, setInput] = useState('');
  const [mode, setMode] = useState<HybridMode>('prefer-on-device');
  const [nano, setNano] = useState<NanoStatus>('checking');
  const [redaction, setRedaction] = useState<RedactionResult | null>(null);
  const [sweep, setSweep] = useState<SweepResult | null>(null);
  const [sweepWarning, setSweepWarning] = useState(false);
  const [approved, setApproved] = useState(false);
  const [triage, setTriage] = useState<TriageResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [log, setLog] = useState<RequestLogEntry[]>([]);
  const [history, setHistory] = useState<SavedReport[]>([]);
  const [uid, setUid] = useState<string | null>(null);
  const [values, setValues] = useState<RemoteConfigValues>(REMOTE_CONFIG_DEFAULTS);
  const [selectedReport, setSelectedReport] = useState<SavedReport | null>(null);

  const pushLog = useCallback((entry: Omit<RequestLogEntry, 'id' | 'at'>) => {
    setLog((prev) => [
      {
        ...entry,
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        at: new Date().toISOString().slice(11, 19),
      },
      ...prev,
    ]);
  }, []);

  useEffect(() => {
    detectNanoAvailability().then((s) => setNano(s));
    refreshRemoteConfig().then(setValues).catch(() => undefined);
    ensureAnonymousAuth()
      .then((user) => {
        setUid(user?.uid ?? null);
        return listReports(user?.uid ?? null);
      })
      .then(setHistory)
      .catch(() => setHistory([]));
    // Log the privacy guarantee up front: nothing has left the device yet.
    pushLog({
      step: 'App opened',
      engine: 'local',
      bytesSent: 0,
      detail: 'No data has left this device. Paste stays local until you approve the redacted text.',
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const refreshHistory = useCallback(async () => {
    setHistory(await listReports(uid));
  }, [uid]);

  async function handleRedact() {
    setError(null);
    setTriage(null);
    setApproved(false);
    setSweep(null);
    setSweepWarning(false);
    if (!input.trim()) {
      setError('Paste some text first.');
      return;
    }
    const result = redactText(input);
    setRedaction(result);
    pushLog({
      step: 'Deterministic redaction',
      engine: 'local',
      bytesSent: 0,
      detail: `${result.redactedCount} secret(s) redacted locally. 0 bytes sent.`,
    });

    // Stage 1 — semantic sweep, on-device first.
    if (nano === 'available') {
      setBusy('sweep');
      try {
        const s = await semanticSweep(input, result.redactedCount, mode, values);
        setSweep(s);
        pushLog({
          step: 'Semantic sweep',
          engine: s.badge.engine,
          bytesSent: s.badge.engine === 'on-device' ? 0 : new Blob([input]).size,
          detail: s.summary,
        });
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Semantic sweep failed.');
      } finally {
        setBusy(null);
      }
    } else if (mode === 'only-on-device') {
      setError(
        'On-device model (Gemini Nano) is not available in this browser, and the mode is "Only on-device". Switch to "Prefer on-device" to allow a cloud fallback, or keep the deterministic redaction only.',
      );
    } else if (nano === 'unavailable' || nano === 'unknown') {
      // Fail closed: the sweep would send the ORIGINAL text to the cloud.
      // Ask first — never silently upload unredacted text.
      setSweepWarning(true);
    }
  }

  async function handleSweepCloudFallback() {
    if (!redaction) return;
    setSweepWarning(false);
    setBusy('sweep');
    setError(null);
    try {
      const s = await semanticSweep(input, redaction.redactedCount, mode, values);
      setSweep(s);
      pushLog({
        step: 'Semantic sweep (cloud fallback, user-approved)',
        engine: s.badge.engine,
        bytesSent: new Blob([input]).size,
        detail: s.summary,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Semantic sweep failed.');
    } finally {
      setBusy(null);
    }
  }

  async function handleTriage() {
    if (!redaction) return;
    setBusy('triage');
    setError(null);
    try {
      const t = await cloudTriage(redaction.redactedText, values);
      setTriage(t);
      pushLog({
        step: 'Cloud triage',
        engine: t.badge.engine,
        bytesSent: new Blob([redaction.redactedText]).size,
        detail: `Severity ${t.severity} · ${t.category}. Sent REDACTED text only.`,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Cloud triage failed.');
    } finally {
      setBusy(null);
    }
  }

  async function handleSave() {
    if (!redaction) return;
    setBusy('save');
    try {
      const saved = await saveReport(uid, {
        redactedText: redaction.redactedText,
        findings: redaction.findings,
        triage,
        mode,
      });
      pushLog({
        step: 'Report saved',
        engine: getFirebase() ? 'cloud' : 'local',
        bytesSent: 0,
        detail: getFirebase()
          ? `Saved to Firestore (redacted text only), id ${saved.id}.`
          : 'Saved to this browser only (demo mode, localStorage).',
      });
      await refreshHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed.');
    } finally {
      setBusy(null);
    }
  }

  async function handleDelete(id: string) {
    await deleteReport(uid, id);
    setSelectedReport(null);
    await refreshHistory();
  }

  const canTriage = redaction !== null && approved && !busy;
  const totalBytesSent = useMemo(
    () => log.reduce((sum, e) => sum + e.bytesSent, 0),
    [log],
  );

  return (
    <div className="app">
      <header>
        <div>
          <h1>PasteSafe</h1>
          <p className="tagline">
            The clipboard that redacts itself before AI sees it.
          </p>
        </div>
        <div className="header-badges">
          {demoMode ? (
            <span className="badge mock" title="Set VITE_FIREBASE_* env vars to connect a Firebase project.">
              Demo mode — no Firebase connected
            </span>
          ) : (
            <span className="badge cloud" title="Firebase AI Logic is configured.">
              Firebase connected
            </span>
          )}
          <span
            className={`badge ${nano === 'available' ? 'on-device' : 'local'}`}
            title="Gemini Nano availability in this browser (Chrome Prompt API)."
          >
            Nano: {nano}
          </span>
          {uid ? (
            <span className="badge local" title={`Anonymous user ${uid}`}>
              Signed in anonymously
            </span>
          ) : (
            <button
              className="btn small"
              disabled={demoMode}
              onClick={() => signInWithGoogle().then((u) => setUid(u?.uid ?? null))}
            >
              Sign in with Google
            </button>
          )}
        </div>
      </header>

      <section className="modebar">
        <label>
          Inference mode
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as HybridMode)}
          >
            {(Object.keys(MODE_LABELS) as HybridMode[]).map((m) => (
              <option key={m} value={m}>
                {MODE_LABELS[m]}
              </option>
            ))}
          </select>
        </label>
        <p className="mode-note">
          On-device first: the privacy sweep runs on Gemini Nano when available.
          The cloud only ever sees <strong>redacted</strong> text — and only
          after you approve it.
        </p>
      </section>

      {error && <div className="error" role="alert">{error}</div>}

      <main>
        <section className="card">
          <h2>1 · Paste</h2>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste a log, a bug report, a chat transcript… PasteSafe redacts secrets on this device before anything is analyzed."
            rows={12}
            spellCheck={false}
          />
          <div className="row">
            <button
              className="btn primary"
              onClick={handleRedact}
              disabled={!input.trim() || busy !== null}
            >
              {busy === 'sweep' ? 'Scanning…' : 'Redact on-device'}
            </button>
            <button className="btn" onClick={() => { setInput(''); setRedaction(null); setSweep(null); setTriage(null); setApproved(false); }}>
              Clear
            </button>
            <span className="samples">
              Try a sample:{' '}
              {SAMPLE_PASTES.map((s) => (
                <button
                  key={s.id}
                  className="link"
                  onClick={() => {
                    setInput(s.body);
                    setRedaction(null);
                    setSweep(null);
                    setTriage(null);
                    setApproved(false);
                  }}
                >
                  {s.title}
                </button>
              ))}
            </span>
          </div>

          {redaction && (
            <>
              <h3>
                Deterministic scan — {redaction.redactedCount} finding
                {redaction.redactedCount === 1 ? '' : 's'} ·{' '}
                {redaction.durationMs.toFixed(1)} ms
              </h3>
              <Badge
                badge={{
                  engine: 'local',
                  model: 'Local regex engine',
                  latencyMs: Math.round(redaction.durationMs),
                  cost: '$0 · offline',
                  note: 'Ran in this browser. 0 bytes sent.',
                }}
              />
              {redaction.findings.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Severity</th>
                      <th>Value (masked)</th>
                      <th>Placeholder</th>
                    </tr>
                  </thead>
                  <tbody>
                    {redaction.findings.map((f) => (
                      <tr key={f.id}>
                        <td>{f.label}</td>
                        <td><SeverityChip severity={f.severity} /></td>
                        <td><code>{f.masked}</code></td>
                        <td><code>{f.placeholder}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="muted">No secrets detected by the deterministic scan.</p>
              )}
            </>
          )}

          {sweepWarning && (
            <div className="warning" role="alert">
              <strong>On-device model unavailable.</strong> The semantic sweep
              would fall back to the cloud — and the cloud would receive your{' '}
              <strong>original, unredacted</strong> text. The deterministic
              redaction above is already done and safe.
              <div className="row">
                <button className="btn" onClick={handleSweepCloudFallback}>
                  Run sweep in cloud anyway
                </button>
                <button className="btn" onClick={() => setSweepWarning(false)}>
                  Skip sweep
                </button>
              </div>
            </div>
          )}

          {sweep && (
            <>
              <h3>Semantic sweep</h3>
              <Badge badge={sweep.badge} />
              <p>{sweep.summary}</p>
              <p>
                Risk level: <SeverityChip severity={sweep.riskLevel} />
              </p>
              {sweep.findings.length > 0 && (
                <ul>
                  {sweep.findings.map((f, i) => (
                    <li key={i}>
                      <strong>{f.type}</strong> — “{f.excerpt}” (
                      {(f.confidence * 100).toFixed(0)}%)
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </section>

        <section className="card">
          <h2>2 · Review the redacted text</h2>
          {redaction ? (
            <>
              <pre className="redacted">{redaction.redactedText}</pre>
              <label className="approve">
                <input
                  type="checkbox"
                  checked={approved}
                  onChange={(e) => setApproved(e.target.checked)}
                />{' '}
                I reviewed the redacted text. It is safe to send to the cloud
                for triage.
              </label>
              <div className="row">
                <button
                  className="btn primary"
                  onClick={handleTriage}
                  disabled={!canTriage}
                >
                  {busy === 'triage' ? 'Analyzing…' : 'Analyze in cloud'}
                </button>
                <button
                  className="btn"
                  onClick={() => {
                    navigator.clipboard?.writeText(redaction.redactedText);
                  }}
                >
                  Copy redacted text
                </button>
              </div>
            </>
          ) : (
            <p className="muted">
              Run the redaction first. Nothing is sent anywhere until you
              approve the redacted text.
            </p>
          )}

          {triage && (
            <>
              <h2>3 · Triage</h2>
              <Badge badge={triage.badge} />
              <h3>
                {triage.title} <SeverityChip severity={triage.severity} />
              </h3>
              <p>
                <strong>Category:</strong> {triage.category}
              </p>
              <p>
                <strong>CVSS:</strong>{' '}
                <code>{triage.cvssVector}</code> ({triage.cvssScore.toFixed(1)}
                )
              </p>
              <p>{triage.summary}</p>
              {triage.remediation.length > 0 && (
                <>
                  <h4>Remediation</h4>
                  <ol>
                    {triage.remediation.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </>
              )}
              <div className="row">
                <button
                  className="btn primary"
                  onClick={handleSave}
                  disabled={busy !== null}
                >
                  {busy === 'save' ? 'Saving…' : 'Save report'}
                </button>
                <button
                  className="btn"
                  onClick={() => {
                    if (!redaction) return;
                    downloadText(
                      `pastesafe-report-${new Date().toISOString().slice(0, 10)}.md`,
                      reportToMarkdown({
                        id: 'export',
                        createdAt: Date.now(),
                        redactedText: redaction.redactedText,
                        findings: redaction.findings,
                        triage,
                        mode,
                      }),
                    );
                  }}
                >
                  Export Markdown
                </button>
              </div>
            </>
          )}
        </section>
      </main>

      <section className="card">
        <h2>History {demoMode && <span className="muted">(this browser only)</span>}</h2>
        {history.length === 0 ? (
          <p className="muted">No saved reports yet.</p>
        ) : (
          <ul className="history">
            {history.map((r) => (
              <li key={r.id}>
                <button className="link" onClick={() => setSelectedReport(r)}>
                  {r.triage?.title ?? 'Untitled finding'} —{' '}
                  {r.triage ? r.triage.severity : 'not triaged'} —{' '}
                  {new Date(r.createdAt).toLocaleString()}
                </button>{' '}
                <button
                  className="link danger"
                  onClick={() => handleDelete(r.id)}
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        )}
        {selectedReport && (
          <div>
            <h3>{selectedReport.triage?.title ?? 'Saved report'}</h3>
            <pre className="redacted">{selectedReport.redactedText}</pre>
            <button
              className="btn"
              onClick={() =>
                downloadText(
                  `pastesafe-report-${selectedReport.id}.md`,
                  reportToMarkdown(selectedReport),
                )
              }
            >
              Export Markdown
            </button>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Request log — proof nothing leaked</h2>
        <p className="muted">
          Total bytes sent so far: <strong>{totalBytesSent}</strong>. Before
          redaction the total was always 0.
        </p>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Step</th>
              <th>Engine</th>
              <th>Bytes sent</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {log.map((e) => (
              <tr key={e.id}>
                <td>{e.at}</td>
                <td>{e.step}</td>
                <td>{e.engine}</td>
                <td>{e.bytesSent}</td>
                <td>{e.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <footer>
        <p>
          PasteSafe — #BuildHybridAI 2026. On-device first: Gemini Nano via
          Firebase AI Logic hybrid inference, cloud fallback only for redacted
          text. Secrets are redacted on this device before any AI sees them.{' '}
          <a href="https://github.com/naplex666/pastesafe">GitHub</a>
        </p>
      </footer>
    </div>
  );
}
