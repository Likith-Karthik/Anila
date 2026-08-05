import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Download,
  FileJson,
  Loader2,
  Play,
  ShieldCheck,
  Square,
  Terminal,
  Upload
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { Defaults, Finding, Observation, Report, ScanInput, ScanOutput, Severity, TargetResult } from "./types";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

const initialForm: ScanInput = {
  targets: "127.0.0.1",
  port: 22,
  ip_preference: "any",
  target_timeout: "10s",
  connection_timeout: "4s",
  concurrency: 10,
  per_host_connections: 3,
  rate_limit: 5,
  maximum_targets: 256,
  audit_user: "sshscope-audit",
  auth_probe_enabled: true,
  known_hosts_path: "",
  policy_path: "",
  failure_threshold: "high",
  scope_reference: "",
  operator_confirmed: false
};

export default function App() {
  const [form, setForm] = useState<ScanInput>(initialForm);
  const [report, setReport] = useState<Report | null>(null);
  const [selected, setSelected] = useState(0);
  const [tab, setTab] = useState<"findings" | "evidence" | "errors" | "json">("findings");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetch("/api/defaults")
      .then((response) => response.json() as Promise<Defaults>)
      .then(({ config }) =>
        setForm((current) => ({
          ...current,
          port: config.port,
          target_timeout: config.target_timeout,
          connection_timeout: config.connection_timeout,
          concurrency: config.concurrency,
          per_host_connections: config.per_host_connections,
          rate_limit: config.rate_limit,
          maximum_targets: config.maximum_targets,
          ip_preference: config.ip_preference,
          auth_probe_enabled: config.auth_probe_enabled,
          audit_user: config.audit_user,
          failure_threshold: config.failure_threshold
        }))
      )
      .catch(() => setMessage("Could not load server defaults."));
  }, []);

  const targetCount = useMemo(() => targetLines(form.targets).length, [form.targets]);
  const selectedTarget = report?.targets[selected] ?? null;
  const totals = useMemo(() => summarize(report), [report]);
  const canScan = targetCount > 0 && form.operator_confirmed && !busy;

  async function startScan() {
    setBusy(true);
    setMessage("");
    setReport(null);
    setSelected(0);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form)
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error ?? "scan failed");
      }
      setReport((body as ScanOutput).report);
      setMessage("Scan complete.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan failed.");
    } finally {
      setBusy(false);
    }
  }

  async function cancelScan() {
    await fetch("/api/cancel", { method: "POST" });
    setMessage("Cancellation requested.");
  }

  function loadReport(file: File | null) {
    if (!file) return;
    file
      .text()
      .then((text) => {
        const parsed = JSON.parse(text) as Report;
        setReport(parsed);
        setSelected(0);
        setMessage("Report loaded.");
      })
      .catch(() => setMessage("Could not load that JSON report."));
  }

  function downloadReport() {
    if (!report) return;
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `sshscope-${new Date().toISOString().replaceAll(":", "-")}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={22} />
          <div>
            <h1>sshscope</h1>
            <p>Defensive SSH assessment</p>
          </div>
        </div>
        <nav>
          <button className="nav-item active">
            <Terminal size={17} /> Scanner
          </button>
          <label className="nav-item file">
            <Upload size={17} /> Open report
            <input type="file" accept="application/json,.json" onChange={(event) => loadReport(event.target.files?.[0] ?? null)} />
          </label>
        </nav>
        <div className="status-strip">
          <span>Targets</span>
          <strong>{targetCount}</strong>
        </div>
      </aside>

      <section className="scan-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Authorized scope</p>
            <h2>New scan</h2>
          </div>
          <div className={`pill ${form.operator_confirmed ? "ok" : "warn"}`}>
            {form.operator_confirmed ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
            {form.operator_confirmed ? "confirmed" : "required"}
          </div>
        </div>

        <label className="field tall">
          <span>Targets</span>
          <textarea
            value={form.targets}
            spellCheck={false}
            onChange={(event) => setForm({ ...form, targets: event.target.value })}
          />
        </label>

        <div className="grid two">
          <NumberField label="Port" value={form.port} setValue={(port) => setForm({ ...form, port })} />
          <SelectField label="Address family" value={form.ip_preference} options={["any", "ipv4", "ipv6"]} setValue={(ip_preference) => setForm({ ...form, ip_preference })} />
        </div>

        <div className="grid two">
          <TextField label="Target timeout" value={form.target_timeout} setValue={(target_timeout) => setForm({ ...form, target_timeout })} />
          <TextField label="Connect timeout" value={form.connection_timeout} setValue={(connection_timeout) => setForm({ ...form, connection_timeout })} />
        </div>

        <div className="grid three">
          <NumberField label="Concurrency" value={form.concurrency} setValue={(concurrency) => setForm({ ...form, concurrency })} />
          <NumberField label="Per host" value={form.per_host_connections} setValue={(per_host_connections) => setForm({ ...form, per_host_connections })} />
          <NumberField label="Max targets" value={form.maximum_targets} setValue={(maximum_targets) => setForm({ ...form, maximum_targets })} />
        </div>

        <div className="grid two">
          <NumberField label="Rate/sec" value={form.rate_limit} setValue={(rate_limit) => setForm({ ...form, rate_limit })} step="0.5" />
          <SelectField label="Fail on" value={form.failure_threshold} options={["critical", "high", "medium", "never"]} setValue={(failure_threshold) => setForm({ ...form, failure_threshold })} />
        </div>

        <label className="check-row">
          <input type="checkbox" checked={form.auth_probe_enabled} onChange={(event) => setForm({ ...form, auth_probe_enabled: event.target.checked })} />
          <span>Observe authentication methods with the credentialless `none` request</span>
        </label>

        <TextField label="Audit user" value={form.audit_user} setValue={(audit_user) => setForm({ ...form, audit_user })} />
        <TextField label="Scope reference" value={form.scope_reference} setValue={(scope_reference) => setForm({ ...form, scope_reference })} />

        <label className="check-row authorization">
          <input type="checkbox" checked={form.operator_confirmed} onChange={(event) => setForm({ ...form, operator_confirmed: event.target.checked })} />
          <span>I confirm I am authorized to assess the listed SSH endpoints.</span>
        </label>

        <div className="actions">
          <button className="primary" disabled={!canScan} onClick={startScan}>
            {busy ? <Loader2 className="spin" size={17} /> : <Play size={17} />} Start assessment
          </button>
          <button className="secondary" disabled={!busy} onClick={cancelScan}>
            <Square size={15} /> Cancel
          </button>
        </div>
        {message && <p className="message">{safeText(message)}</p>}
      </section>

      <section className="report-panel">
        <div className="panel-head">
          <div>
            <p className="eyebrow">Report</p>
            <h2>{report ? report.status : "No report loaded"}</h2>
          </div>
          <button className="icon-button" disabled={!report} onClick={downloadReport} title="Download JSON">
            <Download size={18} />
          </button>
        </div>

        <div className="summary-grid">
          <Metric label="Endpoints" value={report?.targets.length ?? 0} />
          <Metric label="Critical/high" value={totals.critical + totals.high} tone={totals.critical + totals.high > 0 ? "danger" : "ok"} />
          <Metric label="Medium" value={totals.medium} tone={totals.medium > 0 ? "warn" : "ok"} />
          <Metric label="Errors" value={totals.errors} tone={totals.errors > 0 ? "warn" : "ok"} />
        </div>

        {report ? (
          <div className="workspace">
            <div className="target-list">
              {report.targets.map((target, index) => (
                <button key={`${target.target.resolved_ip}:${target.target.port}`} className={index === selected ? "target selected" : "target"} onClick={() => setSelected(index)}>
                  <span>{safeText(target.target.original)}</span>
                  <small>{safeText(target.target.resolved_ip)}:{target.target.port}</small>
                </button>
              ))}
            </div>
            <div className="detail">
              <div className="tabs">
                {(["findings", "evidence", "errors", "json"] as const).map((item) => (
                  <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>
                    {item}
                  </button>
                ))}
              </div>
              {selectedTarget && <TargetDetail target={selectedTarget} report={report} tab={tab} />}
            </div>
          </div>
        ) : (
          <div className="empty-state">
            <FileJson size={32} />
            <p>Run a scan or open a saved JSON report.</p>
          </div>
        )}
      </section>
    </main>
  );
}

function TargetDetail({ target, report, tab }: { target: TargetResult; report: Report; tab: "findings" | "evidence" | "errors" | "json" }) {
  if (tab === "json") {
    return <pre className="json-view">{safeText(JSON.stringify(target, null, 2))}</pre>;
  }
  if (tab === "errors") {
    const errors = [...report.errors, ...target.errors];
    return errors.length ? (
      <div className="stack">{errors.map((error, index) => <ErrorRow key={index} error={`${error.probe}/${error.kind}: ${error.message}`} />)}</div>
    ) : (
      <Empty label="No operational errors recorded." />
    );
  }
  if (tab === "evidence") {
    return target.observations.length ? <div className="stack">{target.observations.map((observation) => <ObservationRow key={`${observation.probe}:${observation.id}`} observation={observation} />)}</div> : <Empty label="No evidence recorded." />;
  }
  return target.findings.length ? <div className="stack">{severityOrder.flatMap((severity) => target.findings.filter((finding) => finding.severity === severity).map((finding) => <FindingRow key={finding.rule_id} finding={finding} />))}</div> : <Empty label="No findings for this target." />;
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <article className={`finding ${finding.severity}`}>
      <div>
        <span className="badge">{finding.severity}</span>
        <h3>{safeText(finding.title)}</h3>
      </div>
      <p>{safeText(finding.description)}</p>
      <small>{safeText(finding.recommendation)}</small>
      {finding.affected_values && finding.affected_values.length > 0 && <code>{safeText(finding.affected_values.join(", "))}</code>}
    </article>
  );
}

function ObservationRow({ observation }: { observation: Observation }) {
  return (
    <article className="observation">
      <div>
        <strong>{safeText(observation.id)}</strong>
        <span>{safeText(observation.probe)} · {safeText(observation.confidence)}</span>
      </div>
      <code>{safeText(renderValue(observation))}</code>
    </article>
  );
}

function ErrorRow({ error }: { error: string }) {
  return (
    <article className="error-row">
      <Ban size={17} />
      <span>{safeText(error)}</span>
    </article>
  );
}

function Empty({ label }: { label: string }) {
  return <p className="empty-line">{label}</p>;
}

function Metric({ label, value, tone = "neutral" }: { label: string; value: number; tone?: "neutral" | "ok" | "warn" | "danger" }) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TextField({ label, value, setValue }: { label: string; value: string; setValue: (value: string) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input value={value} onChange={(event) => setValue(event.target.value)} />
    </label>
  );
}

function NumberField({ label, value, setValue, step = "1" }: { label: string; value: number; step?: string; setValue: (value: number) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input type="number" min="0" step={step} value={value} onChange={(event) => setValue(Number(event.target.value))} />
    </label>
  );
}

function SelectField({ label, value, options, setValue }: { label: string; value: string; options: string[]; setValue: (value: string) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <select value={value} onChange={(event) => setValue(event.target.value)}>
        {options.map((option) => <option key={option}>{option}</option>)}
      </select>
    </label>
  );
}

function targetLines(value: string) {
  return value.split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
}

function summarize(report: Report | null) {
  const totals: Record<Severity, number> & { errors: number } = { critical: 0, high: 0, medium: 0, low: 0, info: 0, errors: 0 };
  if (!report) return totals;
  totals.errors += report.errors.length;
  for (const target of report.targets) {
    totals.errors += target.errors.length;
    for (const finding of target.findings) totals[finding.severity]++;
  }
  return totals;
}

function renderValue(observation: Observation) {
  const value = observation.value;
  if (value.boolean !== undefined) return String(value.boolean);
  if (value.string !== undefined) return value.string;
  if (value.number !== undefined) return `${value.number}${value.unit ? ` ${value.unit}` : ""}`;
  if (value.strings) return value.strings.join(", ");
  if (value.host_keys) return value.host_keys.map((key) => `${key.algorithm} ${key.fingerprint_sha256} ${key.known_hosts_status}`).join("\n");
  return JSON.stringify(value.kex_proposal ?? value);
}

function safeText(value: string) {
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, (char) => {
    const code = char.codePointAt(0)?.toString(16).padStart(4, "0") ?? "0000";
    return `\\u${code}`;
  });
}
