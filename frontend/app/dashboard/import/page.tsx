"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { importFile, type FileImport } from "@/lib/local/importer";
import { runLive } from "@/lib/local/live";
import { getTables, save, persistent, type ImportRecord } from "@/lib/local/store";
import { MAX_FLOWS } from "@/lib/local/engine";

const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH || "";
const btn = { padding: "8px 16px", fontSize: 13, background: "transparent", color: "var(--text-primary)", border: "1px solid var(--border-strong)", cursor: "pointer" } as const;

export default function ImportPage() {
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<(FileImport & { source: string }) | null>(null);
  const [history, setHistory] = useState<ImportRecord[]>([]);
  const [learningMin, setLearningMin] = useState(50);
  const [sensitivity, setSensitivity] = useState(10);
  const [stored, setStored] = useState<boolean | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [bridgeUrl, setBridgeUrl] = useState("http://127.0.0.1:8765");
  const [token, setToken] = useState("");
  const [live, setLive] = useState(false);
  const [liveInfo, setLiveInfo] = useState("");
  const liveStop = useRef(true);
  useEffect(() => () => { liveStop.current = true; }, []);   // stop polling when leaving the page

  async function startLive() {
    liveStop.current = false; setLive(true); setError(""); setResult(null); setLiveInfo("Connecting…");
    try {
      const t = await getTables();
      t.settings.learningMin = Math.max(0, Math.floor(learningMin) || 0);
      const tot = await runLive({ base: bridgeUrl, token, sensitivity, learningMin: t.settings.learningMin, isStopped: () => liveStop.current, onInfo: setLiveInfo });
      setLiveInfo(`Stopped. Saved ${tot.flows.toLocaleString()} flows (${tot.flagged} flagged), ${tot.devices} device sightings, ${tot.endpoints} endpoint rows, ${tot.ot} Modbus messages.`);
    } catch (e) {
      const m = (e as Error).message;
      setError(/Failed to fetch|NetworkError|Load failed/i.test(m)
        ? "Can't reach the helper. Is it running? If your browser asked for permission to access devices on your network, allow it. (An https page reaching http://127.0.0.1 is blocked by some browsers, e.g. Safari; then open the dashboard from a local copy.)"
        : m);
      setLiveInfo("");
    } finally { setLive(false); liveStop.current = true; await refresh(); }
  }
  const stopLive = () => { liveStop.current = true; };

  async function refresh() {
    const t = await getTables();
    setHistory(t.settings.imports); setLearningMin(t.settings.learningMin); setStored(persistent);
  }
  useEffect(() => { refresh(); }, []);

  async function run(name: string, bytes: Uint8Array, learning?: number) {
    setBusy(true); setError(""); setResult(null);
    try {
      const t = await getTables();
      t.settings.learningMin = Math.max(0, Math.floor(learningMin) || 0);
      const res = await importFile(name, bytes, { sensitivity, learningMin: learning, progress: (s) => setStage(s) });
      setResult({ ...res, source: name });
      await refresh();
    } catch (e: any) { setError(e.message ?? String(e)); }
    finally { setBusy(false); setStage(""); }
  }
  async function onFile(f: File | undefined) { if (f) await run(f.name, new Uint8Array(await f.arrayBuffer())); if (fileRef.current) fileRef.current.value = ""; }
  async function sample() {
    const r = await fetch(`${BASE_PATH}/sample-flows.csv`);
    if (!r.ok) { setError(`Sample not found (${r.status})`); return; }
    await run("sample-flows.csv (synthetic)", new Uint8Array(await r.arrayBuffer()), 0);   // short synthetic file: attackers have 25 flows each, all inside a 50-flow learning period
  }

  return (
    <div style={{ maxWidth: 820 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 6 }}>Import traffic</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 20, lineHeight: 1.6 }}>
        Everything here runs and is stored <b>in this browser</b> (IndexedDB). Nothing is uploaded, there is no account.
        Import a Wireshark/tcpdump capture (.pcap, .pcapng) or a flow CSV; the dashboard pages then read what you have imported,
        and later imports add to it. {stored === false && <b style={{ color: "var(--alert)" }}>Browser storage is unavailable here, so data will be lost on reload.</b>}
      </p>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center", marginBottom: 14 }}>
        <input ref={fileRef} data-testid="file" type="file" accept=".pcap,.pcapng,.cap,.csv,.txt" disabled={busy || live} onChange={(e) => onFile(e.target.files?.[0])} />
        <button onClick={sample} disabled={busy} style={btn}>Import a sample</button>
        <span style={{ fontSize: 11, color: "var(--text-dim)" }}>(sample imports with learning period 0: its attackers only have 25 flows each)</span>
      </div>
      <div style={{ display: "flex", gap: 24, flexWrap: "wrap", fontSize: 12, color: "var(--text-muted)", marginBottom: 18 }}>
        <label>Sensitivity{" "}
          <select value={sensitivity} onChange={(e) => setSensitivity(Number(e.target.value))} disabled={busy}>
            {[1, 2, 5, 10, 15, 20].map((v) => <option key={v} value={v}>flag top {v}%</option>)}
          </select>
        </label>
        <label title="A source's first N flows are only learned from, never judged (the server engine's default is 50).">
          Learning period{" "}
          <input type="number" min={0} value={learningMin} disabled={busy} onChange={(e) => setLearningMin(Number(e.target.value))} style={{ width: 70 }} /> flows per new source
        </label>
      </div>
      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 16px", marginBottom: 18 }}>
        <div style={{ fontSize: 13, marginBottom: 4 }}><b>Live capture</b> <span style={{ color: "var(--text-dim)" }}>— needs a small helper on your own computer</span></div>
        <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 10 }}>
          A web page cannot sniff packets, so the helper does the capturing on your computer and this page pulls from it.{" "}
          {process.env.NEXT_PUBLIC_HELPER_URL
            ? <><a href={process.env.NEXT_PUBLIC_HELPER_URL} style={{ color: "var(--signal)" }}>Download the helper</a> (needs Wireshark on Windows/macOS, or tcpdump on Linux; run as Administrator/root) and start it; </>
            : <>Run <span className="mono">python agent/live_bridge.py</span> from the project (needs Wireshark or tcpdump); </>}
          choose your network interface, then paste the token it prints. Flows, devices, internet endpoints and Modbus messages are saved into this browser as they arrive.
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input aria-label="Helper address" value={bridgeUrl} onChange={(e) => setBridgeUrl(e.target.value)} disabled={live} className="mono"
            style={{ width: 220, padding: "6px 8px", fontSize: 12, background: "var(--bg-base)", color: "var(--text-primary)", border: "1px solid var(--border-strong)" }} />
          <input aria-label="Helper token" data-testid="live-token" placeholder="token from the helper" value={token} onChange={(e) => setToken(e.target.value)} disabled={live} className="mono"
            style={{ width: 220, padding: "6px 8px", fontSize: 12, background: "var(--bg-base)", color: "var(--text-primary)", border: "1px solid var(--border-strong)" }} />
          {!live
            ? <button data-testid="live-start" onClick={startLive} disabled={!token.trim() || busy} style={{ ...btn, background: "var(--signal)", color: "#08201d", border: "none", fontWeight: 600, opacity: token.trim() ? 1 : 0.5 }}>Start live capture</button>
            : <button data-testid="live-stop" onClick={stopLive} style={btn}>Stop</button>}
        </div>
        {liveInfo && <div data-testid="live-info" className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>{liveInfo}</div>}
      </div>
      {busy && <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Working… {stage}</div>}
      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 12 }}>{error}</div>}

      {result && (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: 16, fontSize: 13, lineHeight: 1.7, marginBottom: 20 }}>
          <b>{result.source}</b>
          {result.total != null && <>: {result.total.toLocaleString()} flows analysed{result.sampledFrom ? ` (sampled from ${result.sampledFrom.toLocaleString()})` : ""}
          {result.skippedRows ? `, ${result.skippedRows} unreadable rows skipped` : ""}.<br />
          <b>{result.flagged}</b> flagged (critical {result.bySeverity!.critical}, high {result.bySeverity!.high}, medium {result.bySeverity!.medium}, low {result.bySeverity!.low}) · {result.incidentsTouched} incident(s) touched.<br />
          {(result.learning ?? 0) > 0 && <>{result.learning!.toLocaleString()} flows were in a source&apos;s learning period and were learned from, not judged.
            {result.learning! > result.total * 0.3 && <> That is a large share of this file: a source that is new and misbehaves from its first flows is learned as normal. For a one-off capture, set the learning period to 0 and import again.</>}<br /></>}
          {result.burstSkipped && <span style={{ color: "var(--text-dim)" }}>No timestamps in this file, so the burst rule was skipped.<br /></span>}
          {(result.detectors ?? 4) < 4 && <span style={{ color: "var(--text-dim)" }}>Fewer than 250 flows: the Half-Space Trees detector needs more, so 3 of 4 detectors ran.<br /></span>}</>}
          {result.analysisNote && <span>: {result.analysisNote}<br /></span>}
          {result.extras && <>From the capture: {result.extras.devices} device(s) discovered, {result.extras.endpoints} internet endpoint(s), {result.extras.otMessages} Modbus message(s) ({result.extras.otFlagged} flagged by OT rules).<br /></>}
          <Link href="/dashboard" style={{ color: "var(--signal)" }}>Overview →</Link>{" · "}
          <Link href="/dashboard/incidents" style={{ color: "var(--signal)" }}>Incidents →</Link>{" · "}
          <Link href="/dashboard/devices" style={{ color: "var(--signal)" }}>Devices →</Link>{" · "}
          <Link href="/dashboard/external" style={{ color: "var(--signal)" }}>Internet connections →</Link>{" · "}
          <Link href="/dashboard/ot-events" style={{ color: "var(--signal)" }}>OT events →</Link>
        </div>
      )}

      <h2 style={{ fontSize: 14, fontWeight: 600, margin: "24px 0 8px" }}>Imports in this browser</h2>
      {history.length === 0 ? <div style={{ fontSize: 13, color: "var(--text-dim)" }}>Nothing imported yet.</div> : (
        <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
          <thead><tr style={{ textAlign: "left", color: "var(--text-dim)" }}><th>When</th><th>Source</th><th>Flows</th><th>Flagged</th><th>Learning</th><th>Devices</th><th>Endpoints</th><th>Modbus</th></tr></thead>
          <tbody>{history.map((h, i) => (
            <tr key={i} style={{ borderTop: "1px solid var(--border)" }}>
              <td className="mono">{h.at.replace("T", " ").slice(0, 19)}</td><td>{h.source}</td><td>{h.flows}</td><td>{h.flagged}</td><td>{h.learning}</td><td>{h.devices ?? ""}</td><td>{h.endpoints ?? ""}</td><td>{h.ot ?? ""}</td>
            </tr>))}</tbody>
        </table>
      )}

      <details style={{ marginTop: 28, fontSize: 12, color: "var(--text-muted)", lineHeight: 1.7 }}>
        <summary style={{ cursor: "pointer" }}>What local mode does and does not do</summary>
        <ul>
          <li>The four detectors are re-implemented in TypeScript and refit on each import (batch, up to {MAX_FLOWS.toLocaleString()} flows, larger files are sampled). They are not the same code as the server engine; per-source learning, baseline drift and burst rules are ported, and baselines persist between imports.</li>
          <li>Incidents group flagged events from one source within 30 minutes, as on the server.</li>
          <li>From a capture, the same TypeScript ports of the server's passive device discovery, internet-endpoint extraction and Modbus/TCP rule engine also run (Modbus baselines persist between imports).</li>
          <li>Not available without a server: alert delivery (Slack/Teams/email), response actions, API keys and teams, PDF report, and the SNMP physical map (a browser cannot poll switches).</li>
          <li>Data lives only in this browser profile. Clearing site data or using another browser/device starts empty. Use Privacy &amp; audit to export or erase it.</li>
        </ul>
      </details>
    </div>
  );
}
