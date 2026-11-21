"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { parseCsv } from "@/lib/local/csv";
import { parseCapture } from "@/lib/local/pcap";
import { analyze, resultsToCsv, MAX_FLOWS, type Analysis } from "@/lib/local/engine";
import type { Flow } from "@/lib/local/types";
import { severityColor, severityLabel } from "@/lib/severity";

const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH || "";
const RANK = { critical: 4, high: 3, medium: 2, low: 1 } as const;

/** Runs entirely in the visitor's browser: the file is read with FileReader,
 *  parsed and scored by TypeScript code in this page, and never uploaded. */
export default function AnalyzePage() {
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<Analysis | null>(null);
  const [fileName, setFileName] = useState("");
  const [note, setNote] = useState("");
  const [sensitivity, setSensitivity] = useState(10);
  const flowsRef = useRef<Flow[] | null>(null);
  const [drag, setDrag] = useState(false);
  // live capture (talks to agent/live_bridge.py on this computer)
  const [bridgeUrl, setBridgeUrl] = useState("http://127.0.0.1:8765");
  const [token, setToken] = useState("");
  const [live, setLive] = useState(false);
  const [liveInfo, setLiveInfo] = useState("");
  const liveRun = useRef(0);
  const sensRef = useRef(sensitivity);
  sensRef.current = sensitivity;
  useEffect(() => () => { liveRun.current++; }, []);   // stop polling when leaving the page

  async function startLive() {
    const id = ++liveRun.current;
    const base = bridgeUrl.replace(/\/$/, "");
    const buf: Flow[] = [];
    let next = 0, lastAnalyzed = 0, lastCount = 0;
    setLive(true); setError(""); setResult(null); setNote(""); setFileName("live capture");
    setLiveInfo("Connecting…");
    const get = async (path: string) => {
      const r = await fetch(base + path, { headers: { Authorization: `Bearer ${token.trim()}` }, cache: "no-store" });
      if (r.status === 401) throw new Error("Wrong token. Copy the token printed by live_bridge.py.");
      if (!r.ok) throw new Error(`Bridge answered ${r.status}`);
      return r.json();
    };
    try {
      while (liveRun.current === id) {
        const st = await get("/status");
        if (st.mode === "stopped" || st.error) { setLiveInfo(`Bridge: ${st.mode}. ${st.error ?? ""}`); }
        const d = await get(`/flows?since=${next}`);
        next = d.next;
        buf.push(...(d.flows as Flow[]));
        if (buf.length > 20000) buf.splice(0, buf.length - 20000);
        const total = st.flows_total as number;
        const now = Date.now();
        const enough = buf.length >= 100;
        setLiveInfo(`Live · ${st.packets.toLocaleString()} packets seen · ${total.toLocaleString()} flows completed · ${buf.length >= 100 ? "analyzing the latest " + Math.min(buf.length, 5000).toLocaleString() : `collecting (${buf.length}/100 flows needed)`}`);
        if (enough && buf.length !== lastCount && now - lastAnalyzed > 8000) {
          lastCount = buf.length; lastAnalyzed = now;
          const win = buf.slice(-5000);
          flowsRef.current = win;
          setResult(await analyze(win, sensRef.current));
        }
        await new Promise((r) => setTimeout(r, 2000));
      }
    } catch (e) {
      const m = (e as Error).message;
      setError(/Failed to fetch|NetworkError|Load failed/i.test(m)
        ? "Can't reach the bridge. Is live_bridge.py running? If your browser asked for permission to access devices on your network, allow it."
        : m);
      setLive(false);
    }
  }
  function stopLive() { liveRun.current++; setLive(false); setLiveInfo("Stopped. The last results stay on screen."); }

  async function run(flows: Flow[], s: number) {
    setBusy(true); setError("");
    try {
      setResult(await analyze(flows, s, (st) => setStage(st)));
    } catch (e) {
      setResult(null); setError((e as Error).message);
    } finally { setBusy(false); setStage(""); }
  }

  async function loadBytes(name: string, bytes: Uint8Array) {
    setFileName(name); setNote(""); setResult(null); setError("");
    try {
      const looksText = !(bytes[0] === 0xd4 || bytes[0] === 0xa1 || bytes[0] === 0x0a || bytes[0] === 0x4d);
      let flows: Flow[];
      if (/\.(pcap|pcapng|cap)$/i.test(name) || !looksText) {
        flows = parseCapture(bytes);
        setNote(`Read ${flows.length.toLocaleString()} flows from the capture (IPv4 only; non-IP frames skipped).`);
      } else {
        const r = parseCsv(new TextDecoder().decode(bytes));
        flows = r.flows;
        setNote(`Read ${flows.length.toLocaleString()} rows${r.skipped ? `, skipped ${r.skipped} with missing/non-numeric values` : ""}.`);
      }
      flowsRef.current = flows;
      await run(flows, sensitivity);
    } catch (e) { setError((e as Error).message); }
  }

  async function onFile(f: File | undefined | null) {
    if (!f) return;
    if (f.size > 200 * 1024 * 1024) { setError("That file is over 200 MB; browsers run out of memory. Trim the capture first (e.g. with Wireshark)."); return; }
    await loadBytes(f.name, new Uint8Array(await f.arrayBuffer()));
  }

  async function loadSample() {
    try {
      const r = await fetch(`${BASE_PATH}/sample-flows.csv`);
      if (!r.ok) throw new Error(`Sample not found (${r.status})`);
      await loadBytes("sample-flows.csv (synthetic, labelled)", new Uint8Array(await r.arrayBuffer()));
    } catch (e) { setError((e as Error).message); }
  }

  function download() {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([resultsToCsv(result)], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url; a.download = "network-ai-results.csv"; a.click();
    URL.revokeObjectURL(url);
  }

  const flagged = result ? result.scored.filter((r) => r.severity)
    .sort((a, b) => RANK[b.severity!] - RANK[a.severity!] || b.consensus - a.consensus || b.ecodScore - a.ecodScore) : [];

  return (
    <div style={{ minHeight: "100vh", padding: "32px 40px", maxWidth: 1040, margin: "0 auto" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
        <span style={{ fontSize: 14, fontWeight: 600 }}>Network AI — analyze your own capture</span>
        <Link href="/demo" style={{ fontSize: 12, color: "var(--signal)", textDecoration: "none" }}>Saved demo →</Link>
      </div>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 6, lineHeight: 1.6 }}>
        Drop a <b>.pcap / .pcapng</b> capture (Wireshark, tcpdump) or a flow <b>.csv</b>. The analysis runs in this
        browser tab — your file is not uploaded anywhere, and there is no account or key to enter.
      </p>
      <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 20 }}>
        It finds flows that are unusual <i>compared with the rest of that file</i>. It cannot tell you a flow is malicious.
      </p>

      <div
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files?.[0]); }}
        style={{ border: `1px dashed ${drag ? "var(--signal)" : "var(--border-strong)"}`, background: "var(--bg-panel)", padding: "26px 20px", textAlign: "center", marginBottom: 14 }}
      >
        <div style={{ fontSize: 13, marginBottom: 12 }}>Drag a file here, or</div>
        <label style={{ background: "var(--signal)", color: "#08201d", padding: "8px 16px", fontSize: 13, cursor: "pointer", fontWeight: 600 }}>
          Choose a file
          <input data-testid="file" type="file" accept=".pcap,.pcapng,.cap,.csv" style={{ display: "none" }} onChange={(e) => onFile(e.target.files?.[0])} />
        </label>
        <button onClick={loadSample} disabled={busy} style={{ marginLeft: 12, padding: "8px 16px", fontSize: 13, background: "transparent", color: "var(--text-primary)", border: "1px solid var(--border-strong)", cursor: "pointer" }}>
          Try a sample
        </button>
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 12 }}>
          CSV columns: dur, proto, tot_pkts, src_bytes, dst_bytes, rate, load, s_ttl (optional: src_ip, dst_ip, label)
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 12, color: "var(--text-muted)", marginBottom: 18 }}>
        <label htmlFor="sens">Sensitivity</label>
        <select id="sens" value={sensitivity} disabled={busy}
          onChange={(e) => { const v = Number(e.target.value); setSensitivity(v); if (flowsRef.current) run(flowsRef.current, v); }}
          style={{ background: "var(--bg-panel)", color: "var(--text-primary)", border: "1px solid var(--border-strong)", padding: "4px 8px" }}>
          <option value={3}>Strict (about 3% most unusual)</option>
          <option value={5}>Low (5%)</option>
          <option value={10}>Normal (10%)</option>
          <option value={15}>High (15%)</option>
        </select>
        {fileName && <span className="mono" style={{ color: "var(--text-dim)" }}>{fileName}</span>}
      </div>

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 16px", marginBottom: 18 }}>
        <div style={{ fontSize: 13, marginBottom: 4 }}><b>Live capture</b> <span style={{ color: "var(--text-dim)" }}>— needs a small helper on your own computer</span></div>
        <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 10 }}>
          A web page cannot sniff packets, so a small helper runs on your computer.{" "}
          {process.env.NEXT_PUBLIC_HELPER_URL
            ? <><a href={process.env.NEXT_PUBLIC_HELPER_URL} style={{ color: "var(--signal)" }}>Download the helper</a> (Windows, macOS or Linux; needs Wireshark on Windows/macOS, or tcpdump on Linux) and run it; </>
            : <>Run <span className="mono">python agent/live_bridge.py</span> from the project (needs Wireshark or tcpdump); </>}
          choose your network interface when it asks. It prints a token; paste it here. Flows go from the helper to this tab only.
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input aria-label="Bridge address" value={bridgeUrl} onChange={(e) => setBridgeUrl(e.target.value)} disabled={live}
            className="mono" style={{ width: 220, padding: "6px 8px", fontSize: 12, background: "var(--bg-base)", color: "var(--text-primary)", border: "1px solid var(--border-strong)" }} />
          <input aria-label="Bridge token" placeholder="token from the helper" value={token} onChange={(e) => setToken(e.target.value)} disabled={live}
            className="mono" style={{ width: 220, padding: "6px 8px", fontSize: 12, background: "var(--bg-base)", color: "var(--text-primary)", border: "1px solid var(--border-strong)" }} />
          {!live
            ? <button data-testid="live-start" onClick={startLive} disabled={!token.trim()} style={{ padding: "6px 14px", fontSize: 12, background: "var(--signal)", color: "#08201d", border: "none", cursor: token.trim() ? "pointer" : "not-allowed", fontWeight: 600, opacity: token.trim() ? 1 : 0.5 }}>Start live analysis</button>
            : <button data-testid="live-stop" onClick={stopLive} style={{ padding: "6px 14px", fontSize: 12, background: "transparent", color: "var(--text-primary)", border: "1px solid var(--border-strong)", cursor: "pointer" }}>Stop</button>}
        </div>
        {liveInfo && <div data-testid="live-info" className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>{liveInfo}</div>}
      </div>

      {busy && <div data-testid="busy" style={{ fontSize: 13, color: "var(--text-muted)" }}>Analyzing… {stage}</div>}
      {error && <div data-testid="error" style={{ color: "var(--critical)", fontSize: 13, marginBottom: 12 }}>{error}</div>}
      {note && !error && <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 12 }}>{note}</div>}

      {result && !busy && (
        <div data-testid="results">
          {result.sampledFrom && (
            <div style={{ fontSize: 12, color: "var(--alert)", marginBottom: 10 }}>
              The file has {result.sampledFrom.toLocaleString()} flows; {MAX_FLOWS.toLocaleString()} evenly spaced ones were analyzed to keep the browser responsive.
            </div>
          )}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 1, marginBottom: 20 }}>
            <Tile label="Flows analyzed" value={result.total.toLocaleString()} />
            <Tile label="Flagged unusual" value={`${result.flagged} (${((result.flagged / result.total) * 100).toFixed(1)}%)`} tone="alert" />
            <Tile label="High + critical" value={String(result.bySeverity.high + result.bySeverity.critical)} tone="critical" />
            <Tile label="Detectors used" value={`${result.detectors} of 4`} />
          </div>
          {result.detectors < 4 && <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 14 }}>Half-Space Trees needs at least 250 flows, so only 3 detectors voted.</div>}

          {result.selfCheck && (
            <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "12px 16px", fontSize: 12, color: "var(--text-muted)", marginBottom: 20, lineHeight: 1.7 }}>
              <b style={{ color: "var(--text-primary)" }}>Self-check against the file’s own labels:</b>{" "}
              flagged {result.selfCheck.attacksFlagged} of {result.selfCheck.attacksInFile} labelled attack flows
              ({((result.selfCheck.attacksFlagged / Math.max(result.selfCheck.attacksInFile, 1)) * 100).toFixed(0)}%) and{" "}
              {result.selfCheck.benignFlagged} of {result.selfCheck.benign} labelled benign flows
              ({((result.selfCheck.benignFlagged / Math.max(result.selfCheck.benign, 1)) * 100).toFixed(1)}%).
              The sample is synthetic data from the same generator the detector was designed around, so this is a sanity check, not proof of accuracy on real networks.
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: 20 }}>
            <div>
              <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10, display: "flex", justifyContent: "space-between" }}>
                <span>Most unusual flows (top {Math.min(flagged.length, 40)} of {flagged.length})</span>
                <button onClick={download} style={{ fontSize: 12, background: "none", border: "none", color: "var(--signal)", cursor: "pointer" }}>Download all results (CSV)</button>
              </div>
              <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
                {flagged.length === 0 && <div style={{ padding: 14, fontSize: 12, color: "var(--text-dim)" }}>Nothing flagged.</div>}
                {flagged.slice(0, 40).map((r) => (
                  <div key={r.index} style={{ padding: "9px 14px", borderLeft: `3px solid ${severityColor(r.severity)}`, borderBottom: "1px solid var(--border)" }}>
                    <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                      <span className="mono" style={{ fontSize: 11, color: severityColor(r.severity), width: 58, textTransform: "uppercase" }}>{severityLabel(r.severity)}</span>
                      <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)", flex: 1 }}>
                        {r.flow.src_ip ?? "?"} → {r.flow.dst_ip ?? "?"} · {r.flow.proto}
                      </span>
                      <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>{r.consensus}/{result.detectors} agree</span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 3 }}>
                      {r.explanation.map((e) => `${e.feature} ${e.z > 0 ? "+" : ""}${e.z}σ`).join(" · ")}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Sources by flagged flows</div>
              <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
                {result.sources.slice(0, 12).map((s) => (
                  <div key={s.source} style={{ display: "flex", justifyContent: "space-between", padding: "9px 14px", borderBottom: "1px solid var(--border)", borderLeft: `3px solid ${severityColor(s.worst)}` }}>
                    <span className="mono" style={{ fontSize: 12 }}>{s.source}</span>
                    <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>{s.flagged}/{s.flows}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      <details style={{ marginTop: 32, fontSize: 12, color: "var(--text-muted)", lineHeight: 1.7 }}>
        <summary style={{ cursor: "pointer" }}>How it works, and what it does not do</summary>
        <ul style={{ paddingLeft: 18, marginTop: 8 }}>
          <li>Four unsupervised detectors (ECOD, Isolation Forest, Local Outlier Factor, Half-Space Trees) are fitted on <i>your file</i> and then score it. A flow is flagged when it is among the top {sensitivity}% for a detector; severity rises when several detectors agree.</li>
          <li>Because each detector flags its own top share by design, the flagged percentage mostly follows the sensitivity setting. Read the ranking and the reasons, not the count.</li>
          <li>These are TypeScript re-implementations, not the Python code. Against the Python engine on a test set: ECOD and LOF scores match to rounding error; Isolation Forest agrees closely but is random; Half-Space Trees is a batch variant.</li>
          <li>Live mode re-fits the detectors on a rolling window of the latest 5,000 completed flows every few seconds; the first flows of a new device are therefore judged against whatever else is in the window. Flows are cut after 30 s (NetFlow-style) so long transfers appear while they run.</li>
          <li>No history is kept, so the Python product’s per-device learning period, per-device baselines and burst detection are not part of this page.</li>
          <li>pcap parsing covers IPv4 over Ethernet, VLAN, Linux-cooked and raw-IP captures; IPv6 and tunnelled traffic are skipped. Very large captures (over {MAX_FLOWS.toLocaleString()} flows) are sampled.</li>
          <li>Not tested on real production captures yet.</li>
        </ul>
      </details>
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: string; tone?: "alert" | "critical" }) {
  const color = tone === "alert" ? "var(--alert)" : tone === "critical" ? "var(--critical)" : "var(--text-primary)";
  return (
    <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 18px" }}>
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>{label}</div>
      <div className="mono" style={{ fontSize: 20, color }}>{value}</div>
    </div>
  );
}
