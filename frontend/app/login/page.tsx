"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setLoading(false);
    if (error) {
      setError(error.message);
      return;
    }
    router.push("/dashboard");
  }

  return (
    <main
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <div style={{ width: 340 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 32 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 2,
              background: "var(--signal-dim)",
              border: "1px solid var(--signal)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "var(--signal)",
              fontFamily: "var(--font-mono)",
              fontSize: 12,
            }}
          >
            N
          </div>
          <span style={{ fontSize: 14, fontWeight: 600 }}>Network AI</span>
        </div>

        <h1 style={{ fontSize: 17, fontWeight: 600, marginBottom: 4 }}>Sign in</h1>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 24 }}>
          Access your tenant&apos;s anomaly detection dashboard.
        </p>

        <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <Field type="email" placeholder="Email" value={email} onChange={setEmail} />
          <Field type="password" placeholder="Password" value={password} onChange={setPassword} />
          {error && (
            <p style={{ color: "var(--critical)", fontSize: 12 }}>{error}</p>
          )}
          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: 4,
              padding: "10px 12px",
              fontSize: 13,
              fontWeight: 500,
              background: loading ? "var(--bg-panel-raised)" : "var(--signal-dim)",
              border: "1px solid var(--signal)",
              borderRadius: 2,
              color: "var(--text-primary)",
              cursor: loading ? "default" : "pointer",
            }}
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 20, lineHeight: 1.5 }}>
          New tenant? Sign-up creates your workspace and the first admin account.
        </p>
      </div>
    </main>
  );
}

function Field({
  type, placeholder, value, onChange,
}: { type: string; placeholder: string; value: string; onChange: (v: string) => void }) {
  return (
    <input
      type={type}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      required
      style={{
        padding: "10px 12px",
        fontSize: 13,
        background: "var(--bg-panel)",
        border: "1px solid var(--border)",
        borderRadius: 2,
        color: "var(--text-primary)",
      }}
    />
  );
}
