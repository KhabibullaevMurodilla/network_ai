"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { FOCUS_OPTIONS, type Focus } from "@/lib/focus";
import { useProfile } from "@/lib/profile";

export default function OnboardingPage() {
  const router = useRouter();
  const profile = useProfile();
  const [saving, setSaving] = useState<Focus | null>(null);
  const [error, setError] = useState("");

  async function choose(f: (typeof FOCUS_OPTIONS)[number]) {
    setSaving(f.value);
    setError("");
    try {
      await api.setMyFocus(f.value);
      profile?.reload();
      try { sessionStorage.setItem("nai-landed", "1"); } catch {}
      router.replace(f.home);
    } catch (e: any) {
      setError(e.message);
      setSaving(null);
    }
  }

  return (
    <div style={{ maxWidth: 640 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 6 }}>What do you mainly use this for?</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 20 }}>
        This only decides what you see first. Nothing is hidden and it changes nothing about what you're
        allowed to do -- you can change it any time from Team &amp; focus.
      </p>
      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 12 }}>{error}</div>}
      <div style={{ display: "grid", gap: 10 }}>
        {FOCUS_OPTIONS.map((f) => (
          <button
            key={f.value}
            onClick={() => choose(f)}
            disabled={saving !== null}
            style={{ textAlign: "left", padding: "14px 16px", border: "1px solid var(--border-strong)", background: "var(--bg-panel)", color: "inherit", cursor: "pointer", borderRadius: 2, opacity: saving && saving !== f.value ? 0.5 : 1 }}
          >
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 3 }}>{f.label}</div>
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>{saving === f.value ? "Saving…" : f.blurb}</div>
          </button>
        ))}
      </div>
    </div>
  );
}
