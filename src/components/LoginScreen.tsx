import React, { useState, useEffect } from "react";
import { Shield, RefreshCw, Fingerprint, KeyRound, Globe, ArrowLeft, Lock } from "lucide-react";
import { startAuthentication } from "@simplewebauthn/browser";
import { User } from "../types";

interface Props {
  onLoggedIn: (user: User) => void;
}

const jsonPost = async (url: string, body: any) => {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { ok: res.ok, data: await res.json().catch(() => ({})) };
};

export default function LoginScreen({ onLoggedIn }: Props) {
  const [step, setStep] = useState<"creds" | "mfa">("creds");
  const [email, setEmail] = useState("alex.rivera@enterprise.io");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // MFA step
  const [methods, setMethods] = useState<string[]>([]);
  const [pendingToken, setPendingToken] = useState<string>("");
  const [mfaCode, setMfaCode] = useState("");

  const [oidcConfigured, setOidcConfigured] = useState(false);

  useEffect(() => {
    fetch("/api/oidc/status").then((r) => r.json()).then((d) => setOidcConfigured(!!d.configured)).catch(() => {});
    const params = new URLSearchParams(window.location.search);
    const oidc = params.get("oidc");
    if (oidc === "error") setError(`OIDC sign-in failed: ${params.get("reason") || "unknown error"}.`);
    else if (oidc === "unconfigured") setError("OIDC is not configured. Set OIDC_ISSUER + OIDC_CLIENT_ID (see README).");
    if (oidc) window.history.replaceState({}, "", window.location.pathname);
  }, []);

  const submitCreds = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    const { ok, data } = await jsonPost("/api/auth/login", { email, password });
    setBusy(false);
    if (!ok) return setError(data.error || "Login failed.");
    if (data.authenticated) return onLoggedIn(data.user);
    if (data.mfaRequired) {
      setMethods(data.methods || []);
      setPendingToken(data.pendingToken);
      setStep("mfa");
    }
  };

  const submitTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    const { ok, data } = await jsonPost("/api/auth/mfa/totp", { pendingToken, code: mfaCode });
    setBusy(false);
    if (!ok) return setError(data.error || "Verification failed.");
    if (data.authenticated) onLoggedIn(data.user);
  };

  const usePasskey = async () => {
    setBusy(true); setError(null);
    try {
      const optRes = await jsonPost("/api/auth/mfa/passkey/options", { pendingToken });
      if (!optRes.ok) throw new Error(optRes.data.error || "Could not start passkey sign-in.");
      const asResp = await startAuthentication({ optionsJSON: optRes.data });
      const verRes = await jsonPost("/api/auth/mfa/passkey/verify", { pendingToken, response: asResp });
      if (!verRes.data.authenticated) throw new Error(verRes.data.error || "Passkey verification failed.");
      onLoggedIn(verRes.data.user);
    } catch (err: any) {
      setError(err.name === "NotAllowedError" ? "Biometric prompt cancelled." : err.message);
    } finally {
      setBusy(false);
    }
  };

  // Passwordless: resolve the account entirely from the passkey (no email/password).
  const passwordlessPasskey = async () => {
    setBusy(true); setError(null);
    try {
      const optRes = await jsonPost("/api/auth/passkey/login/options", {});
      if (!optRes.ok) throw new Error(optRes.data.error || "Could not start passkey sign-in.");
      const asResp = await startAuthentication({ optionsJSON: optRes.data });
      const verRes = await jsonPost("/api/auth/passkey/login/verify", { response: asResp });
      if (!verRes.data.authenticated) throw new Error(verRes.data.error || "Passkey sign-in failed.");
      onLoggedIn(verRes.data.user);
    } catch (err: any) {
      setError(
        err.name === "NotAllowedError" ? "Passkey prompt cancelled."
          : err.name === "NotSupportedError" ? "No passkey available on this device."
            : err.message,
      );
    } finally {
      setBusy(false);
    }
  };

  const resetToCreds = () => {
    setStep("creds"); setMfaCode(""); setError(null); setPendingToken(""); setMethods([]);
  };

  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col justify-center items-center p-6 font-sans">
      <div className="w-full max-w-sm flex flex-col gap-6">
        {/* Branding */}
        <div className="flex flex-col items-center gap-2 text-center">
          <div className="p-2.5 bg-emerald-500 rounded-2xl">
            <Shield className="w-6 h-6 text-zinc-950" />
          </div>
          <h1 className="text-sm font-extrabold text-white tracking-tight uppercase font-mono flex items-center gap-1.5">
            AegisID IAM Suite
            <span className="text-[9px] bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-500/25">Enterprise</span>
          </h1>
          <p className="text-[11px] text-zinc-500">Sign in to your federated identity account</p>
        </div>

        <div className="bg-white rounded-2xl border border-zinc-200 shadow-2xl p-6 flex flex-col gap-4">
          {step === "creds" ? (
            <form onSubmit={submitCreds} className="flex flex-col gap-3.5">
              <div>
                <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">Email</label>
                <input
                  type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
                  autoComplete="username"
                  className="w-full text-sm p-2.5 bg-zinc-50 border border-zinc-200 rounded-lg outline-none focus:ring-2 focus:ring-emerald-500/30 focus:border-emerald-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">Password</label>
                <input
                  type="password" required value={password} onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password" placeholder="••••••••"
                  className="w-full text-sm p-2.5 bg-zinc-50 border border-zinc-200 rounded-lg outline-none focus:ring-2 focus:ring-emerald-500/30 focus:border-emerald-500 font-mono"
                />
              </div>

              {error && <div className="text-[11px] font-medium bg-rose-50 border border-rose-200 text-rose-700 rounded-lg px-3 py-2">{error}</div>}

              <button type="submit" disabled={busy}
                className="w-full py-2.5 bg-zinc-900 hover:bg-zinc-800 disabled:opacity-50 text-white rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition-colors">
                {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />} Sign in
              </button>

              <div className="flex items-center gap-2 text-[10px] text-zinc-400 uppercase tracking-wider">
                <span className="flex-1 h-px bg-zinc-200" /> or <span className="flex-1 h-px bg-zinc-200" />
              </div>

              <button type="button" onClick={passwordlessPasskey} disabled={busy}
                className="w-full py-2.5 bg-white hover:bg-zinc-50 border border-zinc-300 disabled:opacity-50 text-zinc-800 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition-colors">
                <Fingerprint className="w-4 h-4 text-emerald-500" /> Sign in with a passkey
              </button>

              {oidcConfigured && (
                <a href="/api/oidc/login"
                  className="w-full py-2.5 bg-white hover:bg-zinc-50 border border-zinc-300 text-zinc-800 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition-colors">
                  <Globe className="w-4 h-4 text-indigo-500" /> Sign in with Keycloak (OIDC)
                </a>
              )}
            </form>
          ) : (
            <div className="flex flex-col gap-3.5">
              <div className="flex items-center gap-2">
                <button onClick={resetToCreds} className="text-zinc-400 hover:text-zinc-700"><ArrowLeft className="w-4 h-4" /></button>
                <div>
                  <h2 className="text-sm font-bold text-zinc-900">Second factor required</h2>
                  <p className="text-[11px] text-zinc-500">Signing in as {email}</p>
                </div>
              </div>

              {methods.includes("totp") && (
                <form onSubmit={submitTotp} className="flex flex-col gap-2">
                  <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider flex items-center gap-1.5">
                    <KeyRound className="w-3 h-3" /> Authenticator code
                  </label>
                  <input
                    value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} inputMode="numeric"
                    placeholder="000000" autoFocus
                    className="w-full text-lg text-center tracking-[0.4em] font-mono p-2.5 bg-zinc-50 border border-zinc-200 rounded-lg outline-none focus:ring-2 focus:ring-emerald-500/30 focus:border-emerald-500"
                  />
                  <button type="submit" disabled={busy || mfaCode.length < 6}
                    className="w-full py-2.5 bg-zinc-900 hover:bg-zinc-800 disabled:opacity-50 text-white rounded-lg text-sm font-semibold flex items-center justify-center gap-2">
                    {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : null} Verify code
                  </button>
                </form>
              )}

              {methods.includes("totp") && methods.includes("passkey") && (
                <div className="flex items-center gap-2 text-[10px] text-zinc-400 uppercase tracking-wider">
                  <span className="flex-1 h-px bg-zinc-200" /> or <span className="flex-1 h-px bg-zinc-200" />
                </div>
              )}

              {methods.includes("passkey") && (
                <button onClick={usePasskey} disabled={busy}
                  className="w-full py-2.5 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white rounded-lg text-sm font-semibold flex items-center justify-center gap-2">
                  <Fingerprint className="w-4 h-4" /> Use passkey (Touch ID)
                </button>
              )}

              {error && <div className="text-[11px] font-medium bg-rose-50 border border-rose-200 text-rose-700 rounded-lg px-3 py-2">{error}</div>}
            </div>
          )}
        </div>

        {/* Demo hint */}
        <div className="text-center text-[10px] text-zinc-500 leading-relaxed font-mono">
          <p className="text-zinc-400">Sandbox directory — demo password for all accounts:</p>
          <p className="text-emerald-400 font-semibold">aegis1234</p>
          <p className="mt-1 text-zinc-600">Admin: alex.rivera@enterprise.io · Employee: marcus.c@enterprise.io</p>
        </div>
      </div>
    </div>
  );
}
