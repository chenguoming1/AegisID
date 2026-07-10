import React, { useState } from "react";
import {
  ShieldCheck, Fingerprint, RefreshCw, Check, Trash2, Copy,
  KeyRound, Smartphone, Zap,
} from "lucide-react";
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import { User } from "../types";

interface Props {
  currentUser: User;
  onRefresh: () => void;
}

type Banner = { type: "ok" | "err" | "info"; text: string } | null;

const jsonPost = async (url: string, body: any) => {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { ok: res.ok, data: await res.json().catch(() => ({})) };
};

function MsgBanner({ msg }: { msg: Banner }) {
  if (!msg) return null;
  const styles =
    msg.type === "ok"
      ? "bg-emerald-50 border-emerald-200 text-emerald-800"
      : msg.type === "err"
        ? "bg-rose-50 border-rose-200 text-rose-800"
        : "bg-indigo-50 border-indigo-200 text-indigo-800";
  return (
    <div className={`text-[11px] font-medium border rounded-lg px-3 py-2 ${styles}`}>{msg.text}</div>
  );
}

export default function AccountSecurity({ currentUser, onRefresh }: Props) {
  const userId = currentUser.id;

  // --- TOTP ---
  const [totpEnroll, setTotpEnroll] = useState<{ qrDataUrl: string; manualEntryKey: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpBusy, setTotpBusy] = useState(false);
  const [totpMsg, setTotpMsg] = useState<Banner>(null);
  const [totpTest, setTotpTest] = useState("");
  const [totpTestMsg, setTotpTestMsg] = useState<Banner>(null);

  // --- Passkeys (WebAuthn) ---
  const [pkBusy, setPkBusy] = useState(false);
  const [pkMsg, setPkMsg] = useState<Banner>(null);

  // ---- TOTP handlers ----
  const startTotp = async () => {
    setTotpBusy(true); setTotpMsg(null);
    const { data } = await jsonPost("/api/mfa/totp/enroll", { userId });
    setTotpBusy(false);
    if (data.success) setTotpEnroll({ qrDataUrl: data.qrDataUrl, manualEntryKey: data.manualEntryKey });
    else setTotpMsg({ type: "err", text: data.error || "Could not start enrollment." });
  };

  const confirmTotp = async () => {
    setTotpBusy(true); setTotpMsg(null);
    const { data } = await jsonPost("/api/mfa/totp/verify", { userId, token: totpCode });
    setTotpBusy(false);
    if (data.success) {
      setTotpEnroll(null); setTotpCode("");
      setTotpMsg({ type: "ok", text: "Authenticator verified and enabled." });
      onRefresh();
    } else {
      setTotpMsg({ type: "err", text: data.error || "Invalid code." });
    }
  };

  const disableTotp = async () => {
    await jsonPost("/api/mfa/totp/disable", { userId });
    setTotpMsg({ type: "info", text: "Authenticator removed." });
    onRefresh();
  };

  const testTotp = async () => {
    setTotpTestMsg(null);
    const { data } = await jsonPost("/api/mfa/totp/validate", { userId, token: totpTest });
    setTotpTest("");
    setTotpTestMsg(data.success
      ? { type: "ok", text: "Code accepted — valid second factor." }
      : { type: "err", text: "Code rejected." });
  };

  // ---- WebAuthn handlers ----
  const addPasskey = async () => {
    setPkBusy(true); setPkMsg(null);
    try {
      const optRes = await jsonPost("/api/webauthn/register/options", { userId });
      if (!optRes.ok) throw new Error(optRes.data.error || "Could not get registration options.");
      const attResp = await startRegistration({ optionsJSON: optRes.data });
      const verRes = await jsonPost("/api/webauthn/register/verify", { userId, response: attResp });
      if (!verRes.data.success) throw new Error(verRes.data.error || "Registration could not be verified.");
      setPkMsg({ type: "ok", text: "Passkey registered with your device biometrics." });
      onRefresh();
    } catch (err: any) {
      setPkMsg({ type: "err", text: err.name === "NotAllowedError" ? "Passkey prompt cancelled." : err.message });
    } finally {
      setPkBusy(false);
    }
  };

  const signInPasskey = async () => {
    setPkBusy(true); setPkMsg(null);
    try {
      const optRes = await jsonPost("/api/webauthn/authenticate/options", { userId });
      if (!optRes.ok) throw new Error(optRes.data.error || "No passkey to sign in with.");
      const asResp = await startAuthentication({ optionsJSON: optRes.data });
      const verRes = await jsonPost("/api/webauthn/authenticate/verify", { userId, response: asResp });
      if (!verRes.data.success) throw new Error(verRes.data.error || "Signature verification failed.");
      setPkMsg({ type: "ok", text: "Passkey assertion verified — biometric check passed." });
      onRefresh();
    } catch (err: any) {
      setPkMsg({ type: "err", text: err.name === "NotAllowedError" ? "Biometric prompt cancelled." : err.message });
    } finally {
      setPkBusy(false);
    }
  };

  const removePasskey = async (credentialId: string) => {
    await jsonPost("/api/webauthn/remove", { userId, credentialId });
    onRefresh();
  };

  const totpVerified = !!currentUser.totpVerified;
  const passkeys = currentUser.passkeys || [];

  return (
    <div className="bg-white border border-zinc-200/80 rounded-2xl p-6 shadow-sm flex flex-col gap-5">
      {/* Header */}
      <div className="flex items-start justify-between border-b border-zinc-100 pb-4">
        <div>
          <h3 className="text-base font-semibold text-zinc-900 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            Account Security — Real MFA
          </h3>
          <p className="text-xs text-zinc-500 mt-1">
            Factors for <strong className="text-zinc-700">{currentUser.fullName}</strong>'s AegisID account. Enroll these and
            they'll be required the next time you sign in — real codes from your phone, real device biometrics.
          </p>
        </div>
        <span className="text-[10px] bg-emerald-50 text-emerald-600 font-mono font-medium px-2 py-0.5 rounded-full border border-emerald-100 uppercase tracking-wider shrink-0">
          Not a simulation
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* --- TOTP card --- */}
        <div className="border border-zinc-200 rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Smartphone className="w-4 h-4 text-zinc-700" />
              <h4 className="text-xs font-bold text-zinc-800 uppercase tracking-wider">Authenticator (TOTP)</h4>
            </div>
            {totpVerified
              ? <span className="text-[9px] bg-emerald-100 text-emerald-700 px-1.5 py-0.5 rounded font-bold">ENABLED</span>
              : <span className="text-[9px] bg-zinc-100 text-zinc-500 px-1.5 py-0.5 rounded font-bold">OFF</span>}
          </div>
          <p className="text-[11px] text-zinc-500 leading-normal">RFC 6238 codes verified server-side. Scan with Google Authenticator, Authy, or 1Password.</p>

          {totpEnroll ? (
            <div className="flex flex-col gap-2.5">
              <img src={totpEnroll.qrDataUrl} alt="TOTP QR code" className="w-40 h-40 mx-auto rounded-lg border border-zinc-200" />
              <button
                onClick={() => navigator.clipboard?.writeText(totpEnroll.manualEntryKey)}
                className="text-[10px] font-mono text-zinc-500 hover:text-zinc-800 flex items-center gap-1 justify-center"
                title="Copy manual entry key"
              >
                <Copy className="w-3 h-3" /> {totpEnroll.manualEntryKey}
              </button>
              <input
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                inputMode="numeric"
                placeholder="Enter 6-digit code"
                className="w-full text-sm text-center tracking-widest font-mono p-2 bg-zinc-50 border border-zinc-200 rounded-lg outline-none focus:ring-1 focus:ring-emerald-500"
              />
              <button onClick={confirmTotp} disabled={totpBusy || totpCode.length < 6}
                className="w-full py-2 bg-zinc-900 hover:bg-zinc-800 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5">
                {totpBusy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />} Verify & enable
              </button>
            </div>
          ) : totpVerified ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-1.5 text-[11px] text-emerald-700 font-semibold">
                <Check className="w-3.5 h-3.5" /> Authenticator active
              </div>
              <div className="flex gap-1.5">
                <input value={totpTest} onChange={(e) => setTotpTest(e.target.value)} inputMode="numeric" placeholder="Test a code"
                  className="flex-1 text-xs font-mono p-2 bg-zinc-50 border border-zinc-200 rounded-lg outline-none focus:ring-1 focus:ring-emerald-500" />
                <button onClick={testTotp} disabled={totpTest.length < 6}
                  className="px-3 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white rounded-lg text-xs font-semibold">Test</button>
              </div>
              <MsgBanner msg={totpTestMsg} />
              <button onClick={disableTotp} className="text-[10px] text-rose-600 hover:text-rose-800 flex items-center gap-1 self-start">
                <Trash2 className="w-3 h-3" /> Remove authenticator
              </button>
            </div>
          ) : (
            <button onClick={startTotp} disabled={totpBusy}
              className="w-full py-2 bg-zinc-900 hover:bg-zinc-800 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 mt-auto">
              {totpBusy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />} Set up authenticator
            </button>
          )}
          <MsgBanner msg={totpMsg} />
        </div>

        {/* --- Passkey card --- */}
        <div className="border border-zinc-200 rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-zinc-700" />
              <h4 className="text-xs font-bold text-zinc-800 uppercase tracking-wider">Passkey (WebAuthn)</h4>
            </div>
            {passkeys.length
              ? <span className="text-[9px] bg-emerald-100 text-emerald-700 px-1.5 py-0.5 rounded font-bold">{passkeys.length} SAVED</span>
              : <span className="text-[9px] bg-zinc-100 text-zinc-500 px-1.5 py-0.5 rounded font-bold">NONE</span>}
          </div>
          <p className="text-[11px] text-zinc-500 leading-normal">Real Touch ID / Face ID / Windows Hello. The private key never leaves your device.</p>

          {passkeys.length > 0 && (
            <div className="flex flex-col gap-1.5">
              {passkeys.map((p) => (
                <div key={p.id} className="flex items-center justify-between bg-zinc-50 border border-zinc-150 rounded-lg px-2.5 py-1.5">
                  <span className="text-[10px] font-mono text-zinc-700 flex items-center gap-1.5"><KeyRound className="w-3 h-3 text-emerald-500" />{p.label}</span>
                  <button onClick={() => removePasskey(p.id)} className="text-rose-500 hover:text-rose-700"><Trash2 className="w-3.5 h-3.5" /></button>
                </div>
              ))}
            </div>
          )}

          <div className="flex flex-col gap-2 mt-auto">
            <button onClick={addPasskey} disabled={pkBusy}
              className="w-full py-2 bg-zinc-900 hover:bg-zinc-800 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5">
              {pkBusy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Fingerprint className="w-3.5 h-3.5" />} Add a passkey
            </button>
            {passkeys.length > 0 && (
              <button onClick={signInPasskey} disabled={pkBusy}
                className="w-full py-2 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5">
                <Zap className="w-3.5 h-3.5" /> Test passkey assertion
              </button>
            )}
          </div>
          <MsgBanner msg={pkMsg} />
        </div>
      </div>
    </div>
  );
}
