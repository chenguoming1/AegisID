import React, { useState } from "react";
import { 
  Lock, Unlock, KeyRound, Database, ShieldAlert, ShieldCheck, 
  ArrowRight, Cpu, Eye, EyeOff, RefreshCw 
} from "lucide-react";
import { EncryptedResult } from "../types";

export default function CryptoVisualizer() {
  const [plaintext, setPlaintext] = useState("EnterpriseLDAP_Root_Password_2026!");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EncryptedResult | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [showSensitive, setShowSensitive] = useState(false);

  // Trigger server-side cryptographic encryption
  const handleEncrypt = async () => {
    if (!plaintext.trim()) return;
    setLoading(true);
    setResult(null);
    setDecryptedText(null);
    setDecryptError(null);

    try {
      const response = await fetch("/api/crypto/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plaintext }),
      });
      const data = await response.json();
      if (data.success) {
        setResult(data);
      } else {
        throw new Error(data.error || "Encryption failed.");
      }
    } catch (err: any) {
      setDecryptError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Trigger server-side cryptographic decryption
  const handleDecrypt = async () => {
    if (!result) return;
    setDecrypting(true);
    setDecryptError(null);
    setDecryptedText(null);

    try {
      const response = await fetch("/api/crypto/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          iv: result.iv,
          ciphertext: result.ciphertext,
          authTag: result.authTag,
        }),
      });
      const data = await response.json();
      if (data.success) {
        setDecryptedText(data.decryptedPlaintext);
      } else {
        throw new Error(data.error || "Integrity verification failed.");
      }
    } catch (err: any) {
      setDecryptError(err.message);
    } finally {
      setDecrypting(false);
    }
  };

  return (
    <div className="bg-white border border-zinc-200/80 rounded-2xl p-6 shadow-sm flex flex-col gap-6">
      
      {/* Header */}
      <div className="flex items-start justify-between border-b border-zinc-100 pb-4">
        <div>
          <h3 className="text-base font-semibold text-zinc-900 flex items-center gap-2">
            <Lock className="w-4 h-4 text-emerald-500" />
            End-to-End Cryptography Visualizer
          </h3>
          <p className="text-xs text-zinc-500 mt-1">
            Secure client-to-server credential sealing using AES-256-GCM symmetric encryption.
          </p>
        </div>
        <span className="text-[10px] bg-emerald-50 text-emerald-600 font-mono font-medium px-2 py-0.5 rounded-full border border-emerald-100 uppercase tracking-wider">
          AES-256 GCM
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Plaintext Entry & Encrypt trigger */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          <div>
            <label className="block text-xs font-semibold text-zinc-700 uppercase tracking-wider mb-2">
              Sensitive Credentials (Plaintext)
            </label>
            <div className="relative">
              <input
                type={showSensitive ? "text" : "password"}
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
                placeholder="Enter sensitive system secret..."
                className="w-full text-sm px-3.5 py-2.5 bg-zinc-50 border border-zinc-200 rounded-lg focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 font-mono outline-none text-zinc-800 pr-10"
              />
              <button
                type="button"
                onClick={() => setShowSensitive(!showSensitive)}
                className="absolute top-1/2 -translate-y-1/2 right-3 text-zinc-400 hover:text-zinc-600 focus:outline-none"
              >
                {showSensitive ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-[10px] text-zinc-500 mt-1.5">
              These coordinates represent directory credentials, encryption salts, or private authentication keys.
            </p>
          </div>

          <button
            onClick={handleEncrypt}
            disabled={loading || !plaintext.trim()}
            className="w-full py-2.5 px-4 bg-zinc-900 hover:bg-zinc-800 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all disabled:opacity-50"
          >
            {loading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Cpu className="w-3.5 h-3.5" />
            )}
            Compile AES-256-GCM Seal
          </button>

          {/* Theoretical cryptographic model box */}
          <div className="bg-zinc-50 rounded-xl p-4 border border-zinc-150">
            <h4 className="text-[11px] font-bold text-zinc-800 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <KeyRound className="w-3.5 h-3.5 text-zinc-500" />
              Symmetric Key Pipeline
            </h4>
            <div className="flex flex-col gap-2.5 text-[10px] text-zinc-600 font-mono">
              <div className="flex justify-between items-center bg-white p-1.5 rounded border border-zinc-100">
                <span className="text-zinc-400">PBKDF2 Iterations</span>
                <span className="font-semibold text-zinc-800">100,000 Rounds</span>
              </div>
              <div className="flex justify-between items-center bg-white p-1.5 rounded border border-zinc-100">
                <span className="text-zinc-400">Hash Algorithm</span>
                <span className="font-semibold text-zinc-800">HMAC-SHA256</span>
              </div>
              <div className="flex justify-between items-center bg-white p-1.5 rounded border border-zinc-100">
                <span className="text-zinc-400">Symmetric Crypt</span>
                <span className="font-semibold text-zinc-800">AES-GCM-256</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Encrypted Output & Decrypt verification */}
        <div className="lg:col-span-7 flex flex-col gap-4">
          
          {result ? (
            <div className="flex-1 flex flex-col gap-4 animate-fade-in">
              
              {/* Derived Cryptographic Artifacts */}
              <div className="bg-zinc-950 text-zinc-300 rounded-xl p-4 font-mono text-[11px] border border-zinc-800 flex flex-col gap-3 shadow-inner">
                
                <div>
                  <div className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1.5 mb-1">
                    <Database className="w-3.5 h-3.5" />
                    Symmetric Ciphertext Block
                  </div>
                  <div className="bg-zinc-900 p-2.5 rounded border border-zinc-800 text-[10px] text-zinc-300 break-all select-all font-semibold leading-relaxed">
                    {result.ciphertext}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <span className="text-zinc-500 block text-[9px] uppercase tracking-wider mb-0.5">Initialization Vector (IV)</span>
                    <span className="text-zinc-300 bg-zinc-900 px-2 py-1.5 rounded border border-zinc-800 block text-[10px] select-all break-all">{result.iv}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[9px] uppercase tracking-wider mb-0.5">Authenticity GCM Tag</span>
                    <span className="text-zinc-300 bg-zinc-900 px-2 py-1.5 rounded border border-zinc-800 block text-[10px] select-all break-all">{result.authTag}</span>
                  </div>
                </div>

                <div>
                  <span className="text-zinc-500 block text-[9px] uppercase tracking-wider mb-0.5">Secure Storage Envelope String</span>
                  <span className="text-[10px] text-zinc-400 break-all bg-zinc-900 p-2 rounded border border-zinc-800 block select-all">{result.secureStoragePayload}</span>
                </div>
              </div>

              {/* Action: Integrity Verification */}
              <div className="flex gap-3 items-center">
                <button
                  onClick={handleDecrypt}
                  disabled={decrypting}
                  className="flex-1 py-2.5 px-4 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm"
                >
                  {decrypting ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Unlock className="w-3.5 h-3.5" />
                  )}
                  Integrity Validation (Decrypt)
                </button>
              </div>

              {/* Result State */}
              {decryptedText && (
                <div className="p-3 bg-emerald-50 border border-emerald-200/80 rounded-xl flex items-start gap-2.5 animate-bounce">
                  <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-bold text-emerald-800 uppercase tracking-wider">Authentication Check Passed</p>
                    <p className="text-xs text-emerald-700 font-mono mt-0.5 break-all">
                      Decrypted Value: <strong className="text-zinc-900 select-all font-semibold bg-white px-1 rounded">{decryptedText}</strong>
                    </p>
                    <p className="text-[9px] text-emerald-600 mt-1">
                      AES-GCM integrity checksum matches corporate envelope.
                    </p>
                  </div>
                </div>
              )}

              {decryptError && (
                <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl flex items-start gap-2.5">
                  <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-bold text-rose-800 uppercase tracking-wider">Integrity Compromised</p>
                    <p className="text-xs text-rose-700 font-mono mt-0.5 break-all">{decryptError}</p>
                  </div>
                </div>
              )}

            </div>
          ) : (
            <div className="flex-1 border-2 border-dashed border-zinc-200 rounded-xl flex flex-col justify-center items-center p-6 text-center min-h-[220px] bg-zinc-50/50">
              <Cpu className="w-8 h-8 text-zinc-400 mb-2 animate-pulse" />
              <p className="text-xs text-zinc-700 font-semibold uppercase tracking-wider">No Symmetric Envelope Compiled</p>
              <p className="text-xs text-zinc-500 mt-1 max-w-sm">
                Type secret parameters in the left pane, and trigger the encryption compiler to observe secure binary mapping.
              </p>
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
