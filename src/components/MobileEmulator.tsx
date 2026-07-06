import React, { useState, useEffect } from "react";
import { 
  Smartphone, Fingerprint, Shield, Radio, Check, 
  BellRing, RefreshCw, Eye, Sparkles, KeyRound 
} from "lucide-react";
import { User } from "../types";

interface MobileEmulatorProps {
  currentUser: User | null;
  pendingPushRequest: {
    appId: string;
    appName: string;
    onApprove: () => void;
    onReject: () => void;
  } | null;
  onBiometricSuccess: () => void;
}

export default function MobileEmulator({ 
  currentUser, 
  pendingPushRequest,
  onBiometricSuccess 
}: MobileEmulatorProps) {
  const [totpCode, setTotpCode] = useState("482 910");
  const [totpProgress, setTotpProgress] = useState(100);
  const [phoneTime, setPhoneTime] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanSuccess, setScanSuccess] = useState(false);
  const [showNotificationAlert, setShowNotificationAlert] = useState(false);

  // Synchronized time-based rolling codes (MFA Offline Synchronizer)
  useEffect(() => {
    const updateTimeAndCode = () => {
      const now = new Date();
      // Format phone clock: 14:25
      setPhoneTime(now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }));

      // Roll a new TOTP code every 30 seconds
      const seconds = now.getSeconds();
      const progress = ((30 - (seconds % 30)) / 30) * 100;
      setTotpProgress(progress);

      if (seconds % 30 === 0) {
        // Generate a pseudo-random TOTP number
        const randomNum = Math.floor(100000 + Math.random() * 900000);
        const codeString = randomNum.toString().replace(/(\d{3})(\d{3})/, "$1 $2");
        setTotpCode(codeString);
      }
    };

    updateTimeAndCode();
    const interval = setInterval(updateTimeAndCode, 1000);
    return () => clearInterval(interval);
  }, []);

  // Handle automatic slide-in for push requests
  useEffect(() => {
    if (pendingPushRequest) {
      setShowNotificationAlert(true);
      setScanSuccess(false);
    } else {
      setShowNotificationAlert(false);
    }
  }, [pendingPushRequest]);

  // Simulate fingerprint scan
  const handleFingerprintScan = () => {
    if (isScanning || scanSuccess) return;
    setIsScanning(true);
    
    setTimeout(() => {
      setIsScanning(false);
      setScanSuccess(true);
      
      // Notify parent of successful biometric handshake
      setTimeout(() => {
        if (pendingPushRequest) {
          pendingPushRequest.onApprove();
        }
        onBiometricSuccess();
        setShowNotificationAlert(false);
        setScanSuccess(false);
      }, 1000);
    }, 1500);
  };

  return (
    <div className="w-full max-w-[340px] mx-auto bg-zinc-950 rounded-[48px] p-3.5 border-4 border-zinc-800 shadow-2xl relative overflow-hidden flex flex-col font-sans text-zinc-100 min-h-[580px]">
      
      {/* Phone Ear Speaker & Notch */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 h-6 w-32 bg-zinc-900 rounded-b-2xl z-20 flex items-center justify-center">
        <div className="w-12 h-1 bg-zinc-700 rounded-full mb-1"></div>
      </div>

      {/* Screen Interface */}
      <div className="bg-zinc-900 rounded-[38px] flex-1 p-4 pt-8 flex flex-col relative overflow-hidden border border-zinc-800">
        
        {/* Status Bar */}
        <div className="flex justify-between items-center text-[10px] text-zinc-400 font-mono mb-4 px-2">
          <span>{phoneTime}</span>
          <div className="flex items-center gap-1.5">
            <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
            <span className="text-[9px] bg-zinc-800 px-1 py-0.5 rounded text-emerald-400 font-mono">SECURE-LINK</span>
            <span>98%</span>
          </div>
        </div>

        {/* Authenticator App Title */}
        <div className="flex items-center gap-2 mb-4 px-1">
          <div className="p-1.5 bg-zinc-800 text-emerald-400 rounded-lg">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-semibold tracking-tight text-white leading-tight">Aegis Shield</h4>
            <p className="text-[9px] text-zinc-400">Mobile MFA Node</p>
          </div>
        </div>

        {/* Rolling TOTP Generator (Offline Sync) */}
        <div className="bg-zinc-950 rounded-2xl border border-zinc-800 p-4 mb-4 flex flex-col items-center justify-center text-center relative overflow-hidden group">
          <div className="absolute top-2 right-3 flex items-center gap-1 text-[8px] text-zinc-500 uppercase font-mono">
            <RefreshCw className="w-2.5 h-2.5 animate-spin" style={{ animationDuration: "12s" }} />
            <span>Sync</span>
          </div>

          <p className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider mb-1">
            {currentUser ? currentUser.email : "employee@enterprise.io"}
          </p>
          <div className="text-2xl font-mono font-bold tracking-widest text-emerald-400 my-1 drop-shadow-md">
            {totpCode}
          </div>

          {/* Time Limit Progress Bar */}
          <div className="w-full bg-zinc-900 h-1.5 rounded-full mt-3 overflow-hidden">
            <div 
              className="bg-emerald-500 h-full transition-all duration-1000 rounded-full"
              style={{ width: `${totpProgress}%` }}
            ></div>
          </div>
          <p className="text-[8px] text-zinc-500 mt-2 font-mono">
            Code updates in {Math.round(totpProgress * 0.3)}s • Offline Mode Enabled
          </p>
        </div>

        {/* Main Phone Screen State */}
        <div className="flex-1 flex flex-col justify-between">
          
          {/* Notification Block (Push Notification Simulation) */}
          {showNotificationAlert && pendingPushRequest ? (
            <div className="bg-zinc-950 border border-amber-500/30 rounded-xl p-3 animate-bounce shadow-lg">
              <div className="flex items-start gap-2.5">
                <div className="p-1.5 bg-amber-500/10 text-amber-400 rounded-lg animate-pulse mt-0.5">
                  <BellRing className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <h5 className="text-[11px] font-bold text-white uppercase tracking-wider">Access Request</h5>
                  <p className="text-[10px] text-zinc-300 mt-0.5">
                    Login requested for <strong className="text-emerald-400">{pendingPushRequest.appName}</strong>
                  </p>
                  <p className="text-[8px] text-zinc-500 font-mono mt-0.5">
                    IP: {currentUser?.ipAddress || "192.168.1.52"}
                  </p>
                </div>
              </div>

              {/* Action Prompt */}
              <div className="mt-3 grid grid-cols-2 gap-2 text-[10px]">
                <button 
                  onClick={() => {
                    pendingPushRequest.onReject();
                    setShowNotificationAlert(false);
                  }}
                  className="py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-400 rounded-lg font-medium transition-colors"
                >
                  Deny
                </button>
                <div className="py-1 bg-zinc-900 text-center text-amber-400 border border-amber-500/20 rounded-lg font-mono text-[9px] animate-pulse">
                  Use Biometrics
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-zinc-950/40 rounded-xl p-3 border border-zinc-800/50 flex-1 flex flex-col justify-center items-center text-center">
              <KeyRound className="w-8 h-8 text-zinc-600 mb-2" />
              <p className="text-[10px] text-zinc-400 font-medium px-2">
                Awaiting authentication signals from enterprise workspace...
              </p>
              <div className="mt-2.5 px-2 py-1 rounded bg-emerald-500/5 border border-emerald-500/10 text-[8px] text-emerald-400 font-mono inline-flex items-center gap-1">
                <Sparkles className="w-2.5 h-2.5 text-emerald-400 animate-pulse" />
                Zero-Trust Shield Active
              </div>
            </div>
          )}

          {/* Fingerprint Biometric Scanner Zone */}
          <div className="mt-4 border-t border-zinc-800 pt-3 flex flex-col items-center">
            <p className="text-[9px] text-zinc-500 mb-2 font-medium">
              {showNotificationAlert ? "Touch & hold sensor to approve login" : "Biometric security endpoint active"}
            </p>
            
            <button 
              onMouseDown={handleFingerprintScan}
              onTouchStart={handleFingerprintScan}
              className={`relative p-5 rounded-full border-2 transition-all duration-300 focus:outline-none ${
                scanSuccess 
                  ? "bg-emerald-950/40 border-emerald-500 text-emerald-400 scale-105" 
                  : isScanning 
                    ? "bg-amber-950/40 border-amber-500 text-amber-400 scale-95" 
                    : "bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-white hover:border-zinc-700"
              }`}
            >
              {isScanning && (
                <div className="absolute inset-0 rounded-full border-2 border-amber-400 animate-ping opacity-60"></div>
              )}
              {scanSuccess ? (
                <Check className="w-7 h-7 text-emerald-400" />
              ) : (
                <Fingerprint className="w-7 h-7" />
              )}
            </button>
            
            <div className="text-[9px] text-center mt-1.5 h-4">
              {isScanning ? (
                <span className="text-amber-400 animate-pulse font-mono uppercase tracking-wider">Verifying Identity...</span>
              ) : scanSuccess ? (
                <span className="text-emerald-400 font-mono uppercase tracking-wider">Approved • Signed</span>
              ) : (
                <span className="text-zinc-500 uppercase tracking-widest font-mono text-[8px]">Biometric Keypad</span>
              )}
            </div>
          </div>

        </div>

      </div>

      {/* Interactive Home Indicator Bar */}
      <div className="w-28 h-1 bg-zinc-800 rounded-full mx-auto mt-2"></div>
    </div>
  );
}
