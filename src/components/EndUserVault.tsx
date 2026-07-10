import React, { useState } from "react";
import { 
  Key, Globe, ExternalLink, Lock, ShieldCheck, Terminal, 
  Sparkles, RefreshCw, Smartphone, Check, User, Code, Eye
} from "lucide-react";
import { User as UserType, SSOApp, SAMLHandshakeResponse } from "../types";

interface PushHandlers {
  onApprove?: (data: SAMLHandshakeResponse) => void;
  onReject?: () => void;
}

interface EndUserVaultProps {
  currentUser: UserType;
  apps: SSOApp[];
  onTriggerPush: (app: SSOApp, handlers: PushHandlers) => void;
  onRefresh: () => void;
}

export default function EndUserVault({ 
  currentUser, 
  apps, 
  onTriggerPush,
  onRefresh
}: EndUserVaultProps) {
  const [selectedApp, setSelectedApp] = useState<SSOApp | null>(null);
  const [authenticating, setAuthenticating] = useState(false);
  const [ssoResponse, setSsoResponse] = useState<SAMLHandshakeResponse | null>(null);
  const [showAssertionXml, setShowAssertionXml] = useState(false);
  // Push MFA resolves on the Mobile Emulator, so we can't pop a blocking overlay
  // (it would hide the phone). Track the wait/denied states inline instead.
  const [waitingForPush, setWaitingForPush] = useState<SSOApp | null>(null);
  const [pushDenied, setPushDenied] = useState(false);

  // Filter apps assigned to this user
  const assignedApps = apps.filter(app => currentUser.assignedApps.includes(app.id));

  // Handle single sign-on assertion generation
  const handleSSOLaunch = async (app: SSOApp) => {
    setSsoResponse(null);
    setShowAssertionXml(false);
    setPushDenied(false);

    // REAL apps (the bundled sample SP): open the app itself — it will run a
    // genuine SAML SP-initiated SSO flow back through this IdP.
    if (app.launchUrl) {
      window.open(app.launchUrl, "_blank", "noopener");
      return;
    }

    // Push MFA: approval happens on the Mobile Emulator. Keep the phone reachable by
    // showing a non-blocking inline "waiting" state instead of the full-screen modal.
    // Once the remote biometric handshake resolves, surface the signed assertion.
    if (currentUser.mfaType === "Push") {
      setWaitingForPush(app);
      onTriggerPush(app, {
        onApprove: (data) => {
          setWaitingForPush(null);
          if (data?.success) {
            setSelectedApp(app);
            setSsoResponse(data);
          }
        },
        onReject: () => {
          setWaitingForPush(null);
          setPushDenied(true);
        },
      });
      return;
    }

    // Direct authentications (Biometric / TOTP / SMS simulation) open the modal directly.
    setSelectedApp(app);
    setAuthenticating(true);
    await executeSSOAssertion(app);
  };

  const executeSSOAssertion = async (app: SSOApp) => {
    try {
      const response = await fetch("/api/sso/handshake", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: currentUser.id, appId: app.id }),
      });
      const data = await response.json();
      if (data.success) {
        setSsoResponse(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setAuthenticating(false);
    }
  };

  // Close modal and refresh logs
  const handleCloseSSOModal = () => {
    setSelectedApp(null);
    setSsoResponse(null);
    setAuthenticating(false);
    setWaitingForPush(null);
    onRefresh();
  };

  return (
    <div className="flex flex-col gap-6 font-sans">
      
      {/* Header Banner */}
      <div className="bg-zinc-950 text-white p-6 rounded-2xl border border-zinc-800 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <span className="text-[9px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-mono uppercase tracking-widest font-semibold">
            MFA Endpoint active
          </span>
          <h2 className="text-lg font-bold text-white mt-1.5 flex items-center gap-2">
            <User className="w-5 h-5 text-emerald-400" />
            AegisID MyApps Dashboard
          </h2>
          <p className="text-xs text-zinc-400 mt-1">
            Secure single-sign-on catalog authenticated for <strong className="text-zinc-200">{currentUser.fullName}</strong> ({currentUser.email}).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right hidden md:block">
            <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-semibold block">SAML Directory Role</span>
            <span className="text-xs text-zinc-200 font-semibold">{currentUser.role}</span>
          </div>
          <div className="w-10 h-10 rounded-full bg-zinc-800 flex items-center justify-center font-bold text-white uppercase text-sm border border-zinc-700">
            {currentUser.fullName.slice(0, 2)}
          </div>
        </div>
      </div>

      {/* Main Apps Grid */}
      <div className="bg-white border border-zinc-200 p-6 rounded-2xl shadow-sm flex flex-col gap-4">
        <div>
          <h3 className="text-xs font-bold text-zinc-800 uppercase tracking-wider">Assigned Enterprise Applications</h3>
          <p className="text-xs text-zinc-500 mt-0.5">Click any application launcher card below to issue secure Single Sign-On handshake.</p>
        </div>

        {/* Push MFA: non-blocking wait banner so the Mobile Emulator stays reachable */}
        {waitingForPush && (
          <div className="p-3.5 bg-amber-50 border border-amber-200 rounded-xl flex items-start gap-3 animate-fade-in">
            <RefreshCw className="w-4 h-4 text-amber-500 shrink-0 mt-0.5 animate-spin" />
            <div>
              <p className="text-xs font-bold text-amber-800 uppercase tracking-wider">Push Sent • Awaiting Approval</p>
              <p className="text-[11px] text-amber-700 mt-0.5 leading-normal">
                A login request for <strong>{waitingForPush.name}</strong> was pushed to your device. Approve it with your
                fingerprint on the <strong>Mobile MFA Emulator</strong> to complete the SSO handshake.
              </p>
            </div>
          </div>
        )}

        {/* Push denied feedback */}
        {pushDenied && (
          <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl flex items-start gap-3 animate-fade-in">
            <Lock className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-xs font-bold text-rose-800 uppercase tracking-wider">SSO Access Denied</p>
              <p className="text-[11px] text-rose-700 mt-0.5 leading-normal">
                The federated login was rejected from the mobile authenticator. No SAML assertion was issued.
              </p>
            </div>
            <button
              onClick={() => setPushDenied(false)}
              className="text-[10px] font-mono text-rose-600 hover:text-rose-800 uppercase focus:outline-none"
            >
              Dismiss
            </button>
          </div>
        )}

        {assignedApps.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {assignedApps.map((app) => (
              <button
                key={app.id}
                onClick={() => handleSSOLaunch(app)}
                disabled={!!waitingForPush}
                className="group border border-zinc-200 hover:border-zinc-400 rounded-xl p-5 text-left transition-all hover:shadow-sm flex flex-col justify-between gap-6 min-h-[160px] bg-white outline-none focus:ring-2 focus:ring-zinc-900 disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:border-zinc-200 disabled:hover:shadow-none"
              >
                <div className="flex justify-between items-start w-full">
                  <div className="p-2.5 bg-zinc-100 group-hover:bg-zinc-200 rounded-xl transition-colors font-mono font-bold text-zinc-800 uppercase text-xs">
                    {app.name.slice(0, 2)}
                  </div>
                  <div className="flex items-center gap-1.5">
                    {app.launchUrl && (
                      <span className="text-[9px] bg-emerald-500 text-white font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider animate-pulse">
                        ● Live
                      </span>
                    )}
                    <span className="text-[10px] bg-zinc-100 text-zinc-600 font-mono px-2 py-0.5 rounded font-medium border border-zinc-150">
                      {app.protocol}
                    </span>
                  </div>
                </div>

                <div className="w-full">
                  <h4 className="text-xs font-bold text-zinc-900 group-hover:text-zinc-950 uppercase tracking-tight flex items-center gap-1">
                    {app.name}
                    <ExternalLink className="w-3.5 h-3.5 text-zinc-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </h4>
                  <p className="text-[10px] text-zinc-400 truncate mt-1">{app.entityId}</p>
                </div>
              </button>
            ))}
          </div>
        ) : (
          <div className="border-2 border-dashed border-zinc-200 rounded-xl p-8 text-center bg-zinc-50/50">
            <Lock className="w-8 h-8 text-zinc-300 mx-auto mb-2" />
            <p className="text-xs font-semibold text-zinc-700 uppercase">Catalog Empty</p>
            <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
              You currently have no federated applications assigned. Contact your directory administrator via the Admin Console to provision secure links.
            </p>
          </div>
        )}
      </div>

      {/* Interactive SSO Simulation Modal Overlay */}
      {selectedApp && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-2xl w-full border border-zinc-200 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            
            {/* Modal Header */}
            <div className="bg-zinc-950 p-5 border-b border-zinc-800 text-white flex justify-between items-center">
              <div className="flex items-center gap-3">
                <Terminal className="w-5 h-5 text-emerald-400" />
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider">AegisID Federated SSO Handshake</h3>
                  <p className="text-[10px] text-zinc-400 font-mono mt-0.5">Target Audience: {selectedApp.name}</p>
                </div>
              </div>
              
              <button 
                onClick={handleCloseSSOModal}
                className="text-zinc-400 hover:text-white font-mono text-xs uppercase hover:underline focus:outline-none"
              >
                Close Gateway
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto flex flex-col gap-5">
              
              {/* Authenticating loading status */}
              {authenticating && (
                <div className="py-12 flex flex-col items-center text-center gap-3">
                  <RefreshCw className="w-8 h-8 text-amber-500 animate-spin" />
                  <p className="text-xs font-bold uppercase text-zinc-700 tracking-widest animate-pulse">Waiting for Remote Authenticator...</p>
                  <p className="text-xs text-zinc-500 max-w-xs leading-normal">
                    Secure identity requested via MFA policy. Open the side-by-side **Mobile Shield Simulator** and scan your fingerprint biometric to authorize this login.
                  </p>
                </div>
              )}

              {/* SSO Token Handshake successful results */}
              {ssoResponse && (
                <div className="flex flex-col gap-4 animate-fade-in">
                  
                  {/* Success Alert */}
                  <div className="p-4 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-xl flex items-start gap-3">
                    <ShieldCheck className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider">SSO Authorization Successful</h4>
                      <p className="text-xs text-emerald-700 font-mono mt-1 leading-normal">
                        Issued secure SAML assertion for {selectedApp.name} via biometric verification.
                      </p>
                      <p className="text-[10px] text-emerald-600 mt-1 font-mono">
                        Session Authority Token ID: {ssoResponse.sessionId}
                      </p>
                    </div>
                  </div>

                  {/* SSO Assertion code viewport */}
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider flex items-center gap-1.5 font-mono">
                        <Code className="w-3.5 h-3.5 text-zinc-400" />
                        Signed SAML 2.0 XML Assertion
                      </span>
                      
                      <button
                        onClick={() => setShowAssertionXml(!showAssertionXml)}
                        className="text-[10px] font-mono text-indigo-600 hover:text-indigo-800 flex items-center gap-1 uppercase"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        {showAssertionXml ? "Hide XML" : "Inspect Signed XML"}
                      </button>
                    </div>

                    {showAssertionXml ? (
                      <pre className="bg-zinc-950 text-zinc-300 font-mono text-[10px] p-4 rounded-xl overflow-x-auto border border-zinc-800 select-all leading-normal max-h-[220px]">
                        {ssoResponse.assertion}
                      </pre>
                    ) : (
                      <div className="bg-zinc-50 rounded-xl p-4 border border-zinc-150 text-[11px] text-zinc-600 flex flex-col gap-2 font-mono">
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Issuer:</span>
                          <span className="font-semibold text-zinc-800">https://aegisid.enterprise.com/saml2</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Subject NameID:</span>
                          <span className="font-semibold text-zinc-800">{currentUser.email}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Role Attribute:</span>
                          <span className="font-semibold text-zinc-800">{currentUser.role}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Issued Timestamp:</span>
                          <span className="font-semibold text-zinc-800">{ssoResponse.issuedAt}</span>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="flex justify-end gap-3 mt-2">
                    <button
                      onClick={handleCloseSSOModal}
                      className="px-4 py-2 bg-zinc-900 hover:bg-zinc-800 text-white rounded-lg text-xs font-semibold shadow transition-colors"
                    >
                      Complete SSO Login Handshake
                    </button>
                  </div>

                </div>
              )}

            </div>
          </div>
        </div>
      )}

    </div>
  );
}
