import React, { useState, useEffect } from "react";
import { Shield, Users, Smartphone, RefreshCw, LogOut } from "lucide-react";
import AdminDashboard from "./components/AdminDashboard";
import EndUserVault from "./components/EndUserVault";
import MobileEmulator from "./components/MobileEmulator";
import CryptoVisualizer from "./components/CryptoVisualizer";
import AccountSecurity from "./components/AccountSecurity";
import LoginScreen from "./components/LoginScreen";
import { User, SSOApp, AuditLog, ThreatIncident, SAMLHandshakeResponse } from "./types";

// Optional callbacks so the caller (e.g. the Employee Portal modal) can react to the
// remote push approval/denial that happens over on the Mobile Emulator widget.
interface PushHandlers {
  onApprove?: (data: SAMLHandshakeResponse) => void;
  onReject?: () => void;
}

const ADMIN_ROLES = ["Admin", "Security Engineer"];

function FullLoader({ text }: { text: string }) {
  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col justify-center items-center text-zinc-100 p-6">
      <RefreshCw className="w-12 h-12 text-emerald-400 animate-spin mb-4" />
      <h1 className="text-sm font-mono font-bold tracking-widest uppercase">{text}</h1>
      <p className="text-xs text-zinc-500 mt-1 font-mono">Calibrating directory salts, AES encoders, and OIDC ports</p>
    </div>
  );
}

export default function App() {
  // --- Auth session ---
  const [authUser, setAuthUser] = useState<User | null>(null);
  const [authChecked, setAuthChecked] = useState(false);

  // --- Directory data ---
  const [dbState, setDbState] = useState<{
    users: User[];
    apps: SSOApp[];
    logs: AuditLog[];
    threats: ThreatIncident[];
  } | null>(null);

  const [activeView, setActiveView] = useState<"admin" | "employee">("admin");

  // Pending push requests directed to the smartphone widget
  const [pendingPushRequest, setPendingPushRequest] = useState<{
    appId: string;
    appName: string;
    onApprove: () => void;
    onReject: () => void;
  } | null>(null);

  const canAdmin = authUser ? ADMIN_ROLES.includes(authUser.role) : false;

  // Check for an existing session on mount (also catches the OIDC redirect that
  // set a session server-side, which lands back here as ?login=oidc).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("login")) window.history.replaceState({}, "", window.location.pathname);
    fetch("/api/auth/me")
      .then((r) => r.json())
      .then((d) => { if (d.authenticated) setAuthUser(d.user); })
      .catch(() => {})
      .finally(() => setAuthChecked(true));
  }, []);

  // Resume an interrupted SAML SSO flow: the IdP endpoint bounces unauthenticated
  // users here with ?samlContinue=<original /saml/sso URL>. Once a session exists,
  // send the browser back to complete the handshake. Same-origin /saml/sso only.
  useEffect(() => {
    if (!authUser) return;
    const cont = new URLSearchParams(window.location.search).get("samlContinue");
    if (cont && cont.startsWith("/saml/sso")) {
      window.location.replace(cont);
    }
  }, [authUser?.id]);

  // When the authenticated user changes, pick the default view and load data.
  useEffect(() => {
    if (!authUser) return;
    setActiveView(ADMIN_ROLES.includes(authUser.role) ? "admin" : "employee");
    fetchDbState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authUser?.id]);

  const fetchDbState = async () => {
    try {
      const response = await fetch("/api/db");
      if (response.status === 401) { setAuthUser(null); setDbState(null); return; }
      const data = await response.json();
      setDbState(data);
      // Keep the logged-in user's enrollment flags fresh (drives Account Security).
      const me = data.users.find((u: User) => u.id === authUser?.id);
      if (me) setAuthUser(me);
    } catch (err) {
      console.error("Failed to load federated directory:", err);
    }
  };

  const handleLoggedIn = (user: User) => setAuthUser(user);

  const handleLogout = async () => {
    try { await fetch("/api/auth/logout", { method: "POST" }); } catch {}
    setAuthUser(null);
    setDbState(null);
  };

  // Reset database state to defaults (sandbox utility)
  const handleResetDb = async () => {
    if (!window.confirm("Restore IAM directories to out-of-the-box SOC 2 baseline? This will flush all custom provisioned employees and alert trails.")) return;
    try {
      const res = await fetch("/api/db/reset", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setDbState(data.db);
        const me = data.db.users.find((u: User) => u.id === authUser?.id);
        if (me) setAuthUser(me);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Trigger simulated mock threat alerts from admin portal
  const triggerMockThreat = async (type: string) => {
    try {
      const response = await fetch("/api/threats/trigger-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type }),
      });
      const data = await response.json();
      if (data.success) fetchDbState();
    } catch (err) {
      console.error(err);
    }
  };

  // Push Auth Request (triggered from SSO Single Sign-On launcher)
  const triggerPushSimulation = (user: User, app: SSOApp, handlers?: PushHandlers) => {
    setPendingPushRequest({
      appId: app.id,
      appName: app.name,
      onApprove: async () => {
        setPendingPushRequest(null);
        try {
          const res = await fetch("/api/sso/handshake", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ userId: user.id, appId: app.id }),
          });
          const data: SAMLHandshakeResponse = await res.json();
          fetchDbState();
          handlers?.onApprove?.(data);
        } catch (err) {
          console.error("SSO handshake failed after push approval:", err);
          handlers?.onReject?.();
        }
      },
      onReject: () => {
        setPendingPushRequest(null);
        handlers?.onReject?.();
      },
    });
  };

  const handleBiometricSuccess = () => {
    // Action is handled inside pendingPushRequest.onApprove()
  };

  // --- Render gates ---
  if (!authChecked) return <FullLoader text="Restoring secure session..." />;
  if (!authUser) return <LoginScreen onLoggedIn={handleLoggedIn} />;
  if (!dbState) return <FullLoader text="Initializing AegisID Secure Shell..." />;

  const initials = authUser.fullName.split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase();

  return (
    <div className="min-h-screen bg-zinc-50 flex flex-col font-sans">

      {/* Upper Navigation Rail */}
      <header className="bg-white border-b border-zinc-200/80 sticky top-0 z-40 shadow-sm px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">

        {/* Branding Logo */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500 text-zinc-950 rounded-xl relative overflow-hidden flex items-center justify-center">
            <Shield className="w-5 h-5 text-zinc-950" />
            <div className="absolute inset-0 bg-white/10 mix-blend-overlay"></div>
          </div>
          <div>
            <h1 className="text-sm font-extrabold text-zinc-900 tracking-tight flex items-center gap-1.5 uppercase font-mono">
              AegisID IAM Suite
              <span className="text-[9px] bg-emerald-500/10 text-emerald-600 px-1.5 py-0.5 rounded border border-emerald-500/25">Enterprise</span>
            </h1>
            <p className="text-[10px] text-zinc-500 font-medium">Federated SSO Directory, SCIM Sync & Real-Time Security Logs</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* View Switch — Admin-only accounts can flip to their own Employee Portal */}
          {canAdmin && (
            <div className="bg-zinc-100 p-1 rounded-xl text-xs font-bold flex border border-zinc-200">
              <button
                onClick={() => setActiveView("admin")}
                className={`px-4 py-2 rounded-lg transition-all flex items-center gap-2 ${
                  activeView === "admin" ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-500 hover:text-zinc-900"
                }`}
              >
                <Users className="w-3.5 h-3.5" />
                IT Admin Panel
              </button>
              <button
                onClick={() => setActiveView("employee")}
                className={`px-4 py-2 rounded-lg transition-all flex items-center gap-2 ${
                  activeView === "employee" ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-500 hover:text-zinc-900"
                }`}
              >
                <Smartphone className="w-3.5 h-3.5" />
                Employee Portal
              </button>
            </div>
          )}

          {/* Signed-in identity + controls */}
          <div className="flex items-center gap-3">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-bold text-zinc-900 leading-none">{authUser.fullName}</div>
              <div className="text-[10px] text-zinc-500 font-mono mt-0.5">{authUser.role}</div>
            </div>
            <div className="w-9 h-9 rounded-full bg-zinc-950 text-white flex items-center justify-center font-bold text-xs">{initials}</div>
            <button
              onClick={handleResetDb}
              className="text-[10px] bg-zinc-100 hover:bg-zinc-200 border border-zinc-200 text-zinc-700 px-3 py-2 rounded-xl transition-colors font-semibold uppercase tracking-wider font-mono focus:outline-none"
              title="Reset sandbox directory"
            >
              Reset DB
            </button>
            <button
              onClick={handleLogout}
              className="text-[10px] bg-zinc-950 hover:bg-zinc-800 text-white px-3 py-2 rounded-xl transition-colors font-semibold uppercase tracking-wider font-mono flex items-center gap-1.5 focus:outline-none"
            >
              <LogOut className="w-3.5 h-3.5" /> Sign out
            </button>
          </div>
        </div>

      </header>

      {/* Primary Workspace Viewport Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left Side: Master Dashboards & Sandbox Tools (8 Columns) */}
        <section className="lg:col-span-8 flex flex-col gap-6">

          {canAdmin && activeView === "admin" ? (
            <AdminDashboard
              users={dbState.users}
              apps={dbState.apps}
              logs={dbState.logs}
              threats={dbState.threats}
              onRefresh={fetchDbState}
              triggerMockThreat={triggerMockThreat}
            />
          ) : (
            <EndUserVault
              currentUser={authUser}
              apps={dbState.apps}
              onTriggerPush={(app, handlers) => triggerPushSimulation(authUser, app, handlers)}
              onRefresh={fetchDbState}
            />
          )}

          {/* Real MFA factors for this account (TOTP, WebAuthn passkeys) */}
          <AccountSecurity currentUser={authUser} onRefresh={fetchDbState} />

          {/* Secure Cloud Data Storage & Encryption Visualizer */}
          <CryptoVisualizer />

        </section>

        {/* Right Side: Remote Smartphone Authenticator Emulator Widget (4 Columns) */}
        <aside className="lg:col-span-4 flex flex-col items-center gap-4">
          <div className="sticky top-20 w-full flex flex-col gap-4">

            <div className="bg-white border border-zinc-200 p-4 rounded-2xl shadow-sm">
              <h3 className="text-xs font-bold text-zinc-800 uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                <Smartphone className="w-4 h-4 text-emerald-500" />
                MFA Endpoint Emulator
              </h3>
              <p className="text-[10px] text-zinc-500 leading-normal">
                This simulated mobile app handles push approvals and rolling TOTP sync keys. Trigger an app login in the Employee Portal to send a notification here.
              </p>
            </div>

            <MobileEmulator
              currentUser={authUser}
              pendingPushRequest={pendingPushRequest}
              onBiometricSuccess={handleBiometricSuccess}
            />

          </div>
        </aside>

      </main>

      {/* SOC 2 Compliance Footer */}
      <footer className="bg-zinc-900 border-t border-zinc-800 text-zinc-400 py-6 px-6 mt-12 text-center text-xs font-mono">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span>AEGISID SECURITY CONTROL PORTAL • COMPLIANT WITH SOC 2 TYPE II • ISO/IEC 27001</span>
          </div>
          <div className="text-[10px] text-zinc-500">
            Enterprise Directory Synchronized • AES-256 Symmetric Encryption Enabled
          </div>
        </div>
      </footer>

    </div>
  );
}
