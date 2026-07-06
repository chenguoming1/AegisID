import React, { useState, useEffect } from "react";
import { 
  Shield, Users, Key, AlertTriangle, Smartphone, Sparkles, 
  RefreshCw, ShieldAlert, CheckCircle, Database, HelpCircle 
} from "lucide-react";
import AdminDashboard from "./components/AdminDashboard";
import EndUserVault from "./components/EndUserVault";
import MobileEmulator from "./components/MobileEmulator";
import CryptoVisualizer from "./components/CryptoVisualizer";
import { User, SSOApp, AuditLog, ThreatIncident } from "./types";

export default function App() {
  const [dbState, setDbState] = useState<{
    users: User[];
    apps: SSOApp[];
    logs: AuditLog[];
    threats: ThreatIncident[];
  } | null>(null);

  const [activePersona, setActivePersona] = useState<"admin" | "employee">("admin");
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  
  // Pending push requests directed to the smartphone widget
  const [pendingPushRequest, setPendingPushRequest] = useState<{
    appId: string;
    appName: string;
    onApprove: () => void;
    onReject: () => void;
  } | null>(null);

  // Fetch complete dataset on mount
  const fetchDbState = async () => {
    try {
      const response = await fetch("/api/db");
      const data = await response.json();
      setDbState(data);
      
      // Select Admin user and Employee user from response
      const admin = data.users.find((u: User) => u.role === "Admin");
      const emp = data.users.find((u: User) => u.role === "Employee") || data.users[0];
      
      // Bind context depending on the active persona view
      setCurrentUser(activePersona === "admin" ? admin : emp);
    } catch (err) {
      console.error("Failed to load federated directory:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDbState();
  }, [activePersona]);

  // Synchronize persona change
  const handleTogglePersona = (persona: "admin" | "employee") => {
    setActivePersona(persona);
  };

  // Reset database state to defaults (sandbox utility)
  const handleResetDb = async () => {
    if (!window.confirm("Restore IAM directories to out-of-the-box SOC 2 baseline? This will flush all custom provisioned employees and alert trails.")) return;
    setLoading(true);
    try {
      const res = await fetch("/api/db/reset", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setDbState(data.db);
        const admin = data.db.users.find((u: User) => u.role === "Admin");
        setCurrentUser(activePersona === "admin" ? admin : data.db.users[2]);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
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
      if (data.success) {
        fetchDbState();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Push Auth Request (triggered from SSO Single Sign-On launcher)
  const triggerPushSimulation = (user: User, app: SSOApp) => {
    // Generate trigger on phone emulator
    setPendingPushRequest({
      appId: app.id,
      appName: app.name,
      onApprove: () => {
        // Post SSO confirmation
        fetch("/api/sso/handshake", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId: user.id, appId: app.id }),
        })
          .then((res) => res.json())
          .then((data) => {
            // Success! Reload db
            setPendingPushRequest(null);
            fetchDbState();
            
            // Render positive callback alert on UI (simulated overlay)
            alert(`Single Sign-On Assertion Handshake Complete!\n\nSuccessfully authenticated with ${app.name} using Mobile Biometric approval.`);
          });
      },
      onReject: () => {
        setPendingPushRequest(null);
        alert("Federated SSO Access Denied by Mobile User rejection.");
      },
    });
  };

  // Handle biometric fingerprint trigger callback (from Mobile Emulator directly)
  const handleBiometricSuccess = () => {
    // Action is handled inside pendingPushRequest.onApprove()
  };

  if (loading || !dbState) {
    return (
      <div className="min-h-screen bg-zinc-950 flex flex-col justify-center items-center text-zinc-100 p-6">
        <RefreshCw className="w-12 h-12 text-emerald-400 animate-spin mb-4" />
        <h1 className="text-sm font-mono font-bold tracking-widest uppercase">Initializing AegisID Secure Shell...</h1>
        <p className="text-xs text-zinc-500 mt-1 font-mono">Calibrating directory salts, AES encoders, and OIDC ports</p>
      </div>
    );
  }

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

        {/* View Switch Controller */}
        <div className="flex items-center gap-4">
          <div className="bg-zinc-100 p-1 rounded-xl text-xs font-bold flex border border-zinc-200">
            <button
              onClick={() => handleTogglePersona("admin")}
              className={`px-4 py-2 rounded-lg transition-all flex items-center gap-2 ${
                activePersona === "admin" 
                  ? "bg-white text-zinc-950 shadow-sm" 
                  : "text-zinc-500 hover:text-zinc-900"
              }`}
            >
              <Users className="w-3.5 h-3.5" />
              IT Admin Panel
            </button>
            <button
              onClick={() => handleTogglePersona("employee")}
              className={`px-4 py-2 rounded-lg transition-all flex items-center gap-2 ${
                activePersona === "employee" 
                  ? "bg-white text-zinc-950 shadow-sm" 
                  : "text-zinc-500 hover:text-zinc-900"
              }`}
            >
              <Smartphone className="w-3.5 h-3.5" />
              Employee Portal
            </button>
          </div>

          <button
            onClick={handleResetDb}
            className="text-[10px] bg-zinc-100 hover:bg-zinc-200 border border-zinc-200 text-zinc-700 px-3 py-2 rounded-xl transition-colors font-semibold uppercase tracking-wider font-mono focus:outline-none"
          >
            Reset DB
          </button>
        </div>

      </header>

      {/* Primary Workspace Viewport Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Side: Master Dashboards & Sandbox Tools (8 Columns) */}
        <section className="lg:col-span-8 flex flex-col gap-6">
          
          {/* Active View Selector */}
          {activePersona === "admin" ? (
            <AdminDashboard
              users={dbState.users}
              apps={dbState.apps}
              logs={dbState.logs}
              threats={dbState.threats}
              onRefresh={fetchDbState}
              triggerMockThreat={triggerMockThreat}
              triggerPushSimulation={triggerPushSimulation}
            />
          ) : (
            <EndUserVault
              currentUser={currentUser!}
              apps={dbState.apps}
              onTriggerPush={(app) => triggerPushSimulation(currentUser!, app)}
              onRefresh={fetchDbState}
            />
          )}

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
              currentUser={currentUser}
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
