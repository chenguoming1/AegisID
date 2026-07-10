import React, { useState, useEffect } from "react";
import {
  Users, ShieldAlert, Key, ClipboardList, UserPlus, Trash2,
  RefreshCw, CheckCircle, AlertTriangle, Play, FileText,
  Search, Shield, Download, Lock, Check, ToggleLeft, ToggleRight,
  Database, UserCheck, UserX, Cpu, Server, MapPin, Plus, X, Copy
} from "lucide-react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, BarChart, Bar } from "recharts";
import { User, SSOApp, AuditLog, ThreatIncident } from "../types";

interface AdminDashboardProps {
  users: User[];
  apps: SSOApp[];
  logs: AuditLog[];
  threats: ThreatIncident[];
  onRefresh: () => void;
  triggerMockThreat: (type: string) => void;
}

export default function AdminDashboard({
  users,
  apps,
  logs,
  threats,
  onRefresh,
  triggerMockThreat,
}: AdminDashboardProps) {
  // Tabs: users, threats, apps, logs
  const [activeTab, setActiveTab] = useState<"dashboard" | "users" | "threats" | "apps" | "logs">("dashboard");
  const [searchTerm, setSearchTerm] = useState("");
  const [logFilter, setLogFilter] = useState<string>("ALL");
  const [remediatingId, setRemediatingId] = useState<string | null>(null);
  
  // Provisioning Form
  const [showProvisionModal, setShowProvisionModal] = useState(false);
  const [provisionName, setProvisionName] = useState("");
  const [provisionEmail, setProvisionEmail] = useState("");
  const [provisionRole, setProvisionRole] = useState<any>("Employee");
  const [provisionDept, setProvisionDept] = useState("Engineering");
  const [provisionMfa, setProvisionMfa] = useState<any>("TOTP");
  const [provisionSuccess, setProvisionSuccess] = useState(false);

  // Enterprise app registration form (SSO Apps tab)
  const [showAppForm, setShowAppForm] = useState(false);
  const [appName, setAppName] = useState("");
  const [appProtocol, setAppProtocol] = useState<"SAML 2.0" | "OIDC">("SAML 2.0");
  const [appEntityId, setAppEntityId] = useState("");
  const [appSsoUrl, setAppSsoUrl] = useState("");
  const [appScim, setAppScim] = useState(false);
  const [appScimEndpoint, setAppScimEndpoint] = useState("");
  const [appRegError, setAppRegError] = useState<string | null>(null);
  const [appRegResult, setAppRegResult] = useState<{ name: string; clientId?: string; issuedSecret?: string } | null>(null);

  // Per-user application assignment panel (User Directory tab)
  const [manageAppsUserId, setManageAppsUserId] = useState<string | null>(null);

  // Gemini Incident Report State
  const [activeReportThreatId, setActiveReportThreatId] = useState<string | null>(null);
  const [geminiReport, setGeminiReport] = useState<string | null>(null);
  const [compilingReport, setCompilingReport] = useState(false);
  const [aiGenerated, setAiGenerated] = useState(false);

  // Statistics
  const activeCount = users.filter(u => u.status === "Active").length;
  const suspendedCount = users.filter(u => u.status === "Suspended").length;
  const pendingCount = users.filter(u => u.status === "Pending Onboarding").length;
  const threatCount = threats.filter(t => t.status === "Active" || t.status === "Investigating").length;

  // Chart Data preparation (sign-in telemetry timeline)
  const chartData = [
    { name: "09:00", Successful: 45, ThreatBlocked: 1 },
    { name: "11:00", Successful: 80, ThreatBlocked: 0 },
    { name: "13:00", Successful: 120, ThreatBlocked: 3 },
    { name: "15:00", Successful: 95, ThreatBlocked: 0 },
    { name: "17:00", Successful: 140, ThreatBlocked: 8 },
    { name: "19:00", Successful: 70, ThreatBlocked: 12 },
    { name: "Current", Successful: users.length * 4, ThreatBlocked: threatCount * 2 },
  ];

  // Trigger User Provisioning (SCIM Simulator)
  const handleProvisionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!provisionName || !provisionEmail) return;

    try {
      const response = await fetch("/api/users/provision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fullName: provisionName,
          email: provisionEmail,
          role: provisionRole,
          department: provisionDept,
          mfaType: provisionMfa,
        }),
      });
      const data = await response.json();
      if (data.success) {
        setProvisionSuccess(true);
        setTimeout(() => {
          setShowProvisionModal(false);
          setProvisionSuccess(false);
          setProvisionName("");
          setProvisionEmail("");
          onRefresh();
        }, 1500);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Trigger User Offboarding Deprovisioning (SCIM Simulator)
  const handleDeprovision = async (userId: string) => {
    if (!window.confirm("Are you sure you want to offboard this user? This will instantly trigger automatic SCIM deprovisioning across Slack, Salesforce, and Github, suspending active OIDC tokens and revoking all federated directories.")) return;

    try {
      const response = await fetch("/api/users/deprovision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
      });
      if (response.ok) {
        onRefresh();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Alter User Status manually
  const handleUpdateUserStatus = async (userId: string, status: string) => {
    try {
      const response = await fetch("/api/users/update-status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, status }),
      });
      if (response.ok) {
        onRefresh();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Trigger Threat Remediation Core Actions (Block IP / Force Suspense)
  const handleRemediate = async (threatId: string, actionText: string) => {
    setRemediatingId(threatId);
    try {
      const response = await fetch("/api/threats/remediate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threatId, action: actionText }),
      });
      if (response.ok) {
        onRefresh();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setRemediatingId(null);
    }
  };

  // Register a new enterprise application in the SSO catalog
  const handleRegisterApp = async (e: React.FormEvent) => {
    e.preventDefault();
    setAppRegError(null);
    try {
      const response = await fetch("/api/apps/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: appName,
          protocol: appProtocol,
          entityId: appEntityId,
          ssoUrl: appSsoUrl || undefined,
          scimEnabled: appScim,
          scimEndpoint: appScim ? appScimEndpoint : undefined,
        }),
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        setAppRegError(data.error || "Registration failed.");
        return;
      }
      setAppRegResult({ name: data.app.name, clientId: data.app.clientId, issuedSecret: data.issuedSecret });
      setAppName(""); setAppEntityId(""); setAppSsoUrl(""); setAppScim(false); setAppScimEndpoint("");
      setShowAppForm(false);
      onRefresh();
    } catch (err) {
      console.error(err);
      setAppRegError("Registration failed.");
    }
  };

  // Deregister an application (revokes it from every user)
  const handleRemoveApp = async (appId: string, name: string) => {
    if (!window.confirm(`Deregister "${name}"? This removes the federation trust and revokes access for every assigned user.`)) return;
    try {
      const response = await fetch("/api/apps/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ appId }),
      });
      if (response.ok) onRefresh();
      else alert((await response.json()).error || "Could not remove app.");
    } catch (err) {
      console.error(err);
    }
  };

  // Toggle a user's access to an application
  const handleToggleAssign = async (userId: string, appId: string, assigned: boolean) => {
    try {
      const response = await fetch("/api/apps/assign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, appId, assigned }),
      });
      if (response.ok) onRefresh();
    } catch (err) {
      console.error(err);
    }
  };

  // Compile AI compliance incident report via Gemini API
  const compileIncidentReport = async (threatId: string) => {
    setActiveReportThreatId(threatId);
    setCompilingReport(true);
    setGeminiReport(null);

    try {
      const response = await fetch("/api/gemini/incident-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threatId }),
      });
      const data = await response.json();
      if (data.success) {
        setGeminiReport(data.report);
        setAiGenerated(data.aiUsed);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setCompilingReport(false);
    }
  };

  // Mock export action for audit report
  const handleExportReport = () => {
    if (!geminiReport) return;
    const blob = new Blob([geminiReport], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `AegisID-Incident-Report-${activeReportThreatId}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Filter audit logs
  const filteredLogs = logs.filter(log => {
    const matchesSearch = 
      log.user.toLowerCase().includes(searchTerm.toLowerCase()) || 
      log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.category.toLowerCase().includes(searchTerm.toLowerCase());
    
    if (logFilter === "ALL") return matchesSearch;
    return matchesSearch && log.level === logFilter;
  });

  return (
    <div className="flex flex-col gap-6 font-sans">
      
      {/* Tab Navigation Menu */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-200 pb-3 bg-white px-4 py-2.5 rounded-xl shadow-sm">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-zinc-950 text-white rounded-lg">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-zinc-900 leading-none">AegisID Admin Console</h1>
            <p className="text-[10px] text-zinc-500 mt-1">Enterprise Directory Federated SSO Control Hub</p>
          </div>
        </div>

        <div className="flex items-center gap-1 bg-zinc-100 p-1 rounded-lg text-xs font-semibold">
          <button 
            onClick={() => setActiveTab("dashboard")} 
            className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === "dashboard" ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-600 hover:text-zinc-900"}`}
          >
            Dashboard
          </button>
          <button 
            onClick={() => setActiveTab("users")} 
            className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === "users" ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-600 hover:text-zinc-900"}`}
          >
            User Directory
          </button>
          <button 
            onClick={() => setActiveTab("threats")} 
            className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === "threats" ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-600 hover:text-zinc-900"}`}
          >
            Threat Intel
            {threatCount > 0 && (
              <span className="ml-1 px-1.5 py-0.5 bg-rose-500 text-white rounded-full text-[9px] font-bold animate-pulse">
                {threatCount}
              </span>
            )}
          </button>
          <button 
            onClick={() => setActiveTab("apps")} 
            className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === "apps" ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-600 hover:text-zinc-900"}`}
          >
            SSO Apps
          </button>
          <button 
            onClick={() => setActiveTab("logs")} 
            className={`px-3 py-1.5 rounded-md transition-colors ${activeTab === "logs" ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-600 hover:text-zinc-900"}`}
          >
            Audit Trail
          </button>
        </div>

        <button 
          onClick={onRefresh}
          className="p-2 hover:bg-zinc-150 text-zinc-600 hover:text-zinc-900 rounded-lg border border-zinc-200 transition-colors bg-zinc-50 focus:outline-none"
          title="Force Database Synchronize"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Overview Dashboard Tab */}
      {activeTab === "dashboard" && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 animate-fade-in">
          
          {/* Key Metric Blocks */}
          <div className="md:col-span-12 grid grid-cols-2 lg:grid-cols-4 gap-4">
            
            <div className="bg-white border border-zinc-200 p-5 rounded-2xl flex items-center justify-between shadow-sm">
              <div>
                <span className="text-[10px] uppercase text-zinc-500 font-mono tracking-wider font-semibold">Active Directories</span>
                <h3 className="text-2xl font-bold text-zinc-900 mt-1">{activeCount}</h3>
                <span className="text-[9px] text-emerald-500 font-medium flex items-center gap-1 mt-1">
                  ● LDAP Sync Normal
                </span>
              </div>
              <div className="p-3 bg-emerald-50 text-emerald-600 rounded-xl">
                <Users className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-white border border-zinc-200 p-5 rounded-2xl flex items-center justify-between shadow-sm">
              <div>
                <span className="text-[10px] uppercase text-zinc-500 font-mono tracking-wider font-semibold">Suspended Users</span>
                <h3 className="text-2xl font-bold text-amber-600 mt-1">{suspendedCount}</h3>
                <span className="text-[9px] text-zinc-500 mt-1 block">Secured accounts</span>
              </div>
              <div className="p-3 bg-amber-50 text-amber-600 rounded-xl">
                <UserX className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-white border border-zinc-200 p-5 rounded-2xl flex items-center justify-between shadow-sm">
              <div>
                <span className="text-[10px] uppercase text-zinc-500 font-mono tracking-wider font-semibold">Threat Incidents</span>
                <h3 className="text-2xl font-bold text-rose-600 mt-1">{threatCount}</h3>
                <span className="text-[9px] text-zinc-500 mt-1 block">Active mitigation rules</span>
              </div>
              <div className="p-3 bg-rose-50 text-rose-600 rounded-xl">
                <ShieldAlert className="w-5 h-5" />
              </div>
            </div>

            <div className="bg-white border border-zinc-200 p-5 rounded-2xl flex items-center justify-between shadow-sm">
              <div>
                <span className="text-[10px] uppercase text-zinc-500 font-mono tracking-wider font-semibold">Federated Apps</span>
                <h3 className="text-2xl font-bold text-indigo-600 mt-1">{apps.length}</h3>
                <span className="text-[9px] text-emerald-500 font-medium flex items-center gap-1 mt-1">
                  ● 100% SAML/OIDC uptime
                </span>
              </div>
              <div className="p-3 bg-indigo-50 text-indigo-600 rounded-xl">
                <Key className="w-5 h-5" />
              </div>
            </div>

          </div>

          {/* Real-time Authorization Telemetry Charts */}
          <div className="col-span-12 xl:col-span-8 bg-white border border-zinc-200 p-6 rounded-2xl shadow-sm flex flex-col gap-4">
            <div>
              <h3 className="text-xs font-bold text-zinc-800 uppercase tracking-wider">Access Attempt & Threat Interception Telemetry</h3>
              <p className="text-[11px] text-zinc-500 mt-0.5">Real-time authentication monitoring, compiled from active directory edge proxies.</p>
            </div>
            <div className="h-[220px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorSuccess" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="name" stroke="#888888" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#888888" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: "#18181b", border: "none", borderRadius: "8px", fontSize: "11px", color: "#fff" }} />
                  <Area type="monotone" dataKey="Successful" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#colorSuccess)" name="Successful SSO" />
                  <Area type="monotone" dataKey="ThreatBlocked" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#colorThreat)" name="Intercepted Threats" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Quick Threat Trigger Panel */}
          <div className="col-span-12 xl:col-span-4 bg-white border border-zinc-200 p-6 rounded-2xl shadow-sm flex flex-col justify-between gap-4">
            <div>
              <h3 className="text-xs font-bold text-zinc-800 uppercase tracking-wider">Threat Injection Simulator</h3>
              <p className="text-[11px] text-zinc-500 mt-0.5">Test real-time alert trigger mechanisms and active remediation systems.</p>
            </div>

            <div className="flex flex-col gap-3">
              <button 
                onClick={() => triggerMockThreat("impossible_travel")}
                className="py-2.5 px-4 bg-zinc-50 hover:bg-zinc-150 border border-zinc-200 rounded-xl text-left flex items-start gap-3 transition-all font-sans focus:outline-none"
              >
                <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-[11px] font-bold text-zinc-800 uppercase tracking-wider">Impossible Travel Alert</h4>
                  <p className="text-[10px] text-zinc-500 mt-0.5">Mock login from Singapore concurrently with CA activity.</p>
                </div>
              </button>

              <button 
                onClick={() => triggerMockThreat("api_abuse")}
                className="py-2.5 px-4 bg-zinc-50 hover:bg-zinc-150 border border-zinc-200 rounded-xl text-left flex items-start gap-3 transition-all font-sans focus:outline-none"
              >
                <ShieldAlert className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-[11px] font-bold text-zinc-800 uppercase tracking-wider">Foreign API Key Abuse</h4>
                  <p className="text-[10px] text-zinc-500 mt-0.5">Mock API request burst targeting service credentials.</p>
                </div>
              </button>
            </div>

            <div className="p-3 bg-indigo-50 border border-indigo-150 rounded-xl text-[10px] text-indigo-700 leading-normal flex items-start gap-2">
              <Server className="w-4 h-4 shrink-0 text-indigo-500 mt-0.5" />
              <span>Interventions synchronize instantly with the side-by-side authenticator emulator screen.</span>
            </div>
          </div>

          {/* Critical Threats Real-Time Feed */}
          <div className="md:col-span-12 bg-white border border-zinc-200 rounded-2xl shadow-sm p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-xs font-bold text-zinc-800 uppercase tracking-wider">Active Threat Mitigations</h3>
                <p className="text-[11px] text-zinc-500 mt-0.5">System blocklists and real-time security events requiring administrator approval.</p>
              </div>
              <button 
                onClick={() => setActiveTab("threats")}
                className="text-[10px] text-indigo-600 hover:text-indigo-800 uppercase tracking-wider font-bold"
              >
                Inspect Intel Feed →
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-zinc-600">
                <thead>
                  <tr className="border-b border-zinc-100 text-[10px] text-zinc-400 uppercase tracking-wider">
                    <th className="py-2.5">Severity</th>
                    <th className="py-2.5">Threat Event</th>
                    <th className="py-2.5">Target Account</th>
                    <th className="py-2.5">Network IP Location</th>
                    <th className="py-2.5">Mitigation Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100 font-medium">
                  {threats.slice(0, 3).map((threat) => (
                    <tr key={threat.id} className="hover:bg-zinc-50/50">
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                          threat.severity === "CRITICAL" ? "bg-rose-100 text-rose-700" :
                          threat.severity === "HIGH" ? "bg-amber-100 text-amber-700" : "bg-zinc-100 text-zinc-700"
                        }`}>
                          {threat.severity}
                        </span>
                      </td>
                      <td className="py-3">
                        <div className="font-semibold text-zinc-800">{threat.threatType}</div>
                        <div className="text-[9px] text-zinc-500">{threat.description}</div>
                      </td>
                      <td className="py-3 font-mono text-[10px]">{threat.targetedUser}</td>
                      <td className="py-3">
                        <span className="font-mono">{threat.sourceIp}</span>
                        <span className="text-zinc-500 text-[10px] ml-1">({threat.location})</span>
                      </td>
                      <td className="py-3">
                        {threat.status === "Remediated" ? (
                          <span className="text-emerald-600 flex items-center gap-1.5 text-[11px] font-semibold">
                            <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
                            Remediated
                          </span>
                        ) : (
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleRemediate(threat.id, "Suspend Targeted Account & Block Subnet")}
                              disabled={remediatingId === threat.id}
                              className="px-2 py-1 bg-zinc-950 hover:bg-zinc-850 text-white rounded text-[10px] transition-colors"
                            >
                              Block Account
                            </button>
                            <button
                              onClick={() => compileIncidentReport(threat.id)}
                              className="px-2 py-1 bg-zinc-100 hover:bg-zinc-200 border border-zinc-200 text-zinc-700 rounded text-[10px] transition-colors flex items-center gap-1 font-mono"
                            >
                              <Cpu className="w-3 h-3 text-indigo-500" />
                              AI Compliance
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* User Directory Tab */}
      {activeTab === "users" && (
        <div className="bg-white border border-zinc-200 rounded-2xl shadow-sm p-6 animate-fade-in">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-100 pb-4 mb-4">
            <div>
              <h3 className="text-base font-bold text-zinc-900">Enterprise Access Directory</h3>
              <p className="text-xs text-zinc-500 mt-0.5">Automated user provisioning (SCIM) and SAML-federated permission management.</p>
            </div>

            <button
              onClick={() => setShowProvisionModal(true)}
              className="py-2 px-4 bg-zinc-950 hover:bg-zinc-850 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow transition-all focus:outline-none"
            >
              <UserPlus className="w-4 h-4" />
              Provision New Identity
            </button>
          </div>

          {/* SCIM Provisioning Modal Dialog */}
          {showProvisionModal && (
            <div className="mb-6 p-5 bg-zinc-50 border border-zinc-200 rounded-xl">
              <h4 className="text-xs font-bold text-zinc-800 uppercase tracking-wider mb-3">SCIM Directory Provisioning Wizard</h4>
              
              {provisionSuccess ? (
                <div className="p-4 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg text-xs font-semibold flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-emerald-500 animate-bounce" />
                  <span>Successful identity provisioning handshake completed with corporate Active Directory database. Synced applications list updated.</span>
                </div>
              ) : (
                <form onSubmit={handleProvisionSubmit} className="grid grid-cols-1 md:grid-cols-12 gap-4">
                  <div className="md:col-span-3">
                    <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">Full Name</label>
                    <input
                      type="text"
                      required
                      value={provisionName}
                      onChange={(e) => setProvisionName(e.target.value)}
                      placeholder="Jane Doe"
                      className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950"
                    />
                  </div>
                  
                  <div className="md:col-span-3">
                    <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">Email Address</label>
                    <input
                      type="email"
                      required
                      value={provisionEmail}
                      onChange={(e) => setProvisionEmail(e.target.value)}
                      placeholder="jane.doe@enterprise.com"
                      className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950"
                    />
                  </div>

                  <div className="md:col-span-2">
                    <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">Federated Role</label>
                    <select
                      value={provisionRole}
                      onChange={(e) => setProvisionRole(e.target.value as any)}
                      className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950"
                    >
                      <option value="Employee">Employee</option>
                      <option value="Admin">Admin</option>
                      <option value="Security Engineer">Security Engineer</option>
                      <option value="Compliance Auditor">Compliance Auditor</option>
                    </select>
                  </div>

                  <div className="md:col-span-2">
                    <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">MFA Security Option</label>
                    <select
                      value={provisionMfa}
                      onChange={(e) => setProvisionMfa(e.target.value as any)}
                      className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950"
                    >
                      <option value="TOTP">TOTP Authenticator</option>
                      <option value="Biometric">Biometric (Face/TouchID)</option>
                      <option value="SMS">SMS Verification</option>
                      <option value="Push">Remote Push</option>
                    </select>
                  </div>

                  <div className="md:col-span-2 flex items-end">
                    <button
                      type="submit"
                      className="w-full py-2 bg-zinc-950 hover:bg-zinc-850 text-white rounded-md text-xs font-semibold transition-colors"
                    >
                      Issue SCIM Sync
                    </button>
                  </div>
                </form>
              )}
            </div>
          )}

          {/* Per-User Application Assignment Panel */}
          {manageAppsUserId && (() => {
            const mu = users.find((u) => u.id === manageAppsUserId);
            if (!mu) return null;
            return (
              <div className="mb-6 p-5 bg-zinc-50 border border-zinc-200 rounded-xl">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h4 className="text-xs font-bold text-zinc-800 uppercase tracking-wider flex items-center gap-1.5">
                      <Key className="w-3.5 h-3.5 text-indigo-500" />
                      Application Access — {mu.fullName}
                    </h4>
                    <p className="text-[10px] text-zinc-500 mt-0.5">Toggle entitlements below. Changes appear in the user's MyApps launcher immediately.</p>
                  </div>
                  <button onClick={() => setManageAppsUserId(null)} className="p-1 text-zinc-400 hover:text-zinc-700 rounded" title="Close">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {apps.map((app) => {
                    const on = mu.assignedApps.includes(app.id);
                    return (
                      <button
                        key={app.id}
                        onClick={() => handleToggleAssign(mu.id, app.id, !on)}
                        className={`px-3 py-1.5 rounded-lg text-[11px] font-semibold border flex items-center gap-1.5 transition-colors ${
                          on
                            ? "bg-emerald-50 border-emerald-300 text-emerald-800 hover:bg-emerald-100"
                            : "bg-white border-zinc-200 text-zinc-500 hover:border-zinc-400 hover:text-zinc-800"
                        }`}
                      >
                        {on ? <CheckCircle className="w-3.5 h-3.5 text-emerald-500" /> : <Plus className="w-3.5 h-3.5" />}
                        {app.name}
                        <span className="text-[8px] font-mono text-zinc-400">{app.protocol}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })()}

          {/* Directory Spreadsheet Grid */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-zinc-600">
              <thead>
                <tr className="border-b border-zinc-100 text-[10px] text-zinc-400 uppercase tracking-wider">
                  <th className="py-2.5">User Identity</th>
                  <th className="py-2.5">Role / Dept</th>
                  <th className="py-2.5">Security Policies</th>
                  <th className="py-2.5">Account Status</th>
                  <th className="py-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 font-medium">
                {users.map((user) => (
                  <tr key={user.id} className="hover:bg-zinc-50/50">
                    <td className="py-3">
                      <div className="font-semibold text-zinc-900">{user.fullName}</div>
                      <div className="text-[10px] text-zinc-400 font-mono mt-0.5">{user.email}</div>
                    </td>
                    <td className="py-3">
                      <div className="font-semibold text-zinc-800">{user.role}</div>
                      <div className="text-[10px] text-zinc-500 uppercase font-mono mt-0.5">{user.department}</div>
                    </td>
                    <td className="py-3">
                      <div className="flex flex-wrap gap-1.5">
                        <span className="px-1.5 py-0.5 bg-zinc-100 text-zinc-600 rounded text-[9px] font-mono">
                          MFA: {user.mfaType}
                        </span>
                        {user.mfaEnabled ? (
                          <span className="px-1.5 py-0.5 bg-emerald-50 text-emerald-700 rounded text-[9px] font-semibold border border-emerald-100">
                            MFA On
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 bg-rose-50 text-rose-700 rounded text-[9px] font-semibold border border-rose-100">
                            MFA Required
                          </span>
                        )}
                        {user.biometricRegistered && (
                          <span className="px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded text-[9px] font-semibold border border-blue-100">
                            Biometric Verified
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                        user.status === "Active" ? "bg-emerald-100 text-emerald-700" :
                        user.status === "Suspended" ? "bg-amber-100 text-amber-700" : 
                        user.status === "Offboarded" ? "bg-rose-100 text-rose-700" : "bg-zinc-100 text-zinc-700"
                      }`}>
                        {user.status}
                      </span>
                    </td>
                    <td className="py-3 text-right">
                      <div className="flex justify-end gap-2">
                        {user.status !== "Offboarded" && (
                          <button
                            onClick={() => setManageAppsUserId(manageAppsUserId === user.id ? null : user.id)}
                            className={`p-1 rounded transition-colors ${
                              manageAppsUserId === user.id ? "bg-indigo-100 text-indigo-700" : "text-indigo-600 hover:bg-indigo-50"
                            }`}
                            title="Manage application access"
                          >
                            <Key className="w-4 h-4" />
                          </button>
                        )}
                        {user.status === "Active" && (
                          <button
                            onClick={() => handleUpdateUserStatus(user.id, "Suspended")}
                            className="p-1 text-amber-600 hover:bg-amber-50 rounded transition-colors"
                            title="Suspend Account"
                          >
                            <UserX className="w-4 h-4" />
                          </button>
                        )}
                        {user.status === "Suspended" && (
                          <button
                            onClick={() => handleUpdateUserStatus(user.id, "Active")}
                            className="p-1 text-emerald-600 hover:bg-emerald-50 rounded transition-colors"
                            title="Activate Account"
                          >
                            <UserCheck className="w-4 h-4" />
                          </button>
                        )}
                        {user.status !== "Offboarded" && (
                          <button
                            onClick={() => handleDeprovision(user.id)}
                            className="p-1 text-rose-600 hover:bg-rose-50 rounded transition-colors"
                            title="Offboard / Deprovision User"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                        {user.status === "Offboarded" && (
                          <span className="text-[10px] text-zinc-400 italic">SCIM Deprovisioned</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Intelligence Feed & AI Report */}
      {activeTab === "threats" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 animate-fade-in">
          
          {/* Threats List Panel */}
          <div className="col-span-12 xl:col-span-5 bg-white border border-zinc-200 p-6 rounded-2xl shadow-sm flex flex-col gap-4">
            <div>
              <h3 className="text-base font-bold text-zinc-900">Security Threat Intelligence</h3>
              <p className="text-xs text-zinc-500 mt-0.5">Real-time alerts processed by internal anomaly filters.</p>
            </div>

            <div className="flex flex-col gap-3">
              {threats.map((threat) => (
                <div 
                  key={threat.id} 
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    activeReportThreatId === threat.id 
                      ? "bg-zinc-50 border-zinc-400" 
                      : "bg-white hover:bg-zinc-50/50 border-zinc-200"
                  }`}
                  onClick={() => compileIncidentReport(threat.id)}
                >
                  <div className="flex justify-between items-start gap-2">
                    <span className={`px-2 py-0.5 rounded text-[8px] font-bold ${
                      threat.severity === "CRITICAL" ? "bg-rose-100 text-rose-700 animate-pulse" :
                      threat.severity === "HIGH" ? "bg-amber-100 text-amber-700" : "bg-zinc-100 text-zinc-700"
                    }`}>
                      {threat.severity}
                    </span>
                    <span className="text-[9px] text-zinc-400 font-mono">{threat.timestamp.slice(11, 16)} UTC</span>
                  </div>

                  <h4 className="text-xs font-bold text-zinc-800 uppercase tracking-tight mt-2">{threat.threatType}</h4>
                  <p className="text-[11px] text-zinc-500 mt-1">{threat.description}</p>
                  
                  <div className="mt-3 flex items-center justify-between text-[10px] text-zinc-600 font-mono">
                    <span className="flex items-center gap-1">
                      <MapPin className="w-3 h-3 text-zinc-400" />
                      {threat.location}
                    </span>
                    <span>User: {threat.targetedUser}</span>
                  </div>

                  {threat.status !== "Remediated" && (
                    <div className="mt-3 flex gap-2 justify-end border-t border-zinc-100 pt-2.5">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRemediate(threat.id, "Revoke OpenID Connect tokens & block IP");
                        }}
                        className="px-2 py-1 bg-rose-50 hover:bg-rose-100 text-rose-700 rounded text-[9px] font-semibold border border-rose-200"
                      >
                        Enforce Suspend
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* AI Security Incident Compliance Report Compiler */}
          <div className="col-span-12 xl:col-span-7 bg-white border border-zinc-200 p-6 rounded-2xl shadow-sm flex flex-col gap-4">
            
            <div className="border-b border-zinc-100 pb-3 flex items-center justify-between">
              <div>
                <h3 className="text-xs font-bold text-zinc-800 uppercase tracking-wider flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-indigo-500" />
                  AI Security compliance Report generator
                </h3>
                <p className="text-[11px] text-zinc-500 mt-0.5">Generates instant SOC 2 and NIST-compliant digital incident documentation for IT compliance audits.</p>
              </div>

              {geminiReport && (
                <button
                  onClick={handleExportReport}
                  className="px-2.5 py-1 bg-zinc-950 hover:bg-zinc-850 text-white rounded-lg text-[10px] font-mono flex items-center gap-1 focus:outline-none"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export Markdown
                </button>
              )}
            </div>

            {/* Compiled Report Window */}
            {compilingReport ? (
              <div className="flex-1 flex flex-col justify-center items-center py-12 text-center text-zinc-500">
                <RefreshCw className="w-8 h-8 text-indigo-500 animate-spin mb-3" />
                <p className="text-xs font-bold uppercase tracking-widest text-zinc-700">Connecting to Gemini AI Engine...</p>
                <p className="text-[10px] text-zinc-400 mt-1 max-w-xs">Correlating directory logs, auditing cryptography checksums, and building NIST-compliant report format.</p>
              </div>
            ) : geminiReport ? (
              <div className="flex-1 overflow-y-auto max-h-[440px] border border-zinc-150 rounded-xl bg-zinc-950 text-zinc-100 p-5 font-mono text-[11px] leading-relaxed select-text">
                <div className="flex items-center justify-between mb-3 border-b border-zinc-800 pb-2">
                  <span className="text-[9px] text-emerald-400 font-bold uppercase tracking-widest flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5" />
                    {aiGenerated ? "Real-time Gemini Model output active" : "Static compliance engine fallback output"}
                  </span>
                  <span className="text-[8px] bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded">NIST SP 800-61</span>
                </div>
                <div className="whitespace-pre-wrap whitespace-pre-line prose prose-invert max-w-none text-zinc-300">
                  {geminiReport}
                </div>
              </div>
            ) : (
              <div className="flex-1 border-2 border-dashed border-zinc-200 rounded-xl flex flex-col justify-center items-center p-8 text-center min-h-[300px] bg-zinc-50/50">
                <FileText className="w-10 h-10 text-zinc-300 mb-2" />
                <p className="text-xs font-bold uppercase text-zinc-700 tracking-wider">Awaiting Incident Selection</p>
                <p className="text-xs text-zinc-500 mt-1 max-w-sm">
                  Select any threat on the left panel to trigger automatic directory audit log correlation and generate a legal incident response draft.
                </p>
              </div>
            )}

          </div>

        </div>
      )}

      {/* SSO Applications Configuration Tab */}
      {activeTab === "apps" && (
        <div className="bg-white border border-zinc-200 p-6 rounded-2xl shadow-sm animate-fade-in flex flex-col gap-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-zinc-900">Enterprise Applications Directory</h3>
              <p className="text-xs text-zinc-500 mt-0.5">Integrate Slack, AWS, Zoom, and Salesforce with SSO (SAML 2.0 / OIDC) and SCIM synchronization protocols.</p>
            </div>
            <button
              onClick={() => { setShowAppForm(!showAppForm); setAppRegResult(null); setAppRegError(null); }}
              className="py-2 px-4 bg-zinc-950 hover:bg-zinc-800 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow transition-all focus:outline-none"
            >
              <Plus className="w-4 h-4" />
              Register New App
            </button>
          </div>

          {/* One-time credential banner (OIDC secrets are never shown again) */}
          {appRegResult && (
            <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800">
              <div className="font-bold flex items-center gap-1.5 uppercase tracking-wider">
                <CheckCircle className="w-4 h-4 text-emerald-500" />
                {appRegResult.name} registered — federation trust established
              </div>
              {appRegResult.clientId && (
                <div className="mt-2 font-mono text-[11px] flex flex-col gap-1">
                  <span>client_id: <strong className="select-all">{appRegResult.clientId}</strong></span>
                  <span className="flex items-center gap-1.5">
                    client_secret: <strong className="select-all">{appRegResult.issuedSecret}</strong>
                    <button onClick={() => navigator.clipboard?.writeText(appRegResult.issuedSecret || "")} className="text-emerald-600 hover:text-emerald-800" title="Copy secret">
                      <Copy className="w-3 h-3" />
                    </button>
                  </span>
                  <span className="text-[10px] text-emerald-600">Store the secret now — it is shown only once and never re-exposed by the API.</span>
                </div>
              )}
            </div>
          )}

          {/* Registration Form */}
          {showAppForm && (
            <div className="p-5 bg-zinc-50 border border-zinc-200 rounded-xl">
              <h4 className="text-xs font-bold text-zinc-800 uppercase tracking-wider mb-3">Federation Trust Registration</h4>
              <form onSubmit={handleRegisterApp} className="grid grid-cols-1 md:grid-cols-12 gap-4">
                <div className="md:col-span-3">
                  <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">App Name</label>
                  <input type="text" required value={appName} onChange={(e) => setAppName(e.target.value)} placeholder="Zoom Enterprise"
                    className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950" />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">Protocol</label>
                  <select value={appProtocol} onChange={(e) => setAppProtocol(e.target.value as any)}
                    className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950">
                    <option value="SAML 2.0">SAML 2.0</option>
                    <option value="OIDC">OIDC</option>
                  </select>
                </div>
                <div className="md:col-span-4">
                  <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">Entity ID / Audience</label>
                  <input type="text" required value={appEntityId} onChange={(e) => setAppEntityId(e.target.value)} placeholder="https://zoom.us/saml2/metadata"
                    className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950 font-mono" />
                </div>
                <div className="md:col-span-3">
                  <label className="block text-[10px] uppercase font-bold text-zinc-500 tracking-wider mb-1">ACS / SSO URL (optional)</label>
                  <input type="text" value={appSsoUrl} onChange={(e) => setAppSsoUrl(e.target.value)} placeholder="auto-generated if empty"
                    className="w-full text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950 font-mono" />
                </div>
                <div className="md:col-span-4 flex items-center gap-2">
                  <button type="button" onClick={() => setAppScim(!appScim)} className="focus:outline-none" title="Toggle SCIM provisioning">
                    {appScim ? <ToggleRight className="w-6 h-6 text-emerald-500" /> : <ToggleLeft className="w-6 h-6 text-zinc-300" />}
                  </button>
                  <span className="text-[10px] text-zinc-600 uppercase tracking-wider font-semibold">SCIM auto-provisioning</span>
                  {appScim && (
                    <input type="text" value={appScimEndpoint} onChange={(e) => setAppScimEndpoint(e.target.value)} placeholder="https://api.app.com/scim/v2"
                      className="flex-1 text-xs p-2 bg-white border border-zinc-200 rounded-md outline-none focus:ring-1 focus:ring-zinc-950 font-mono" />
                  )}
                </div>
                <div className="md:col-span-8 flex items-end justify-end gap-2">
                  {appRegError && <span className="text-[11px] text-rose-600 font-semibold self-center mr-auto">{appRegError}</span>}
                  <button type="button" onClick={() => setShowAppForm(false)}
                    className="py-2 px-4 bg-white hover:bg-zinc-100 border border-zinc-200 text-zinc-600 rounded-md text-xs font-semibold transition-colors">
                    Cancel
                  </button>
                  <button type="submit"
                    className="py-2 px-4 bg-zinc-950 hover:bg-zinc-800 text-white rounded-md text-xs font-semibold transition-colors">
                    Establish Federation Trust
                  </button>
                </div>
              </form>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {apps.map((app) => (
              <div key={app.id} className="border border-zinc-150 rounded-2xl p-5 hover:shadow-sm transition-all flex flex-col justify-between gap-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 bg-zinc-950 text-white rounded-xl uppercase font-bold text-xs font-mono">
                      {app.name.slice(0, 2)}
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-zinc-900 uppercase tracking-tight">{app.name}</h4>
                      <span className="text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-100 px-1.5 py-0.5 rounded font-mono mt-1 inline-block">
                        {app.protocol}
                      </span>
                    </div>
                  </div>

                  <span className="text-[9px] text-emerald-600 font-mono font-bold flex items-center gap-1 uppercase">
                    ● ACTIVE
                  </span>
                </div>

                <div className="bg-zinc-50 rounded-xl p-3 text-[11px] font-mono text-zinc-600 flex flex-col gap-2 border border-zinc-150">
                  <div className="flex justify-between">
                    <span className="text-zinc-400">Entity ID:</span>
                    <span className="text-zinc-800 text-right truncate max-w-[180px]">{app.entityId}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-400">ACS / SSO URL:</span>
                    <span className="text-zinc-800 text-right truncate max-w-[180px]">{app.ssoUrl}</span>
                  </div>
                  {app.scimEnabled && (
                    <div className="flex justify-between border-t border-zinc-150 pt-1.5 mt-0.5">
                      <span className="text-zinc-400">SCIM Endpoint:</span>
                      <span className="text-zinc-800 text-right truncate max-w-[180px] font-semibold text-emerald-600">Enabled</span>
                    </div>
                  )}
                </div>

                <div className="flex justify-between items-center border-t border-zinc-100 pt-3">
                  <div className="flex items-center gap-2">
                    {app.scimEnabled ? <ToggleRight className="w-5 h-5 text-emerald-500 cursor-pointer" /> : <ToggleLeft className="w-5 h-5 text-zinc-300 cursor-pointer" />}
                    <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-semibold">SCIM Onboarding Sync</span>
                  </div>

                  <div className="flex items-center gap-2.5">
                    <span className="text-[9px] text-zinc-400 font-mono">
                      {users.filter((u) => u.assignedApps.includes(app.id)).length} users
                    </span>
                    {!app.launchUrl && (
                      <button
                        onClick={() => handleRemoveApp(app.id, app.name)}
                        className="p-1 text-rose-500 hover:bg-rose-50 rounded transition-colors"
                        title="Deregister application"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Compliance Audit Logs Tab */}
      {activeTab === "logs" && (
        <div className="bg-white border border-zinc-200 rounded-2xl shadow-sm p-6 animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-100 pb-4">
            <div>
              <h3 className="text-base font-bold text-zinc-900">Federated Directory Audit Log Trail</h3>
              <p className="text-xs text-zinc-500 mt-0.5">SOC 2 compliant, read-only immutable identity audit stream.</p>
            </div>

            <div className="flex items-center gap-3">
              <select
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
                className="text-xs p-2 bg-white border border-zinc-200 rounded-lg outline-none focus:ring-1 focus:ring-zinc-950 font-medium"
              >
                <option value="ALL">All Severities</option>
                <option value="INFO">INFO Only</option>
                <option value="WARN">WARN Only</option>
                <option value="CRITICAL">CRITICAL Only</option>
              </select>

              <div className="relative">
                <input
                  type="text"
                  placeholder="Search log trail..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="text-xs p-2 bg-white border border-zinc-200 rounded-lg pl-8 outline-none focus:ring-1 focus:ring-zinc-950"
                />
                <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-zinc-600 font-mono">
              <thead>
                <tr className="border-b border-zinc-100 text-[10px] text-zinc-400 uppercase tracking-wider">
                  <th className="py-2.5">Timestamp</th>
                  <th className="py-2.5">Category</th>
                  <th className="py-2.5">Level</th>
                  <th className="py-2.5">Audit Message</th>
                  <th className="py-2.5">IP Location</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 font-medium">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-zinc-50/50">
                    <td className="py-2.5 text-zinc-500 whitespace-nowrap">{log.timestamp.slice(0, 19).replace("T", " ")}</td>
                    <td className="py-2.5">
                      <span className="px-1.5 py-0.5 bg-zinc-100 text-zinc-700 rounded text-[9px] uppercase font-bold">
                        {log.category}
                      </span>
                    </td>
                    <td className="py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                        log.level === "CRITICAL" ? "bg-rose-100 text-rose-700" :
                        log.level === "WARN" ? "bg-amber-100 text-amber-700" : "bg-zinc-100 text-zinc-700"
                      }`}>
                        {log.level}
                      </span>
                    </td>
                    <td className="py-2.5 text-zinc-800 font-sans max-w-sm leading-normal">
                      {log.message}
                      <span className="block text-[10px] text-zinc-500 font-mono mt-0.5">Subject: {log.user}</span>
                    </td>
                    <td className="py-2.5 text-zinc-500 text-[10px]">
                      <span>{log.ipAddress}</span>
                      <span className="block text-[9px] mt-0.5 truncate max-w-[120px]">{log.location}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
