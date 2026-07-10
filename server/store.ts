import fs from "fs";
import path from "path";
import crypto from "crypto";

// ---------------------------------------------------------------------------
// Shared persistence layer for AegisID.
//
// This is the single source of truth for the local JSON "database" and the
// domain types. Both the simulated routes (server.ts) and the REAL integration
// routes (totp / webauthn / oidc) read and write through here so everything
// lands in the same database.json.
// ---------------------------------------------------------------------------

// --- Real security material stored per user (NEVER sent to the browser) ------
export interface TotpEnrollment {
  secret: string; // base32 shared secret (RFC 6238)
  verified: boolean; // becomes true once the user confirms a code
  createdAt: string;
}

export interface PasskeyRecord {
  id: string; // credential ID (base64url)
  publicKey: string; // COSE public key, base64-encoded
  counter: number; // signature counter (replay protection)
  transports?: string[];
  label: string;
  createdAt: string;
}

export interface User {
  id: string;
  username: string;
  fullName: string;
  email: string;
  role: "Admin" | "Security Engineer" | "Compliance Auditor" | "Employee";
  status: "Active" | "Suspended" | "Pending Onboarding" | "Offboarded";
  assignedApps: string[];
  mfaEnabled: boolean;
  mfaType: "TOTP" | "Biometric" | "SMS" | "Push";
  biometricRegistered: boolean;
  createdAt: string;
  department: string;
  lastLogin: string;
  ipAddress: string;

  // --- Real integration state (secret; stripped by sanitizeDb) ---
  totp?: TotpEnrollment;
  passkeys?: PasskeyRecord[];
  webauthnChallenge?: string; // transient challenge during register/auth
  passwordHash?: string; // scrypt "salt:hash" for the primary login factor
}

export interface SSOApp {
  id: string;
  name: string;
  icon: string;
  protocol: "SAML 2.0" | "OIDC";
  entityId: string;
  ssoUrl: string;
  certificate?: string;
  clientId?: string;
  clientSecret?: string;
  scimEnabled: boolean;
  scimEndpoint?: string;
  // Set on apps that are REAL: launching opens this URL (the local sample SP)
  // and runs an actual SAML SP-initiated SSO flow instead of the simulation.
  launchUrl?: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  level: "INFO" | "WARN" | "CRITICAL";
  category: "AUTH" | "MFA" | "PROVISIONING" | "SECURITY_INCIDENT" | "SSO" | "SYSTEM";
  message: string;
  user: string;
  ipAddress: string;
  location: string;
}

export interface ThreatIncident {
  id: string;
  timestamp: string;
  threatType: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  sourceIp: string;
  location: string;
  targetedUser: string;
  status: "Active" | "Investigating" | "Remediated" | "Suppressed";
  description: string;
}

export interface Database {
  users: User[];
  apps: SSOApp[];
  logs: AuditLog[];
  threats: ThreatIncident[];
  // IDs of one-time migrations already applied to this database file.
  migrations?: string[];
}

const DB_FILE = path.join(process.cwd(), "database.json");

// --- Seed data --------------------------------------------------------------
export const DEFAULT_USERS: User[] = [
  {
    id: "u-1",
    username: "admin.cyber",
    fullName: "Alex Rivera",
    email: "alex.rivera@enterprise.io",
    role: "Admin",
    status: "Active",
    assignedApps: ["app-1", "app-2", "app-3", "app-4"],
    mfaEnabled: true,
    mfaType: "Biometric",
    biometricRegistered: true,
    createdAt: "2026-01-10T08:30:00Z",
    department: "SecOps",
    lastLogin: "2026-07-04T19:00:00Z",
    ipAddress: "192.168.1.52",
  },
  {
    id: "u-2",
    username: "sarah.compliance",
    fullName: "Sarah Jenkins",
    email: "sarah.j@enterprise.io",
    role: "Compliance Auditor",
    status: "Active",
    assignedApps: ["app-1", "app-3"],
    mfaEnabled: true,
    mfaType: "TOTP",
    biometricRegistered: false,
    createdAt: "2026-02-14T09:15:00Z",
    department: "Risk Management",
    lastLogin: "2026-07-04T17:45:00Z",
    ipAddress: "192.168.2.11",
  },
  {
    id: "u-3",
    username: "dev.marcus",
    fullName: "Marcus Chen",
    email: "marcus.c@enterprise.io",
    role: "Employee",
    status: "Active",
    assignedApps: ["app-1", "app-2"],
    mfaEnabled: true,
    mfaType: "Push",
    biometricRegistered: true,
    createdAt: "2026-03-20T10:00:00Z",
    department: "Engineering",
    lastLogin: "2026-07-04T14:20:00Z",
    ipAddress: "172.16.5.90",
  },
  {
    id: "u-4",
    username: "onboarding.jane",
    fullName: "Jane Doe",
    email: "jane.doe@enterprise.io",
    role: "Employee",
    status: "Pending Onboarding",
    assignedApps: [],
    mfaEnabled: false,
    mfaType: "SMS",
    biometricRegistered: false,
    createdAt: "2026-07-04T12:00:00Z",
    department: "Product",
    lastLogin: "Never",
    ipAddress: "N/A",
  },
];

export const DEFAULT_APPS: SSOApp[] = [
  {
    id: "app-1",
    name: "Slack Enterprise",
    icon: "Slack",
    protocol: "SAML 2.0",
    entityId: "https://enterprise.slack.com/saml2/metadata",
    ssoUrl: "https://aegisid.enterprise.com/sso/saml/slack",
    certificate: "MIIE0DCCA7igAwIBAgIQC...[AegisID Signed SAML Public Certificate Key]...===",
    scimEnabled: true,
    scimEndpoint: "https://api.slack.com/scim/v2/AegisIDSync",
  },
  {
    id: "app-2",
    name: "Amazon Web Services",
    icon: "Aws",
    protocol: "SAML 2.0",
    entityId: "urn:amazon:webservices",
    ssoUrl: "https://aegisid.enterprise.com/sso/saml/aws",
    certificate: "MIIE0DCCA7igAwIBAgIQC...[AegisID Signed SAML Public Certificate Key]...===",
    scimEnabled: false,
  },
  {
    id: "app-3",
    name: "Salesforce Cloud",
    icon: "Salesforce",
    protocol: "OIDC",
    entityId: "https://enterprise.salesforce.com",
    ssoUrl: "https://aegisid.enterprise.com/sso/oidc/salesforce",
    clientId: "client_sf_823908420",
    clientSecret: "sec_sf_98319028409184091809",
    scimEnabled: true,
    scimEndpoint: "https://enterprise.salesforce.com/services/scim/v2",
  },
  {
    id: "app-4",
    name: "GitHub Enterprise",
    icon: "Github",
    protocol: "SAML 2.0",
    entityId: "https://github.com/enterprises/aegis-corp",
    ssoUrl: "https://aegisid.enterprise.com/sso/saml/github",
    certificate: "MIIE0DCCA7igAwIBAgIQC...[AegisID Signed SAML Public Certificate Key]...===",
    scimEnabled: true,
    scimEndpoint: "https://api.github.com/scim/v2/organizations/aegis-corp",
  },
];

export const DEFAULT_LOGS: AuditLog[] = [
  {
    id: "log-1",
    timestamp: "2026-07-04T19:25:00Z",
    level: "INFO",
    category: "AUTH",
    message: "Admin session authenticated successfully via Biometric Handshake",
    user: "alex.rivera@enterprise.io",
    ipAddress: "192.168.1.52",
    location: "San Jose, CA (HQ)",
  },
  {
    id: "log-2",
    timestamp: "2026-07-04T19:15:30Z",
    level: "INFO",
    category: "PROVISIONING",
    message: "SCIM Sync: Automated user provisioning trigger initialized for Jane Doe",
    user: "System",
    ipAddress: "127.0.0.1",
    location: "Cloud Container",
  },
  {
    id: "log-3",
    timestamp: "2026-07-04T18:45:10Z",
    level: "WARN",
    category: "MFA",
    message: "Failed TOTP login attempt: verification code skew detected (User: marcus.c@enterprise.io)",
    user: "marcus.c@enterprise.io",
    ipAddress: "172.16.5.90",
    location: "Denver, CO",
  },
  {
    id: "log-4",
    timestamp: "2026-07-04T18:10:15Z",
    level: "CRITICAL",
    category: "SECURITY_INCIDENT",
    message: "Threat Triggered: Brute Force login attempts detected (15 requests in 10s)",
    user: "anonymous@enterprise.io",
    ipAddress: "185.220.101.44",
    location: "Moscow, RU (Tor Exit)",
  },
  {
    id: "log-5",
    timestamp: "2026-07-04T17:30:20Z",
    level: "INFO",
    category: "SSO",
    message: "SSO Assertion issued for Slack Enterprise (Protocol: SAML 2.0)",
    user: "sarah.j@enterprise.io",
    ipAddress: "192.168.2.11",
    location: "San Jose, CA (HQ)",
  },
];

export const DEFAULT_THREATS: ThreatIncident[] = [
  {
    id: "threat-1",
    timestamp: "2026-07-04T18:10:15Z",
    threatType: "Brute Force Attack",
    severity: "CRITICAL",
    sourceIp: "185.220.101.44",
    location: "Moscow, RU (Tor Node)",
    targetedUser: "alex.rivera@enterprise.io",
    status: "Active",
    description: "Suspicious login burst of 15 unsuccessful attempts targeted at a high-privilege Administrator account within a 10-second interval.",
  },
  {
    id: "threat-2",
    timestamp: "2026-07-04T16:05:00Z",
    threatType: "Impossible Travel Detection",
    severity: "HIGH",
    sourceIp: "84.23.111.90",
    location: "Frankfurt, DE",
    targetedUser: "marcus.c@enterprise.io",
    status: "Investigating",
    description: "Multi-factor authentication session initiated from Frankfurt, Germany just 14 minutes after a verified biometric login from Denver, CO. Speed of travel exceeds commercial aircraft limits.",
  },
  {
    id: "threat-3",
    timestamp: "2026-07-04T13:40:00Z",
    threatType: "Unapproved User Offboarding Leak",
    severity: "MEDIUM",
    sourceIp: "198.51.100.22",
    location: "Austin, TX",
    targetedUser: "deprovisioned.employee",
    status: "Remediated",
    description: "Attempted OAuth token refresh on Salesforce Cloud from an offboarded employee account. Access denied automatically due to SCIM directory de-provisioning policies.",
  },
];

export function defaultDb(): Database {
  // Deep clone so callers can never mutate the seed constants.
  return JSON.parse(
    JSON.stringify({
      users: DEFAULT_USERS,
      apps: DEFAULT_APPS,
      logs: DEFAULT_LOGS,
      threats: DEFAULT_THREATS,
    }),
  );
}

// The one REAL app in the catalog: the bundled sample SP (sample-sp/server.ts).
// Registered via migration (not seed) so existing databases pick it up without
// losing enrolled MFA factors.
function localSpApp(): SSOApp {
  const spBase = process.env.SAMPLE_SP_URL || "http://localhost:3400";
  const idpBase = process.env.APP_URL && process.env.APP_URL !== "MY_APP_URL"
    ? process.env.APP_URL
    : `http://localhost:${Number(process.env.PORT) || 3000}`;
  return {
    id: "app-5",
    name: "Globex Intranet",
    icon: "Globex",
    protocol: "SAML 2.0",
    entityId: `${spBase}/saml/metadata`,
    ssoUrl: `${idpBase}/saml/sso`,
    certificate: "Published live at /saml/metadata (self-signed RSA-2048, rotates with saml-keys.json)",
    scimEnabled: true,
    scimEndpoint: `${spBase}/scim/v2`,
    launchUrl: spBase,
  };
}

// One-time migrations, recorded in db.migrations so they never re-run — a
// migration that re-applied on every load would silently undo admin changes
// (e.g. re-granting an app an admin just unassigned).
function migrate(db: Database): boolean {
  let changed = false;
  db.migrations = db.migrations || [];

  if (!db.migrations.includes("local-sp-app")) {
    if (!db.apps.some((a) => a.id === "app-5")) {
      db.apps.push(localSpApp());
    }
    // Initial backfill only: give existing users the real app in their launcher.
    for (const u of db.users) {
      if (u.status !== "Offboarded" && !u.assignedApps.includes("app-5")) {
        u.assignedApps.push("app-5");
      }
    }
    db.migrations.push("local-sp-app");
    changed = true;
  }

  // Turn on real SCIM provisioning for the bundled sample app (existing DBs
  // created before the SCIM integration have scimEnabled: false on app-5).
  if (!db.migrations.includes("scim-live-app")) {
    const spApp = db.apps.find((a) => a.id === "app-5");
    if (spApp) {
      const fresh = localSpApp();
      spApp.scimEnabled = true;
      spApp.scimEndpoint = fresh.scimEndpoint;
    }
    db.migrations.push("scim-live-app");
    changed = true;
  }

  return changed;
}

export function loadDb(): Database {
  try {
    if (fs.existsSync(DB_FILE)) {
      const db = JSON.parse(fs.readFileSync(DB_FILE, "utf-8")) as Database;
      if (migrate(db)) saveDb(db);
      return db;
    }
  } catch (err) {
    console.error("Failed to read database file, generating defaults...", err);
  }
  const db = defaultDb();
  migrate(db);
  saveDb(db);
  return db;
}

export function saveDb(data: Database): void {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf-8");
  } catch (err) {
    console.error("Failed to write database file:", err);
  }
}

// Monotonic id helper (ids are never reused because rows are never deleted).
export function nextId(prefix: string, rows: { id: string }[]): string {
  return `${prefix}-${rows.length + 1}`;
}

// Append an audit log entry to the front of the trail.
export function pushLog(db: Database, entry: Omit<AuditLog, "id" | "timestamp"> & { timestamp?: string }): AuditLog {
  const log: AuditLog = {
    id: nextId("log", db.logs),
    timestamp: entry.timestamp || new Date().toISOString(),
    level: entry.level,
    category: entry.category,
    message: entry.message,
    user: entry.user,
    ipAddress: entry.ipAddress,
    location: entry.location,
  };
  db.logs.unshift(log);
  return log;
}

export function findUser(db: Database, userId: string): User | undefined {
  return db.users.find((u) => u.id === userId);
}

// The browser must never see TOTP secrets, passkey public keys, password
// hashes, or challenges. Strip them and surface safe, derived flags instead.
export type SafeUser = Omit<User, "totp" | "passkeys" | "webauthnChallenge" | "passwordHash"> & {
  totpEnrolled: boolean;
  totpVerified: boolean;
  passkeys: { id: string; label: string; createdAt: string }[];
};

export function sanitizeUser(user: User): SafeUser {
  const { totp, passkeys, webauthnChallenge, passwordHash, ...safe } = user;
  return {
    ...safe,
    totpEnrolled: !!totp,
    totpVerified: !!totp?.verified,
    passkeys: (passkeys || []).map((p) => ({ id: p.id, label: p.label, createdAt: p.createdAt })),
  };
}

// ---------------------------------------------------------------------------
// Primary login factor (password) — real scrypt hashing.
//
// Demo directory accounts share a default password that is hashed on first use.
// Users always have at least a password so they can get into the app and then
// enroll a real second factor (TOTP / passkey) from Account Security.
// ---------------------------------------------------------------------------
export const DEMO_PASSWORD = "aegis1234";

export function setPassword(user: User, password: string): void {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  user.passwordHash = `${salt}:${hash}`;
}

export function verifyPassword(user: User, password: string): boolean {
  // Bootstrap: seed accounts accept the demo password once, then it is hashed.
  if (!user.passwordHash) {
    if (password === DEMO_PASSWORD) {
      setPassword(user, password);
      return true;
    }
    return false;
  }
  const [salt, hash] = user.passwordHash.split(":");
  const test = crypto.scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(test, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function findUserByEmail(db: Database, email: string): User | undefined {
  const target = (email || "").trim().toLowerCase();
  return db.users.find((u) => u.email.toLowerCase() === target);
}

// Just-in-time provisioning: create a directory account for a federated
// (OIDC) identity that has no matching local user yet.
export function jitCreateUser(db: Database, email: string, fullName?: string): User {
  const name = fullName || email.split("@")[0];
  const user: User = {
    id: nextId("u", db.users),
    username: email.split("@")[0].toLowerCase(),
    fullName: name,
    email,
    role: "Employee",
    status: "Active",
    assignedApps: ["app-1", "app-2"],
    mfaEnabled: false,
    mfaType: "Push",
    biometricRegistered: false,
    createdAt: new Date().toISOString(),
    department: "Federated (JIT)",
    lastLogin: new Date().toISOString(),
    ipAddress: "N/A",
  };
  db.users.push(user);
  return user;
}

export function sanitizeDb(db: Database) {
  return {
    users: db.users.map(sanitizeUser),
    // OIDC client secrets are issued once at registration and never re-exposed.
    apps: db.apps.map(({ clientSecret, ...app }) => ({ ...app, clientSecretSet: !!clientSecret })),
    logs: db.logs,
    threats: db.threats,
  };
}
