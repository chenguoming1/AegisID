import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const PORT = 3000;
const DB_FILE = path.join(process.cwd(), "database.json");

// Define Interface Shapes
interface User {
  id: string;
  username: string;
  fullName: string;
  email: string;
  role: "Admin" | "Security Engineer" | "Compliance Auditor" | "Employee";
  status: "Active" | "Suspended" | "Pending Onboarding" | "Offboarded";
  assignedApps: string[]; // Application IDs
  mfaEnabled: boolean;
  mfaType: "TOTP" | "Biometric" | "SMS" | "Push";
  biometricRegistered: boolean;
  createdAt: string;
  department: string;
  lastLogin: string;
  ipAddress: string;
}

interface SSOApp {
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
}

interface AuditLog {
  id: string;
  timestamp: string;
  level: "INFO" | "WARN" | "CRITICAL";
  category: "AUTH" | "MFA" | "PROVISIONING" | "SECURITY_INCIDENT" | "SSO" | "SYSTEM";
  message: string;
  user: string;
  ipAddress: string;
  location: string;
}

interface ThreatIncident {
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

// Initial/Seed Data
const DEFAULT_USERS: User[] = [
  {
    id: "u-1",
    username: "admin.cyber",
    fullName: "Alex Rivera",
    email: "heliexpertaung@gmail.com", // User's email as bootstrapped admin
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

const DEFAULT_APPS: SSOApp[] = [
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

const DEFAULT_LOGS: AuditLog[] = [
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

const DEFAULT_THREATS: ThreatIncident[] = [
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

// Helper to Load & Save Database State
function loadDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, "utf-8");
      return JSON.parse(raw);
    }
  } catch (err) {
    console.error("Failed to read database file, generating defaults...", err);
  }

  const defaultDb = {
    users: DEFAULT_USERS,
    apps: DEFAULT_APPS,
    logs: DEFAULT_LOGS,
    threats: DEFAULT_THREATS,
  };
  saveDb(defaultDb);
  return defaultDb;
}

function saveDb(data: any) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf-8");
  } catch (err) {
    console.error("Failed to write database file:", err);
  }
}

// Lazy initialization of Google Gemini Client to protect startup
let geminiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI | null {
  if (!geminiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (key && key !== "MY_GEMINI_API_KEY") {
      geminiClient = new GoogleGenAI({
        apiKey: key,
        httpOptions: {
          headers: {
            "User-Agent": "aistudio-build",
          },
        },
      });
    }
  }
  return geminiClient;
}

// Encryption Keys
// In production, these should be securely stored secrets. For the sandbox simulation,
// we generate a consistent 256-bit key based on an environment secret or static salt.
const ENCRYPTION_SECRET = process.env.GEMINI_API_KEY || "AegisIDSymmetricMasterKeySeed2026!";
const KEY_DERIVATION_SALT = "AegisIDSalt2026!";
const CRYPTO_KEY = crypto.pbkdf2Sync(ENCRYPTION_SECRET, KEY_DERIVATION_SALT, 100000, 32, "sha256");

async function startServer() {
  const app = express();
  app.use(express.json());

  // API ROUTE: Database Initialization / Reset
  app.post("/api/db/reset", (req, res) => {
    const defaultDb = {
      users: DEFAULT_USERS,
      apps: DEFAULT_APPS,
      logs: DEFAULT_LOGS,
      threats: DEFAULT_THREATS,
    };
    saveDb(defaultDb);
    res.json({ success: true, message: "Database state reset to enterprise defaults.", db: defaultDb });
  });

  // API ROUTE: Get All Database State
  app.get("/api/db", (req, res) => {
    res.json(loadDb());
  });

  // API ROUTE: Manage Users (Provisioning SCIM Simulation)
  app.get("/api/users", (req, res) => {
    res.json(loadDb().users);
  });

  app.post("/api/users/provision", (req, res) => {
    const dbData = loadDb();
    const { fullName, email, role, department, mfaType } = req.body;

    if (!fullName || !email) {
      return res.status(400).json({ error: "Full Name and Email are required for provisioning." });
    }

    const username = fullName.toLowerCase().replace(/\s+/g, ".");
    const id = "u-" + (dbData.users.length + 1);

    const newUser: User = {
      id,
      username,
      fullName,
      email,
      role: role || "Employee",
      status: "Active", // Instantly Active under automated SCIM flow
      assignedApps: ["app-1", "app-2"], // Default onboarding apps (Slack, AWS)
      mfaEnabled: true,
      mfaType: mfaType || "TOTP",
      biometricRegistered: false,
      createdAt: new Date().toISOString(),
      department: department || "Operations",
      lastLogin: "Never",
      ipAddress: "N/A",
    };

    dbData.users.push(newUser);

    // Create Audit Log
    const log: AuditLog = {
      id: "log-" + (dbData.logs.length + 1),
      timestamp: new Date().toISOString(),
      level: "INFO",
      category: "PROVISIONING",
      message: `SCIM Provisioning Successful: Account created for ${fullName} (${email}). Automatic app syncing initiated.`,
      user: "System Admin (SCIM)",
      ipAddress: req.ip || "127.0.0.1",
      location: "San Jose, CA (HQ)",
    };
    dbData.logs.unshift(log);

    saveDb(dbData);
    res.json({ success: true, user: newUser, log });
  });

  app.post("/api/users/deprovision", (req, res) => {
    const dbData = loadDb();
    const { userId } = req.body;

    const userIndex = dbData.users.findIndex((u: User) => u.id === userId);
    if (userIndex === -1) {
      return res.status(404).json({ error: "User not found." });
    }

    const user = dbData.users[userIndex];
    user.status = "Offboarded";
    user.assignedApps = []; // Clear apps

    // Create Audit Log
    const log: AuditLog = {
      id: "log-" + (dbData.logs.length + 1),
      timestamp: new Date().toISOString(),
      level: "WARN",
      category: "PROVISIONING",
      message: `SCIM Deprovisioning Event: Suspended sessions and disabled access for ${user.fullName}. Offboarding pipeline complete.`,
      user: "System Admin (SCIM)",
      ipAddress: req.ip || "127.0.0.1",
      location: "San Jose, CA (HQ)",
    };
    dbData.logs.unshift(log);

    saveDb(dbData);
    res.json({ success: true, user, log });
  });

  app.post("/api/users/update-status", (req, res) => {
    const dbData = loadDb();
    const { userId, status } = req.body;

    const user = dbData.users.find((u: User) => u.id === userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    user.status = status;

    const log: AuditLog = {
      id: "log-" + (dbData.logs.length + 1),
      timestamp: new Date().toISOString(),
      level: status === "Suspended" ? "WARN" : "INFO",
      category: "PROVISIONING",
      message: `Security Administrator altered status of user ${user.fullName} to: ${status}`,
      user: "Security Administrator",
      ipAddress: req.ip || "127.0.0.1",
      location: "HQ-Cloud",
    };
    dbData.logs.unshift(log);

    saveDb(dbData);
    res.json({ success: true, user, log });
  });

  // API ROUTE: SAML SSO Assertion Handshake Generator
  app.post("/api/sso/handshake", (req, res) => {
    const { userId, appId } = req.body;
    const dbData = loadDb();

    const user = dbData.users.find((u: User) => u.id === userId);
    const appItem = dbData.apps.find((a: SSOApp) => a.id === appId);

    if (!user || !appItem) {
      return res.status(400).json({ error: "Invalid user or application reference." });
    }

    const now = new Date();
    const expiration = new Date(now.getTime() + 10 * 60 * 1000); // 10 min window
    const sessionId = crypto.randomUUID();

    // Generate simulated SAML 2.0 Response XML assertion (readable and authentic)
    const xmlAssertion = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
                ID="_${crypto.randomBytes(16).toString("hex")}" 
                Version="2.0" 
                IssueInstant="${now.toISOString()}" 
                Destination="${appItem.ssoUrl}">
  <saml:Issuer>https://aegisid.enterprise.com/saml2</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_${crypto.randomBytes(16).toString("hex")}" 
                  IssueInstant="${now.toISOString()}" 
                  Version="2.0">
    <saml:Issuer>https://aegisid.enterprise.com/saml2</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_${sessionId}">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>${crypto.randomBytes(32).toString("base64")}</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>
        ${crypto.randomBytes(128).toString("base64")}
      </ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        ${user.email}
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${expiration.toISOString()}" 
                                      Recipient="${appItem.ssoUrl}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${now.toISOString()}" 
                     NotOnOrAfter="${expiration.toISOString()}">
      <saml:AudienceRestriction>
        <saml:Audience>${appItem.entityId}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="User.ID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>${user.id}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="User.Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>${user.role}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="User.Department" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>${user.department}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

    // Log the SSO authentication event
    const log: AuditLog = {
      id: "log-" + (dbData.logs.length + 1),
      timestamp: now.toISOString(),
      level: "INFO",
      category: "SSO",
      message: `SAML SSO Single Sign-On handshake completed for ${appItem.name}. Subject: ${user.email}`,
      user: user.email,
      ipAddress: user.ipAddress === "N/A" ? "192.168.1.100" : user.ipAddress,
      location: "San Jose, CA (HQ)",
    };
    dbData.logs.unshift(log);
    saveDb(dbData);

    res.json({
      success: true,
      protocol: appItem.protocol,
      entityId: appItem.entityId,
      ssoUrl: appItem.ssoUrl,
      sessionId,
      issuedAt: now.toISOString(),
      expiresAt: expiration.toISOString(),
      assertion: xmlAssertion,
      log,
    });
  });

  // API ROUTE: Cryptographic Encryption Visualizer (AES-256-GCM)
  app.post("/api/crypto/encrypt", (req, res) => {
    try {
      const { plaintext } = req.body;
      if (!plaintext) {
        return res.status(400).json({ error: "Plaintext is required for encryption." });
      }

      const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
      const cipher = crypto.createCipheriv("aes-256-gcm", CRYPTO_KEY, iv);
      
      let encrypted = cipher.update(plaintext, "utf8", "hex");
      encrypted += cipher.final("hex");
      
      const tag = cipher.getAuthTag();

      res.json({
        success: true,
        plaintext,
        salt: KEY_DERIVATION_SALT,
        algorithm: "AES-256-GCM",
        keyDerivation: "PBKDF2 (100k Iterations, SHA256)",
        iv: iv.toString("hex"),
        ciphertext: encrypted,
        authTag: tag.toString("hex"),
        secureStoragePayload: `AegisSec_${iv.toString("hex")}_${tag.toString("hex")}_${encrypted}`,
      });
    } catch (err: any) {
      res.status(500).json({ error: "Cryptographic failure: " + err.message });
    }
  });

  // API ROUTE: Cryptographic Decryption Visualizer
  app.post("/api/crypto/decrypt", (req, res) => {
    try {
      const { iv, ciphertext, authTag } = req.body;
      if (!iv || !ciphertext || !authTag) {
        return res.status(400).json({ error: "IV, Ciphertext, and AuthTag are all required for verification." });
      }

      const decipher = crypto.createDecipheriv("aes-256-gcm", CRYPTO_KEY, Buffer.from(iv, "hex"));
      decipher.setAuthTag(Buffer.from(authTag, "hex"));

      let decrypted = decipher.update(ciphertext, "hex", "utf8");
      decrypted += decipher.final("utf8");

      res.json({
        success: true,
        decryptedPlaintext: decrypted,
        verification: "PASSED: AES-GCM Integrity Verification Confirmed. Message Authentic.",
      });
    } catch (err: any) {
      res.status(400).json({ error: "Cryptographic Decryption / Authenticity tag verification failed: " + err.message });
    }
  });

  // API ROUTE: Simulated Threat Remediation Trigger
  app.post("/api/threats/remediate", (req, res) => {
    const { threatId, action } = req.body;
    const dbData = loadDb();

    const threat = dbData.threats.find((t: ThreatIncident) => t.id === threatId);
    if (!threat) return res.status(404).json({ error: "Threat incident not found." });

    threat.status = "Remediated";

    // Create Audit Log
    const log: AuditLog = {
      id: "log-" + (dbData.logs.length + 1),
      timestamp: new Date().toISOString(),
      level: "INFO",
      category: "SECURITY_INCIDENT",
      message: `Threat Remediation Executed [ID: ${threatId}]: ${action}. Threat state updated to 'Remediated'.`,
      user: "Security Analyst (Remediation Hub)",
      ipAddress: req.ip || "127.0.0.1",
      location: "San Jose, CA (HQ)",
    };
    dbData.logs.unshift(log);

    // If targeted user account exists, secure it based on the action
    if (action.includes("Suspend") || action.includes("Block")) {
      const targetUser = dbData.users.find((u: User) => u.email === threat.targetedUser || u.username === threat.targetedUser);
      if (targetUser) {
        targetUser.status = "Suspended";
        dbData.logs.unshift({
          id: "log-" + (dbData.logs.length + 1),
          timestamp: new Date().toISOString(),
          level: "WARN",
          category: "PROVISIONING",
          message: `User account of ${targetUser.fullName} has been automatically Suspended as part of remediation policy.`,
          user: "System SecOps",
          ipAddress: "127.0.0.1",
          location: "Security Automation",
        });
      }
    }

    saveDb(dbData);
    res.json({ success: true, threat, log, users: dbData.users });
  });

  // API ROUTE: Trigger Mock Security Alert
  app.post("/api/threats/trigger-test", (req, res) => {
    const dbData = loadDb();
    const { type } = req.body;

    let newThreat: ThreatIncident;

    if (type === "impossible_travel") {
      newThreat = {
        id: "threat-" + (dbData.threats.length + 1),
        timestamp: new Date().toISOString(),
        threatType: "Impossible Travel Detection",
        severity: "HIGH",
        sourceIp: "103.88.22.14",
        location: "Singapore, SG",
        targetedUser: "alex.rivera@enterprise.io",
        status: "Active",
        description: "Admin account session initiated from Singapore. Active session already exists from San Jose, CA. Travel timeframe physically impossible.",
      };
    } else {
      newThreat = {
        id: "threat-" + (dbData.threats.length + 1),
        timestamp: new Date().toISOString(),
        threatType: "API Key Abuse Detection",
        severity: "CRITICAL",
        sourceIp: "45.143.201.12",
        location: "Sao Paulo, BR",
        targetedUser: "ServicePrincipal_AWSReader",
        status: "Active",
        description: "Automated alert: High-privilege API key used from a non-whitelisted foreign subnet. Mass resource listing triggered.",
      };
    }

    dbData.threats.unshift(newThreat);

    // Write alert audit log
    dbData.logs.unshift({
      id: "log-" + (dbData.logs.length + 1),
      timestamp: new Date().toISOString(),
      level: "CRITICAL",
      category: "SECURITY_INCIDENT",
      message: `REAL-TIME INCIDENT: ${newThreat.threatType} triggered. Severity: ${newThreat.severity}. Source IP: ${newThreat.sourceIp}`,
      user: newThreat.targetedUser,
      ipAddress: newThreat.sourceIp,
      location: newThreat.location,
    });

    saveDb(dbData);
    res.json({ success: true, threat: newThreat });
  });

  // API ROUTE: AI-Powered SOC 2 & CISA Compliance Incident Report Generator (Gemini)
  app.post("/api/gemini/incident-report", async (req, res) => {
    const { threatId } = req.body;
    const dbData = loadDb();

    const threat = dbData.threats.find((t: ThreatIncident) => t.id === threatId);
    if (!threat) {
      return res.status(404).json({ error: "Threat incident not found." });
    }

    // Filter relevant logs within 2 hours of threat for context
    const correlatedLogs = dbData.logs
      .filter((l: AuditLog) => l.category === "AUTH" || l.category === "SECURITY_INCIDENT" || l.category === "MFA")
      .slice(0, 5);

    const client = getGeminiClient();

    if (!client) {
      // Graceful fallback if Gemini API Key is missing or default placeholder
      const mockReport = `# SOC 2 & CISA SECURITY INCIDENT AUDIT REPORT
**REGULATORY CLASSIFICATION:** NIST SP 800-61 Rev. 2 (Incident Handling) / SOC 2 Type II Compliance
**REPORT STATUS:** GENERATED (SANDBOX FALLBACK MODE)

---

## 1. Executive Summary
On **${threat.timestamp}**, the AegisID Security Orchestration, Automation, and Response (SOAR) engine detected a highly suspicious security event classified under **${threat.threatType}** with a severity index of **${threat.severity}**. This incident targeted the account credentials of **${threat.targetedUser}** originating from remote IP subnet **${threat.sourceIp}** (${threat.location}).

## 2. Technical Profile & Core Vectors
- **Incident ID Reference:** ${threat.id}
- **Source Host IP Network:** \`${threat.sourceIp}\` (Subnet Location: ${threat.location})
- **Primary Attack Vector:** External Identity Hijacking / Credential Abuse
- **System Impact Level:** Confidentiality: High | Integrity: High | Availability: Medium

## 3. Automated Log Correlation Analysis
AegisID threat telemetry correlated the following system directory activities leading up to the detection threshold:
${correlatedLogs.map((l: AuditLog) => `- **${l.timestamp}** [${l.level}] ${l.category}: "${l.message}" from IP ${l.ipAddress}`).join("\n")}

## 4. SOC 2 Remediation & Root Cause Corrective Actions (CAPA)
1. **Immediate Session Termination (Revocation):** Revoked all active SAML 2.0 / OIDC assertions associated with the target entity.
2. **Directory Suspension:** Automated SCIM directory sync triggered status modification to \`Suspended\` to halt further LDAP/AD federation.
3. **Boundary Firewall Control:** Appended host IP \`${threat.sourceIp}\` to the corporate cloud ingress blocklist.
4. **MFA Hardening:** Mandated instant biometric registration and invalidated TOTP tokens for future registrations.

---
*Note: To enable real-time compliance reporting powered by advanced Gemini 3.5 capabilities, configure your **GEMINI_API_KEY** in the Secrets menu.*`;

      return res.json({
        success: true,
        report: mockReport,
        aiUsed: false,
        message: "Report compiled via compliance engine rules. Configure GEMINI_API_KEY to unlock advanced deep-reasoning summaries.",
      });
    }

    try {
      const prompt = `You are a Principal Cyber Security Forensic Auditor and SOC 2 Compliance Specialist.
Generate an official executive and technical Security Incident Audit Report aligned with NIST SP 800-61 Rev. 2 and SOC 2 compliance standards.

Here is the details of the active threat:
- Threat Type: ${threat.threatType}
- Severity: ${threat.severity}
- Timestamp: ${threat.timestamp}
- Targeted Entity/User: ${threat.targetedUser}
- Source Location & Subnet: ${threat.sourceIp} (${threat.location})
- System Status: ${threat.status}
- Incident Description: ${threat.description}

Here is a list of correlated audit logs of related active directory sessions:
${JSON.stringify(correlatedLogs, null, 2)}

Requirements for your written Report in Markdown:
1. Executive Summary of the breach / anomaly.
2. Threat actor profile and geographical/subnet details.
3. Technical log correlation analysis, detailing any timing pattern or risk escalation (PBKDF2/AES-256 integrity check status, SAML Assertion metadata).
4. Concrete containment, eradication, and remediation steps (e.g., immediate SCIM suspension, revoking OAuth tokens, blocklisting, or biometric MFA enforcement).
5. Preventative CAPA (Corrective and Preventive Action) roadmap to enforce zero-trust posture.

Keep the report formal, highly technical, and completely realistic for an enterprise security team. Return ONLY the report markdown. Do not include markdown wraps like \`\`\`markdown or generic chat preambles.`;

      const response = await client.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
      });

      res.json({
        success: true,
        report: response.text,
        aiUsed: true,
      });
    } catch (err: any) {
      res.status(500).json({ error: "Gemini report compilation error: " + err.message });
    }
  });

  // VITE DEVELOPMENT MIDDLEWARE OR STATIC FILES
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[AegisID Server] Running successfully on http://0.0.0.0:${PORT}`);
  });
}

startServer();
