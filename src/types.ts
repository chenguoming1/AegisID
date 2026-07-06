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

export interface EncryptedResult {
  plaintext: string;
  salt: string;
  algorithm: string;
  keyDerivation: string;
  iv: string;
  ciphertext: string;
  authTag: string;
  secureStoragePayload: string;
}

export interface SAMLHandshakeResponse {
  success: boolean;
  protocol: string;
  entityId: string;
  ssoUrl: string;
  sessionId: string;
  issuedAt: string;
  expiresAt: string;
  assertion: string;
  log: AuditLog;
}
