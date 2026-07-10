import { Database, SSOApp, User, pushLog } from "./store";

// ---------------------------------------------------------------------------
// REAL SCIM 2.0 client — AegisID acting as the provisioning IdP.
//
// On user lifecycle events (provision, offboard, suspend/activate, app
// assign/unassign) AegisID pushes actual HTTP calls to the app's SCIM
// endpoint: POST /Users to create, PATCH /Users/:id to (de)activate. Every
// push writes an audit-log entry with the real HTTP outcome.
//
// Pushes only target "live" apps — catalog entries with scimEnabled, a SCIM
// endpoint AND a launchUrl (i.e. the bundled Globex sample app). The seeded
// Slack/Salesforce/GitHub endpoints are decorative and are never called.
// ---------------------------------------------------------------------------

const SCIM_TOKEN = process.env.SCIM_TOKEN || "aegis-scim-demo-token";
const TIMEOUT_MS = 3000;

const ENTERPRISE_EXT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

export function isLiveScimApp(app: SSOApp): boolean {
  return !!(app.scimEnabled && app.scimEndpoint && app.launchUrl);
}

async function scimFetch(url: string, method: string, body?: unknown) {
  const resp = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/scim+json",
      Authorization: `Bearer ${SCIM_TOKEN}`,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const json = await resp.json().catch(() => ({}));
  return { status: resp.status, json: json as any };
}

async function findRemoteId(endpoint: string, userName: string): Promise<string | null> {
  const { status, json } = await scimFetch(
    `${endpoint}/Users?filter=${encodeURIComponent(`userName eq "${userName}"`)}`,
    "GET",
  );
  if (status !== 200 || !json.Resources?.length) return null;
  return json.Resources[0].id;
}

// Push one user lifecycle change to one app. Never throws — the outcome
// (including network failure) is recorded as an audit log entry on `db`;
// the caller is responsible for saveDb().
export async function syncUserToApp(
  db: Database,
  app: SSOApp,
  user: User,
  action: "activate" | "deactivate",
  reason: string,
): Promise<void> {
  if (!isLiveScimApp(app)) return;
  const endpoint = app.scimEndpoint!.replace(/\/$/, "");

  let outcome: string;
  let level: "INFO" | "WARN" = "INFO";
  try {
    const remoteId = await findRemoteId(endpoint, user.email);

    if (action === "activate") {
      if (remoteId) {
        const { status } = await scimFetch(`${endpoint}/Users/${remoteId}`, "PATCH", {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "replace", value: { active: true, displayName: user.fullName, title: user.role } }],
        });
        outcome = `PATCH /Users (reactivate) → HTTP ${status}`;
      } else {
        const { status } = await scimFetch(`${endpoint}/Users`, "POST", {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", ENTERPRISE_EXT],
          userName: user.email,
          displayName: user.fullName,
          name: { formatted: user.fullName },
          emails: [{ value: user.email, primary: true }],
          title: user.role,
          active: true,
          [ENTERPRISE_EXT]: { department: user.department },
        });
        outcome = `POST /Users (create) → HTTP ${status}`;
        if (status >= 400) level = "WARN";
      }
    } else {
      if (remoteId) {
        const { status } = await scimFetch(`${endpoint}/Users/${remoteId}`, "PATCH", {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "replace", value: { active: false } }],
        });
        outcome = `PATCH /Users (deactivate) → HTTP ${status}`;
      } else {
        outcome = "no remote account to deactivate (skipped)";
      }
    }
  } catch (err: any) {
    outcome = `FAILED: ${err.name === "TimeoutError" ? "endpoint unreachable (timeout)" : err.message}`;
    level = "WARN";
  }

  pushLog(db, {
    level,
    category: "PROVISIONING",
    message: `SCIM sync → ${app.name}: ${user.email} ${action} (${reason}). ${outcome}.`,
    user: "AegisID SCIM Engine",
    ipAddress: "127.0.0.1",
    location: "SCIM Connector",
  });
}

// Push a change to every live SCIM app in the given assignment list.
export async function syncUserToApps(
  db: Database,
  appIds: string[],
  user: User,
  action: "activate" | "deactivate",
  reason: string,
): Promise<void> {
  const targets = db.apps.filter((a) => appIds.includes(a.id) && isLiveScimApp(a));
  for (const app of targets) {
    await syncUserToApp(db, app, user, action, reason);
  }
}
