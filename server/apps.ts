import { Router } from "express";
import crypto from "crypto";
import { loadDb, saveDb, findUser, pushLog, nextId, sanitizeUser, SSOApp } from "./store";
import { syncUserToApp } from "./scim-client";

// ---------------------------------------------------------------------------
// Enterprise application management:
//   POST /api/apps/register — register a new SSO app (SAML 2.0 or OIDC)
//   POST /api/apps/remove   — remove an app and revoke it from all users
//   POST /api/apps/assign   — assign/unassign an app to a user's launcher
// ---------------------------------------------------------------------------

const slugify = (s: string) =>
  s.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "").slice(0, 24) || "app";

export function appsRouter(): Router {
  const router = Router();

  router.post("/register", (req, res) => {
    const db = loadDb();
    const { name, protocol, entityId, ssoUrl, scimEnabled, scimEndpoint } = req.body || {};

    if (!name || !entityId) {
      return res.status(400).json({ error: "App Name and Entity ID are required." });
    }
    if (protocol !== "SAML 2.0" && protocol !== "OIDC") {
      return res.status(400).json({ error: "Protocol must be 'SAML 2.0' or 'OIDC'." });
    }
    if (db.apps.some((a: SSOApp) => a.entityId === entityId)) {
      return res.status(409).json({ error: "An application with this Entity ID is already registered." });
    }

    const slug = slugify(name);
    const app: SSOApp = {
      id: nextId("app", db.apps),
      name,
      icon: name.slice(0, 2),
      protocol,
      entityId,
      ssoUrl: ssoUrl || `https://aegisid.enterprise.com/sso/${protocol === "OIDC" ? "oidc" : "saml"}/${slug}`,
      scimEnabled: !!scimEnabled,
      ...(scimEnabled && scimEndpoint ? { scimEndpoint } : {}),
    };

    // Issue protocol credentials the way a real IdP admin console would.
    let issuedSecret: string | undefined;
    if (protocol === "OIDC") {
      app.clientId = `client_${slug}_${crypto.randomBytes(4).toString("hex")}`;
      issuedSecret = `sec_${crypto.randomBytes(24).toString("hex")}`;
      app.clientSecret = issuedSecret;
    } else {
      app.certificate = "Signed by AegisID IdP — public certificate published at /saml/metadata";
    }

    db.apps.push(app);
    const log = pushLog(db, {
      level: "INFO",
      category: "SSO",
      message: `New enterprise application registered: ${name} (${protocol}, Entity ID: ${entityId}).`,
      user: "Security Administrator",
      ipAddress: req.ip || "127.0.0.1",
      location: "Admin Console",
    });
    saveDb(db);

    // clientSecret is returned once at registration and never again via /api/db.
    res.json({ success: true, app, issuedSecret, log });
  });

  router.post("/remove", (req, res) => {
    const db = loadDb();
    const { appId } = req.body || {};
    const app = db.apps.find((a: SSOApp) => a.id === appId);
    if (!app) return res.status(404).json({ error: "Application not found." });
    if (app.launchUrl) {
      return res.status(400).json({ error: "The bundled live sample app cannot be removed — it backs the real SAML SSO demo. You can unassign it per user instead." });
    }

    db.apps = db.apps.filter((a: SSOApp) => a.id !== appId);
    let revoked = 0;
    for (const u of db.users) {
      if (u.assignedApps.includes(appId)) {
        u.assignedApps = u.assignedApps.filter((id) => id !== appId);
        revoked++;
      }
    }
    pushLog(db, {
      level: "WARN",
      category: "SSO",
      message: `Enterprise application deregistered: ${app.name}. Access revoked from ${revoked} user(s); federation trust removed.`,
      user: "Security Administrator",
      ipAddress: req.ip || "127.0.0.1",
      location: "Admin Console",
    });
    saveDb(db);
    res.json({ success: true, removedAppId: appId, revokedFrom: revoked });
  });

  router.post("/assign", async (req, res) => {
    const db = loadDb();
    const { userId, appId, assigned } = req.body || {};
    const user = findUser(db, userId);
    const app = db.apps.find((a: SSOApp) => a.id === appId);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!app) return res.status(404).json({ error: "Application not found." });
    if (user.status === "Offboarded") {
      return res.status(400).json({ error: "Cannot assign applications to an offboarded user." });
    }

    const has = user.assignedApps.includes(appId);
    if (assigned && !has) {
      user.assignedApps.push(appId);
    } else if (!assigned && has) {
      user.assignedApps = user.assignedApps.filter((id) => id !== appId);
    }

    pushLog(db, {
      level: "INFO",
      category: "PROVISIONING",
      message: assigned
        ? `Application access granted: ${app.name} assigned to ${user.fullName} (${user.email}). SCIM entitlement sync queued.`
        : `Application access revoked: ${app.name} unassigned from ${user.fullName} (${user.email}). Active sessions for this app invalidated.`,
      user: "Security Administrator",
      ipAddress: req.ip || "127.0.0.1",
      location: "Admin Console",
    });

    // REAL SCIM push (live apps only): assignment creates/reactivates the
    // account in the app; unassignment deactivates it.
    await syncUserToApp(db, app, user, assigned ? "activate" : "deactivate", assigned ? "app assigned" : "app unassigned");

    saveDb(db);
    res.json({ success: true, user: sanitizeUser(user) });
  });

  return router;
}
