import { Router } from "express";
import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";

// ---------------------------------------------------------------------------
// REAL SCIM 2.0 server for the Globex sample app (RFC 7643/7644 subset).
//
// AegisID (the IdP) is the SCIM *client*: it pushes user lifecycle events here
// over HTTP with a bearer token. Globex keeps its own user directory — accounts
// exist (or are deactivated) in the app independent of any SSO login.
//
// Supported: GET /Users (with `filter=userName eq "..."`), POST /Users,
// GET/PATCH/DELETE /Users/:id. PATCH understands `replace` ops on `active`.
// ---------------------------------------------------------------------------

const STORE_FILE = path.join(process.cwd(), "globex-directory.json");
const SCIM_TOKEN = process.env.SCIM_TOKEN || "aegis-scim-demo-token";

export interface GlobexUser {
  id: string;
  userName: string; // email, the SCIM identifier AegisID uses
  displayName: string;
  email: string;
  active: boolean;
  role?: string;
  department?: string;
  source: "scim" | "jit"; // pushed by the IdP vs created at first SSO login
  createdAt: string;
  updatedAt: string;
}

function load(): GlobexUser[] {
  try {
    if (fs.existsSync(STORE_FILE)) return JSON.parse(fs.readFileSync(STORE_FILE, "utf-8"));
  } catch {
    // corrupted file -> start fresh
  }
  return [];
}
function save(users: GlobexUser[]): void {
  fs.writeFileSync(STORE_FILE, JSON.stringify(users, null, 2), "utf-8");
}

export function listGlobexUsers(): GlobexUser[] {
  return load();
}

export function findGlobexUser(userName: string): GlobexUser | undefined {
  return load().find((u) => u.userName.toLowerCase() === userName.toLowerCase());
}

// Called from the ACS after a verified SSO login for a user Globex doesn't know
// yet — classic JIT provisioning (the "pull" counterpart to SCIM's push).
export function jitProvisionGlobexUser(userName: string, displayName: string): GlobexUser {
  const users = load();
  const existing = users.find((u) => u.userName.toLowerCase() === userName.toLowerCase());
  if (existing) return existing;
  const now = new Date().toISOString();
  const user: GlobexUser = {
    id: crypto.randomUUID(),
    userName,
    displayName,
    email: userName,
    active: true,
    source: "jit",
    createdAt: now,
    updatedAt: now,
  };
  users.push(user);
  save(users);
  return user;
}

const ENTERPRISE_EXT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

function toScimResource(u: GlobexUser) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", ENTERPRISE_EXT],
    id: u.id,
    userName: u.userName,
    displayName: u.displayName,
    name: { formatted: u.displayName },
    emails: [{ value: u.email, primary: true }],
    title: u.role,
    active: u.active,
    [ENTERPRISE_EXT]: { department: u.department },
    meta: { resourceType: "User", created: u.createdAt, lastModified: u.updatedAt },
  };
}

const scimError = (status: number, detail: string) => ({
  schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
  status: String(status),
  detail,
});

export function scimRouter(): Router {
  const router = Router();
  router.use(express.json({ type: ["application/json", "application/scim+json"] }));

  // Bearer-token auth on every SCIM call — same as a real SCIM integration.
  router.use((req, res, next) => {
    const auth = req.headers.authorization || "";
    if (auth !== `Bearer ${SCIM_TOKEN}`) {
      return res.status(401).json(scimError(401, "Invalid or missing SCIM bearer token."));
    }
    next();
  });

  router.get("/Users", (req, res) => {
    let users = load();
    const filter = String(req.query.filter || "");
    const m = filter.match(/^userName eq "(.+)"$/i);
    if (m) users = users.filter((u) => u.userName.toLowerCase() === m[1].toLowerCase());
    res.json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: users.length,
      startIndex: 1,
      itemsPerPage: users.length,
      Resources: users.map(toScimResource),
    });
  });

  router.get("/Users/:id", (req, res) => {
    const user = load().find((u) => u.id === req.params.id);
    if (!user) return res.status(404).json(scimError(404, "User not found."));
    res.json(toScimResource(user));
  });

  router.post("/Users", (req, res) => {
    const body = req.body || {};
    const userName = body.userName;
    if (!userName) return res.status(400).json(scimError(400, "userName is required."));

    const users = load();
    const existing = users.find((u) => u.userName.toLowerCase() === String(userName).toLowerCase());
    if (existing) {
      return res.status(409).json(scimError(409, `User ${userName} already exists (id ${existing.id}).`));
    }

    const now = new Date().toISOString();
    const user: GlobexUser = {
      id: crypto.randomUUID(),
      userName,
      displayName: body.displayName || body.name?.formatted || userName,
      email: body.emails?.[0]?.value || userName,
      active: body.active !== false,
      role: body.title,
      department: body[ENTERPRISE_EXT]?.department,
      source: "scim",
      createdAt: now,
      updatedAt: now,
    };
    users.push(user);
    save(users);
    console.log(`[Globex SCIM] Provisioned ${user.userName} (active=${user.active})`);
    res.status(201).json(toScimResource(user));
  });

  router.patch("/Users/:id", (req, res) => {
    const users = load();
    const user = users.find((u) => u.id === req.params.id);
    if (!user) return res.status(404).json(scimError(404, "User not found."));

    // Standard PatchOp: { Operations: [{ op: "replace", value: { active: false } }] }
    for (const op of req.body?.Operations || []) {
      const opName = String(op.op || "").toLowerCase();
      if (opName !== "replace" && opName !== "add") continue;
      const value = op.path === "active" ? { active: op.value } : op.value || {};
      if (typeof value.active === "boolean") user.active = value.active;
      if (typeof value.displayName === "string") user.displayName = value.displayName;
      if (typeof value.title === "string") user.role = value.title;
    }
    user.updatedAt = new Date().toISOString();
    save(users);
    console.log(`[Globex SCIM] Updated ${user.userName} (active=${user.active})`);
    res.json(toScimResource(user));
  });

  router.delete("/Users/:id", (req, res) => {
    const users = load();
    const idx = users.findIndex((u) => u.id === req.params.id);
    if (idx === -1) return res.status(404).json(scimError(404, "User not found."));
    const [removed] = users.splice(idx, 1);
    save(users);
    console.log(`[Globex SCIM] Deleted ${removed.userName}`);
    res.status(204).send();
  });

  return router;
}
