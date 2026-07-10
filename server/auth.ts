import { Router } from "express";
import crypto from "crypto";
import {
  loadDb, saveDb, findUser, findUserByEmail, verifyPassword, sanitizeUser, pushLog, User,
} from "./store";
import { createSession, destroySession, getSessionUser } from "./session";
import {
  startPasskeyAuth, finishPasskeyAuth, generateDiscoverableAuthOptions, verifyPasskeyAssertion, WebAuthnConfig,
} from "./webauthn";
import { isValidTotp } from "./totp";

// ---------------------------------------------------------------------------
// The real login gate for the whole AegisID app.
//
// Flow: POST /login with email + password (primary factor). If the account has
// a real second factor enrolled (verified TOTP or a passkey), the response asks
// for step-up and the session is only created once the second factor checks out.
// OIDC (see oidc.ts) is an alternative primary that also creates the session.
// ---------------------------------------------------------------------------

const PENDING_TTL_MS = 5 * 60 * 1000;

function secondFactorsFor(user: User): string[] {
  const factors: string[] = [];
  if (user.totp?.verified) factors.push("totp");
  if (user.passkeys?.length) factors.push("passkey");
  return factors;
}

export function authRouter(config: WebAuthnConfig): Router {
  const router = Router();

  // Short-lived tokens bridging the password step and the MFA step.
  const pending = new Map<string, { userId: string; createdAt: number }>();
  const newPending = (userId: string) => {
    const token = crypto.randomUUID();
    pending.set(token, { userId, createdAt: Date.now() });
    return token;
  };
  const takePending = (token?: string): string | null => {
    const p = token ? pending.get(token) : undefined;
    if (!p) return null;
    if (Date.now() - p.createdAt > PENDING_TTL_MS) {
      pending.delete(token!);
      return null;
    }
    return p.userId;
  };

  // Step 1: primary factor (password).
  router.post("/login", (req, res) => {
    const db = loadDb();
    const email = String(req.body?.email || "");
    const user = findUserByEmail(db, email);

    if (!user || !verifyPassword(user, String(req.body?.password || ""))) {
      pushLog(db, {
        level: "WARN", category: "AUTH",
        message: `Failed password login attempt for ${email || "unknown"}.`,
        user: email || "unknown", ipAddress: req.ip || "127.0.0.1", location: "Login",
      });
      saveDb(db);
      return res.status(401).json({ error: "Invalid email or password." });
    }
    if (user.status === "Offboarded" || user.status === "Suspended") {
      return res.status(403).json({ error: `This account is ${user.status.toLowerCase()}. Contact your administrator.` });
    }
    saveDb(db); // persist a freshly-bootstrapped password hash

    const factors = secondFactorsFor(user);
    if (factors.length === 0) {
      createSession(res, user.id);
      user.lastLogin = new Date().toISOString();
      pushLog(db, {
        level: "INFO", category: "AUTH",
        message: `Login for ${user.email} via password (no second factor enrolled).`,
        user: user.email, ipAddress: req.ip || "127.0.0.1", location: "Login",
      });
      saveDb(db);
      return res.json({ authenticated: true, user: sanitizeUser(user) });
    }

    return res.json({
      mfaRequired: true,
      methods: factors,
      pendingToken: newPending(user.id),
      email: user.email,
    });
  });

  // Step 2a: TOTP second factor.
  router.post("/mfa/totp", async (req, res) => {
    const userId = takePending(req.body?.pendingToken);
    if (!userId) return res.status(400).json({ error: "Login session expired. Please start over." });
    const db = loadDb();
    const user = findUser(db, userId);
    if (!user?.totp?.verified) return res.status(400).json({ error: "TOTP is not available for this account." });

    if (!(await isValidTotp(user.totp.secret, String(req.body?.code || "")))) {
      pushLog(db, {
        level: "WARN", category: "AUTH",
        message: `Failed TOTP step-up for ${user.email}.`,
        user: user.email, ipAddress: req.ip || "127.0.0.1", location: "Login MFA",
      });
      saveDb(db);
      return res.status(401).json({ error: "Invalid authenticator code." });
    }

    pending.delete(req.body.pendingToken);
    createSession(res, user.id);
    user.lastLogin = new Date().toISOString();
    pushLog(db, {
      level: "INFO", category: "AUTH",
      message: `Login completed for ${user.email} with password + TOTP.`,
      user: user.email, ipAddress: req.ip || "127.0.0.1", location: "Login MFA",
    });
    saveDb(db);
    res.json({ authenticated: true, user: sanitizeUser(user) });
  });

  // Step 2b: passkey second factor.
  router.post("/mfa/passkey/options", async (req, res) => {
    const userId = takePending(req.body?.pendingToken);
    if (!userId) return res.status(400).json({ error: "Login session expired. Please start over." });
    const db = loadDb();
    const user = findUser(db, userId);
    if (!user?.passkeys?.length) return res.status(400).json({ error: "No passkey enrolled for this account." });

    const options = await startPasskeyAuth(user, config);
    saveDb(db);
    res.json(options);
  });

  router.post("/mfa/passkey/verify", async (req, res) => {
    const userId = takePending(req.body?.pendingToken);
    if (!userId) return res.status(400).json({ error: "Login session expired. Please start over." });
    const db = loadDb();
    const user = findUser(db, userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    const result = await finishPasskeyAuth(user, req.body?.response, config);
    if (!result.verified) {
      saveDb(db);
      return res.status(401).json({ error: result.error || "Passkey verification failed." });
    }

    pending.delete(req.body.pendingToken);
    createSession(res, user.id);
    user.lastLogin = new Date().toISOString();
    pushLog(db, {
      level: "INFO", category: "AUTH",
      message: `Login completed for ${user.email} with password + passkey.`,
      user: user.email, ipAddress: req.ip || "127.0.0.1", location: "Login MFA",
    });
    saveDb(db);
    res.json({ authenticated: true, user: sanitizeUser(user) });
  });

  // --- Passwordless passkey login (no email/password) ---------------------
  // Challenges are held here (not on a user, since we don't know who yet) and
  // are single-use with a short TTL.
  const loginChallenges = new Map<string, number>();
  const rememberChallenge = (c: string) => loginChallenges.set(c, Date.now() + PENDING_TTL_MS);
  const consumeChallenge = (c: string): boolean => {
    const exp = loginChallenges.get(c);
    loginChallenges.delete(c);
    return !!exp && Date.now() <= exp;
  };

  router.post("/passkey/login/options", async (req, res) => {
    const options = await generateDiscoverableAuthOptions(config);
    rememberChallenge(options.challenge);
    res.json(options);
  });

  router.post("/passkey/login/verify", async (req, res) => {
    const response = req.body?.response;
    if (!response?.id) return res.status(400).json({ error: "Missing passkey response." });

    const db = loadDb();
    // Resolve the user from the credential id in the assertion.
    let owner: User | undefined;
    let passkey;
    for (const u of db.users) {
      const pk = (u.passkeys || []).find((p) => p.id === response.id);
      if (pk) { owner = u; passkey = pk; break; }
    }
    if (!owner || !passkey) return res.status(401).json({ error: "Unrecognized passkey." });
    if (owner.status === "Offboarded" || owner.status === "Suspended") {
      return res.status(403).json({ error: `This account is ${owner.status.toLowerCase()}.` });
    }

    const result = await verifyPasskeyAssertion(passkey, response, consumeChallenge, config);
    if (!result.verified) {
      pushLog(db, {
        level: "WARN", category: "AUTH",
        message: `Failed passwordless passkey login for ${owner.email}.`,
        user: owner.email, ipAddress: req.ip || "127.0.0.1", location: "Passkey Login",
      });
      saveDb(db);
      return res.status(401).json({ error: result.error || "Passkey verification failed." });
    }

    passkey.counter = result.newCounter!;
    createSession(res, owner.id);
    owner.lastLogin = new Date().toISOString();
    pushLog(db, {
      level: "INFO", category: "AUTH",
      message: `Passwordless login for ${owner.email} via passkey (biometric).`,
      user: owner.email, ipAddress: req.ip || "127.0.0.1", location: "Passkey Login",
    });
    saveDb(db);
    res.json({ authenticated: true, user: sanitizeUser(owner) });
  });

  // Current session.
  router.get("/me", (req, res) => {
    const user = getSessionUser(req);
    res.json({ authenticated: !!user, user: user ? sanitizeUser(user) : null });
  });

  router.post("/logout", (req, res) => {
    destroySession(req, res);
    res.json({ success: true });
  });

  return router;
}
