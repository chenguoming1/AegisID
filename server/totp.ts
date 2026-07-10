import { Router } from "express";
import { generateSecret, generateURI, verify } from "otplib";
import QRCode from "qrcode";
import { loadDb, saveDb, findUser, pushLog, sanitizeUser } from "./store";

// ---------------------------------------------------------------------------
// REAL TOTP (RFC 6238) multi-factor authentication.
//
// Unlike the simulated rolling code in the phone widget, these codes are real:
// a per-user base32 secret is generated, encoded into an otpauth:// URI + QR,
// and scanned with any standard authenticator app (Google Authenticator, Authy,
// Microsoft Authenticator, 1Password...). The server verifies codes with the
// same HMAC-based algorithm the app uses. No third party or account required.
// ---------------------------------------------------------------------------

const ISSUER = "AegisID";

// Allow +/- one 30s time-step of clock skew between phone and server.
const EPOCH_TOLERANCE = 30;

export async function isValidTotp(secret: string, token: string): Promise<boolean> {
  const clean = token.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(clean)) return false;
  const result = await verify({ secret, token: clean, epochTolerance: EPOCH_TOLERANCE });
  return result.valid;
}

export function totpRouter(): Router {
  const router = Router();

  // Begin enrollment: mint a secret and return a scannable QR + manual key.
  router.post("/enroll", async (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    const secret = generateSecret(); // base32, 160-bit
    user.totp = { secret, verified: false, createdAt: new Date().toISOString() };
    saveDb(db);

    const otpauthUri = generateURI({ issuer: ISSUER, label: user.email, secret });
    const qrDataUrl = await QRCode.toDataURL(otpauthUri, { margin: 1, width: 240 });

    res.json({
      success: true,
      // The secret is returned only during enrollment so the user can add it
      // to their authenticator; it is never exposed again via /api/db.
      manualEntryKey: secret,
      otpauthUri,
      qrDataUrl,
      issuer: ISSUER,
      account: user.email,
      user: sanitizeUser(user),
    });
  });

  // Confirm enrollment by proving the user scanned the secret.
  router.post("/verify", async (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!user.totp) return res.status(400).json({ error: "No TOTP enrollment in progress. Start enrollment first." });

    if (!(await isValidTotp(user.totp.secret, String(req.body?.token || "")))) {
      pushLog(db, {
        level: "WARN",
        category: "MFA",
        message: `TOTP enrollment verification failed for ${user.email} (invalid or expired code).`,
        user: user.email,
        ipAddress: req.ip || "127.0.0.1",
        location: "TOTP Enrollment",
      });
      saveDb(db);
      return res.status(400).json({ success: false, error: "Invalid code. Check your authenticator app and try again." });
    }

    user.totp.verified = true;
    user.mfaEnabled = true;
    user.mfaType = "TOTP";
    const log = pushLog(db, {
      level: "INFO",
      category: "MFA",
      message: `TOTP authenticator enrolled and verified for ${user.email}. RFC 6238 second factor active.`,
      user: user.email,
      ipAddress: req.ip || "127.0.0.1",
      location: "TOTP Enrollment",
    });
    saveDb(db);
    res.json({ success: true, verified: true, user: sanitizeUser(user), log });
  });

  // Login-time validation of a code against a verified enrollment.
  router.post("/validate", async (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!user.totp?.verified) return res.status(400).json({ error: "TOTP is not enrolled for this user." });

    const valid = await isValidTotp(user.totp.secret, String(req.body?.token || ""));
    pushLog(db, {
      level: valid ? "INFO" : "WARN",
      category: "AUTH",
      message: valid
        ? `Successful TOTP second-factor verification for ${user.email}.`
        : `Failed TOTP second-factor attempt for ${user.email} (invalid code).`,
      user: user.email,
      ipAddress: req.ip || "127.0.0.1",
      location: "MFA Challenge",
    });
    if (valid) user.lastLogin = new Date().toISOString();
    saveDb(db);
    res.status(valid ? 200 : 400).json({ success: valid, verified: valid });
  });

  // Remove the enrollment.
  router.post("/disable", (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    delete user.totp;
    pushLog(db, {
      level: "WARN",
      category: "MFA",
      message: `TOTP authenticator removed for ${user.email}.`,
      user: user.email,
      ipAddress: req.ip || "127.0.0.1",
      location: "MFA Settings",
    });
    saveDb(db);
    res.json({ success: true, user: sanitizeUser(user) });
  });

  return router;
}
