import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { loadDb, saveDb, findUser, pushLog, sanitizeUser, PasskeyRecord, User } from "./store";

// ---------------------------------------------------------------------------
// REAL WebAuthn / passkeys.
//
// This triggers the browser + OS's genuine platform authenticator — Touch ID,
// Face ID, Windows Hello, or a security key. The private key is created and
// held in the device's secure enclave and never leaves it; the server only
// ever stores the public key and a signature counter. This is the real,
// phishing-resistant version of the "fingerprint approve" in the phone widget.
// No third party or enterprise account required.
// ---------------------------------------------------------------------------

const RP_NAME = "AegisID";

export interface WebAuthnConfig {
  rpID: string; // e.g. "localhost"
  origins: string[]; // e.g. ["http://localhost:3200"]
}

function b64(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64");
}
function unb64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
}

// --- Shared passkey-authentication helpers (used by the enrollment router
// below AND by the login flow in auth.ts). They mutate the user's transient
// challenge / credential counter; the caller is responsible for persisting. ---
export async function startPasskeyAuth(user: User, config: WebAuthnConfig) {
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    allowCredentials: (user.passkeys || []).map((p) => ({ id: p.id, transports: p.transports as any })),
    userVerification: "required",
  });
  user.webauthnChallenge = options.challenge;
  return options;
}

export async function finishPasskeyAuth(
  user: User,
  response: any,
  config: WebAuthnConfig,
): Promise<{ verified: boolean; error?: string }> {
  if (!user.webauthnChallenge) return { verified: false, error: "No authentication challenge in progress." };
  const passkey = (user.passkeys || []).find((p) => p.id === response?.id);
  if (!passkey) return { verified: false, error: "Passkey not recognized for this user." };

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.webauthnChallenge,
      expectedOrigin: config.origins,
      expectedRPID: config.rpID,
      credential: {
        id: passkey.id,
        publicKey: unb64(passkey.publicKey),
        counter: passkey.counter,
        transports: passkey.transports as any,
      },
    });
  } catch (err: any) {
    return { verified: false, error: err.message };
  }

  if (!verification.verified) return { verified: false, error: "Passkey signature verification failed." };
  passkey.counter = verification.authenticationInfo.newCounter;
  delete user.webauthnChallenge;
  return { verified: true };
}

// Passwordless (usernameless / discoverable-credential) login: no allowCredentials,
// so the browser offers any passkey registered for this relying party. The user is
// resolved afterwards from the credential id carried in the response.
export async function generateDiscoverableAuthOptions(config: WebAuthnConfig) {
  return generateAuthenticationOptions({ rpID: config.rpID, userVerification: "required" });
}

// Verify an assertion against a known credential, with the challenge supplied
// externally (a string, or a validator function for the usernameless flow where
// the challenge isn't stored on a user record).
export async function verifyPasskeyAssertion(
  passkey: PasskeyRecord,
  response: any,
  expectedChallenge: string | ((c: string) => boolean | Promise<boolean>),
  config: WebAuthnConfig,
): Promise<{ verified: boolean; newCounter?: number; error?: string }> {
  try {
    const v = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.origins,
      expectedRPID: config.rpID,
      credential: {
        id: passkey.id,
        publicKey: unb64(passkey.publicKey),
        counter: passkey.counter,
        transports: passkey.transports as any,
      },
    });
    if (!v.verified) return { verified: false, error: "Signature verification failed." };
    return { verified: true, newCounter: v.authenticationInfo.newCounter };
  } catch (err: any) {
    return { verified: false, error: err.message };
  }
}

export function webauthnRouter(config: WebAuthnConfig): Router {
  const router = Router();
  const { rpID, origins } = config;

  // --- Registration: create a new passkey ---------------------------------
  router.post("/register/options", async (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID,
      userName: user.email,
      userDisplayName: user.fullName,
      userID: new TextEncoder().encode(user.id),
      attestationType: "none",
      excludeCredentials: (user.passkeys || []).map((p) => ({
        id: p.id,
        transports: p.transports as any,
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        // Require a real user-verification gesture (Touch ID / Face ID / PIN) at
        // registration so the credential is created with the UV flag set. This
        // keeps it consistent with verifyAuthenticationResponse, which requires
        // user verification by default.
        userVerification: "required",
      },
    });

    user.webauthnChallenge = options.challenge;
    saveDb(db);
    res.json(options);
  });

  router.post("/register/verify", async (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!user.webauthnChallenge) return res.status(400).json({ error: "No registration challenge in progress." });

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body.response,
        expectedChallenge: user.webauthnChallenge,
        expectedOrigin: origins,
        expectedRPID: rpID,
      });
    } catch (err: any) {
      return res.status(400).json({ success: false, error: err.message });
    }

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ success: false, error: "Passkey registration could not be verified." });
    }

    const { credential, credentialDeviceType } = verification.registrationInfo;
    const record: PasskeyRecord = {
      id: credential.id,
      publicKey: b64(credential.publicKey),
      counter: credential.counter,
      transports: req.body.response?.response?.transports || credential.transports,
      label: credentialDeviceType === "multiDevice" ? "Synced passkey" : "Device passkey",
      createdAt: new Date().toISOString(),
    };

    user.passkeys = [...(user.passkeys || []), record];
    user.biometricRegistered = true;
    delete user.webauthnChallenge;

    const log = pushLog(db, {
      level: "INFO",
      category: "MFA",
      message: `WebAuthn passkey registered for ${user.email} (${record.label}). Public-key credential bound to device secure enclave.`,
      user: user.email,
      ipAddress: req.ip || "127.0.0.1",
      location: "Passkey Enrollment",
    });
    saveDb(db);
    res.json({ success: true, verified: true, passkey: { id: record.id, label: record.label, createdAt: record.createdAt }, user: sanitizeUser(user), log });
  });

  // --- Authentication: sign in with an existing passkey -------------------
  router.post("/authenticate/options", async (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!user.passkeys?.length) return res.status(400).json({ error: "No passkeys registered for this user." });

    const options = await startPasskeyAuth(user, config);
    saveDb(db);
    res.json(options);
  });

  router.post("/authenticate/verify", async (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    const result = await finishPasskeyAuth(user, req.body.response, config);
    if (!result.verified) {
      pushLog(db, {
        level: "WARN",
        category: "AUTH",
        message: `WebAuthn passkey authentication failed for ${user.email}.`,
        user: user.email,
        ipAddress: req.ip || "127.0.0.1",
        location: "Passkey Login",
      });
      saveDb(db);
      return res.status(400).json({ success: false, error: result.error || "Passkey verification failed." });
    }

    user.lastLogin = new Date().toISOString();

    const log = pushLog(db, {
      level: "INFO",
      category: "AUTH",
      message: `WebAuthn passkey authentication succeeded for ${user.email}. Biometric assertion verified against stored public key.`,
      user: user.email,
      ipAddress: req.ip || "127.0.0.1",
      location: "Passkey Login",
    });
    saveDb(db);
    res.json({ success: true, verified: true, user: sanitizeUser(user), log });
  });

  router.post("/remove", (req, res) => {
    const db = loadDb();
    const user = findUser(db, req.body?.userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    user.passkeys = (user.passkeys || []).filter((p) => p.id !== req.body?.credentialId);
    if (!user.passkeys.length) user.biometricRegistered = false;
    pushLog(db, {
      level: "WARN",
      category: "MFA",
      message: `WebAuthn passkey removed for ${user.email}.`,
      user: user.email,
      ipAddress: req.ip || "127.0.0.1",
      location: "Passkey Settings",
    });
    saveDb(db);
    res.json({ success: true, user: sanitizeUser(user) });
  });

  return router;
}
