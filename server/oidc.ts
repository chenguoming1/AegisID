import { Router } from "express";
import crypto from "crypto";
import { loadDb, saveDb, pushLog, findUserByEmail, jitCreateUser } from "./store";
import { createSession } from "./session";

// ---------------------------------------------------------------------------
// REAL OpenID Connect single sign-on (Authorization Code + PKCE).
//
// Point AegisID at any standard OIDC provider — a local Keycloak in Docker is
// the zero-account option. A successful sign-in maps the federated identity to
// a directory user (creating one just-in-time if needed) and establishes the
// same app session that the password/MFA login uses.
//
// Everything is guarded: with no OIDC_ISSUER configured, these routes return a
// helpful "not configured" response and the rest of the app is unaffected.
// ---------------------------------------------------------------------------

interface OidcMeta {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
  issuer: string;
}

const ISSUER = process.env.OIDC_ISSUER || ""; // e.g. http://localhost:8080/realms/aegisid
const CLIENT_ID = process.env.OIDC_CLIENT_ID || "";
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET || ""; // optional (public client uses PKCE only)

const isConfigured = () => Boolean(ISSUER && CLIENT_ID);

// Transient PKCE/state store (state -> verifier/nonce).
const pending = new Map<string, { verifier: string; nonce: string; createdAt: number }>();

let metaCache: OidcMeta | null = null;
async function discover(): Promise<OidcMeta> {
  if (metaCache) return metaCache;
  const url = `${ISSUER.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`OIDC discovery failed (${resp.status}) at ${url}`);
  metaCache = (await resp.json()) as OidcMeta;
  return metaCache;
}

const b64url = (buf: Buffer) => buf.toString("base64url");
function decodeJwtPayload(jwt: string): Record<string, any> {
  const [, payload] = jwt.split(".");
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf-8"));
}
function redirectUri(req: any): string {
  return process.env.OIDC_REDIRECT_URI || `${req.protocol}://${req.get("host")}/api/oidc/callback`;
}

export function oidcRouter(): Router {
  const router = Router();

  router.get("/status", (req, res) => {
    res.json({
      configured: isConfigured(),
      issuer: ISSUER || null,
      clientId: CLIENT_ID || null,
      redirectUri: isConfigured() ? redirectUri(req) : null,
      hint: isConfigured()
        ? "Ready. Use 'Sign in with Keycloak' to start a real OIDC sign-in."
        : "Set OIDC_ISSUER and OIDC_CLIENT_ID (see README) and restart to enable real SSO.",
    });
  });

  // Step 1: kick off the flow.
  router.get("/login", async (req, res) => {
    if (!isConfigured()) return res.redirect("/?oidc=unconfigured");
    try {
      const meta = await discover();
      const state = crypto.randomBytes(16).toString("hex");
      const nonce = crypto.randomBytes(16).toString("hex");
      const verifier = b64url(crypto.randomBytes(32));
      const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
      pending.set(state, { verifier, nonce, createdAt: Date.now() });

      const params = new URLSearchParams({
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: redirectUri(req),
        scope: "openid profile email",
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      res.redirect(`${meta.authorization_endpoint}?${params.toString()}`);
    } catch (err: any) {
      res.status(502).json({ error: err.message });
    }
  });

  // Step 3: provider redirects back here with ?code&state.
  router.get("/callback", async (req, res) => {
    if (!isConfigured()) return res.redirect("/?oidc=unconfigured");
    const { code, state, error } = req.query as Record<string, string>;
    if (error) return res.redirect(`/?oidc=error&reason=${encodeURIComponent(error)}`);

    const saved = state ? pending.get(state) : undefined;
    if (!code || !saved) return res.redirect("/?oidc=error&reason=invalid_state");
    pending.delete(state);

    try {
      const meta = await discover();
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri(req),
        client_id: CLIENT_ID,
        code_verifier: saved.verifier,
      });
      if (CLIENT_SECRET) body.set("client_secret", CLIENT_SECRET);

      const tokenResp = await fetch(meta.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      if (!tokenResp.ok) return res.redirect(`/?oidc=error&reason=token_exchange_failed`);
      const tokens = (await tokenResp.json()) as { id_token?: string };
      if (!tokens.id_token) return res.redirect("/?oidc=error&reason=no_id_token");

      // The tokens came straight from the provider's token endpoint over the
      // back channel, so the claims are trustworthy. (Production should still
      // verify the JWT signature against the provider's JWKS.)
      const claims = decodeJwtPayload(tokens.id_token);
      if (saved.nonce && claims.nonce && claims.nonce !== saved.nonce) {
        return res.redirect("/?oidc=error&reason=nonce_mismatch");
      }
      const email = claims.email || claims.preferred_username;
      if (!email) return res.redirect("/?oidc=error&reason=no_email_claim");

      // Map the federated identity to a directory user (JIT-provision if new).
      const db = loadDb();
      let user = findUserByEmail(db, email);
      if (!user) {
        user = jitCreateUser(db, email, claims.name || claims.preferred_username);
        pushLog(db, {
          level: "INFO", category: "PROVISIONING",
          message: `JIT-provisioned directory account for ${user.email} from OIDC (${claims.iss}).`,
          user: user.email, ipAddress: req.ip || "127.0.0.1", location: "OIDC Provider",
        });
      }
      user.lastLogin = new Date().toISOString();
      pushLog(db, {
        level: "INFO", category: "SSO",
        message: `OIDC single sign-on completed for ${user.email} via ${claims.iss}.`,
        user: user.email, ipAddress: req.ip || "127.0.0.1", location: "OIDC Provider",
      });
      saveDb(db);

      createSession(res, user.id);
      res.redirect("/?login=oidc");
    } catch (err: any) {
      res.redirect(`/?oidc=error&reason=${encodeURIComponent(err.message || "callback_failed")}`);
    }
  });

  return router;
}
