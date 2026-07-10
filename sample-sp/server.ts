import express from "express";
import crypto from "crypto";
import { ServiceProvider, IdentityProvider, setSchemaValidator, IdentityProviderInstance } from "samlify";
import { scimRouter, listGlobexUsers, findGlobexUser, jitProvisionGlobexUser } from "./scim";

// ---------------------------------------------------------------------------
// Sample enterprise application: "Globex Industries Intranet".
//
// A completely separate web app that trusts AegisID for login via REAL
// SAML 2.0 (SP-initiated SSO):
//   1. /login       -> builds an AuthnRequest and redirects to AegisID's IdP
//   2. AegisID authenticates the user and POSTs a signed SAMLResponse back
//   3. /acs         -> verifies the RSA-SHA256 signature against the IdP
//                      certificate (fetched from IdP metadata), validates
//                      conditions, and creates a local app session
//
// Run with:  npm run sp        (defaults: port 3400, IdP at localhost:3000)
//            AEGIS_URL=http://localhost:3200 npm run sp
// ---------------------------------------------------------------------------

setSchemaValidator({ validate: () => Promise.resolve("skipped") });

const SP_PORT = Number(process.env.SP_PORT) || 3400;
const SP_URL = process.env.SAMPLE_SP_URL || `http://localhost:${SP_PORT}`;
const AEGIS_URL = process.env.AEGIS_URL || "http://localhost:3000";

const sp = ServiceProvider({
  entityID: `${SP_URL}/saml/metadata`,
  assertionConsumerService: [
    { Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: `${SP_URL}/acs` },
  ],
  wantAssertionsSigned: true,
  authnRequestsSigned: false,
  relayState: "/",
});

// The IdP is discovered from AegisID's published metadata — exactly how a real
// SP admin would configure "Sign in with <your IdP>".
let idpCache: IdentityProviderInstance | null = null;
async function getIdp(): Promise<IdentityProviderInstance> {
  if (idpCache) return idpCache;
  const resp = await fetch(`${AEGIS_URL}/saml/metadata`);
  if (!resp.ok) throw new Error(`Could not fetch IdP metadata from ${AEGIS_URL}/saml/metadata (${resp.status})`);
  const metadata = await resp.text();
  idpCache = IdentityProvider({ metadata, wantAuthnRequestsSigned: false });
  return idpCache;
}

// Minimal cookie session
interface SpSession {
  nameID: string;
  attributes: Record<string, string | string[]>;
  issuer: string;
  authnInstant: string;
  rawResponse: string;
}
const attrText = (v: string | string[]) => (Array.isArray(v) ? v.join(", ") : v);
const sessions = new Map<string, SpSession>();
const readSid = (req: express.Request): string | null => {
  const m = (req.headers.cookie || "").match(/globex_sid=([^;]+)/);
  return m ? m[1] : null;
};
const getSession = (req: express.Request): SpSession | null => {
  const sid = readSid(req);
  return sid ? sessions.get(sid) || null : null;
};

const esc = (s: string) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const page = (title: string, body: string) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title} — Globex Industries</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; flex-direction: column; }
    header { background: #1e293b; border-bottom: 1px solid #334155; padding: 14px 28px; display: flex; align-items: center; justify-content: space-between; }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 800; letter-spacing: 0.04em; font-size: 15px; color: #f8fafc; }
    .brand .logo { width: 30px; height: 30px; border-radius: 8px; background: linear-gradient(135deg, #6366f1, #8b5cf6); display: flex; align-items: center; justify-content: center; font-size: 15px; }
    .tag { font-size: 10px; color: #818cf8; border: 1px solid #4c4f9455; background: #6366f11a; padding: 2px 8px; border-radius: 99px; text-transform: uppercase; letter-spacing: 0.1em; }
    main { flex: 1; display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 32px; max-width: 660px; width: 100%; box-shadow: 0 20px 60px #0007; }
    h1 { font-size: 20px; color: #f8fafc; margin-bottom: 6px; }
    p.sub { font-size: 13px; color: #94a3b8; line-height: 1.6; margin-bottom: 22px; }
    .btn { display: inline-flex; align-items: center; gap: 8px; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; border: none; padding: 12px 22px; font-size: 14px; font-weight: 600; border-radius: 10px; cursor: pointer; text-decoration: none; }
    .btn:hover { filter: brightness(1.1); }
    .btn.ghost { background: transparent; border: 1px solid #475569; color: #cbd5e1; font-size: 12px; padding: 8px 16px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; margin: 14px 0 20px; }
    th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid #334155; }
    th { color: #64748b; font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; }
    td.k { color: #94a3b8; font-family: ui-monospace, monospace; font-size: 12px; }
    td.v { color: #f1f5f9; font-weight: 600; }
    .ok { display: inline-flex; align-items: center; gap: 6px; color: #34d399; font-size: 12px; font-weight: 700; background: #10b98114; border: 1px solid #10b98133; padding: 5px 12px; border-radius: 99px; margin-bottom: 18px; }
    details { margin-top: 18px; font-size: 12px; }
    summary { cursor: pointer; color: #818cf8; font-weight: 600; }
    pre { margin-top: 10px; background: #0b1120; border: 1px solid #1e293b; padding: 14px; border-radius: 10px; overflow-x: auto; font-size: 10.5px; line-height: 1.5; color: #7dd3fc; max-height: 320px; }
    .err { background: #7f1d1d33; border: 1px solid #dc262655; color: #fca5a5; padding: 12px 16px; border-radius: 10px; font-size: 13px; margin-bottom: 18px; }
    footer { text-align: center; font-size: 11px; color: #475569; padding: 18px; border-top: 1px solid #1e293b; }
  </style>
</head>
<body>
  <header>
    <div class="brand"><span class="logo">G</span> GLOBEX INDUSTRIES <span class="tag">Intranet</span></div>
    <span style="font-size:11px;color:#64748b">Sample Service Provider · SAML 2.0</span>
  </header>
  <main>${body}</main>
  <footer>Globex Industries — a sample enterprise application federated with AegisID via SAML 2.0</footer>
</body>
</html>`;

async function startSp() {
  const app = express();
  app.use(express.urlencoded({ extended: false }));

  // SP metadata (XML) — what you'd hand to the IdP admin in a real rollout.
  app.get("/saml/metadata", (req, res) => {
    res.type("application/xml").send(sp.getMetadata());
  });

  // REAL SCIM 2.0 provisioning API — AegisID pushes user lifecycle events here.
  app.use("/scim/v2", scimRouter());

  // App-side user directory: everything Globex knows about its users, whether
  // pushed by the IdP over SCIM or JIT-created at first SSO login.
  app.get("/directory", (req, res) => {
    const users = listGlobexUsers();
    const rows = users.length
      ? users.map((u) => `
        <tr>
          <td class="v">${esc(u.displayName)}</td>
          <td class="k">${esc(u.userName)}</td>
          <td>${u.active
            ? '<span class="ok" style="margin:0;padding:3px 10px">ACTIVE</span>'
            : '<span class="ok" style="margin:0;padding:3px 10px;color:#f87171;background:#dc262614;border-color:#dc262633">DEACTIVATED</span>'}</td>
          <td class="k">${u.source === "scim" ? "SCIM push (IdP)" : "JIT (first SSO login)"}</td>
          <td class="k">${esc(u.role || "—")} / ${esc(u.department || "—")}</td>
          <td class="k">${esc(u.updatedAt.slice(0, 19).replace("T", " "))}</td>
        </tr>`).join("")
      : `<tr><td colspan="6" class="k" style="text-align:center;padding:22px">No accounts yet. Provision or assign a user in AegisID to push one here over SCIM.</td></tr>`;

    res.send(page("User directory", `
      <div class="card" style="max-width:860px">
        <h1>Globex user directory</h1>
        <p class="sub">Accounts this application knows about — independent of any login session. <b>SCIM push</b> rows were created/updated by AegisID calling <span style="font-family:ui-monospace,monospace">/scim/v2/Users</span> over HTTP; <b>JIT</b> rows appeared at a user's first SSO sign-in. Deactivated accounts cannot sign in even with a valid SAML assertion.</p>
        <table>
          <tr><th>Name</th><th>userName</th><th>Status</th><th>Provisioned via</th><th>Role / Dept</th><th>Last sync</th></tr>
          ${rows}
        </table>
        <a class="btn ghost" href="/">&larr; Back</a>
      </div>`));
  });

  // Landing / dashboard
  app.get("/", async (req, res) => {
    const session = getSession(req);
    if (!session) {
      let idpStatus = "";
      try {
        await getIdp();
      } catch {
        idpStatus = `<div class="err">Cannot reach the AegisID IdP at <b>${esc(AEGIS_URL)}</b>. Start it first (npm run dev), or set AEGIS_URL.</div>`;
      }
      return res.send(page("Sign in", `
        <div class="card" style="max-width:460px;text-align:center">
          <h1>Globex Employee Intranet</h1>
          <p class="sub">This application does not manage passwords. Sign-in is federated to your company identity provider over SAML 2.0.</p>
          ${idpStatus}
          <a class="btn" href="/login">&#128737; Sign in with AegisID SSO</a>
          <p class="sub" style="margin:18px 0 0;font-size:11px">You will be redirected to AegisID, authenticated there, and returned with a digitally signed assertion.</p>
          <p style="margin-top:14px"><a href="/directory" style="font-size:11px;color:#818cf8;text-decoration:none">View the SCIM-provisioned user directory &rarr;</a></p>
        </div>`));
    }

    const rows = Object.entries(session.attributes)
      .map(([k, v]) => `<tr><td class="k">${esc(k)}</td><td class="v">${esc(attrText(v))}</td></tr>`)
      .join("");
    res.send(page("Dashboard", `
      <div class="card">
        <div class="ok">&#10003; SAML RESPONSE SIGNATURE VERIFIED (RSA-SHA256)</div>
        <h1>Welcome, ${esc(attrText(session.attributes.displayName || session.nameID))}</h1>
        <p class="sub">You are signed in to Globex via single sign-on. No Globex password exists for this account — identity was asserted by <b>${esc(session.issuer)}</b> and verified against its X.509 certificate.</p>
        <table>
          <tr><th>SAML claim</th><th>Value</th></tr>
          <tr><td class="k">NameID (subject)</td><td class="v">${esc(session.nameID)}</td></tr>
          ${rows}
          <tr><td class="k">AuthnInstant</td><td class="v">${esc(session.authnInstant)}</td></tr>
        </table>
        <div style="display:flex;gap:10px">
          <a class="btn ghost" href="/logout">Sign out of Globex</a>
          <a class="btn ghost" href="/directory">View user directory (SCIM)</a>
        </div>
        <details>
          <summary>Inspect the raw signed SAMLResponse XML</summary>
          <pre>${esc(session.rawResponse)}</pre>
        </details>
      </div>`));
  });

  // SP-initiated SSO: build AuthnRequest, redirect to the IdP.
  app.get("/login", async (req, res) => {
    try {
      const idp = await getIdp();
      const { context } = sp.createLoginRequest(idp, "redirect");
      res.redirect(context);
    } catch (err: any) {
      res.status(502).send(page("Error", `<div class="card"><div class="err">${esc(err.message)}</div><a class="btn ghost" href="/">Back</a></div>`));
    }
  });

  // Assertion Consumer Service: verify the signed SAMLResponse, start a session.
  app.post("/acs", async (req, res) => {
    try {
      const idp = await getIdp();
      const parsed = await sp.parseLoginResponse(idp, "post", req);
      const { nameID, attributes, issuer } = parsed.extract;

      // App-side account check (the SCIM layer): a deactivated Globex account
      // cannot sign in even with a cryptographically valid assertion. Unknown
      // users are JIT-provisioned on first login.
      const account = findGlobexUser(nameID);
      if (account && !account.active) {
        return res.status(403).send(page("Account deactivated", `
          <div class="card" style="max-width:460px;text-align:center">
            <h1>Account deactivated</h1>
            <p class="sub">Your SAML assertion was valid, but the Globex account for <b>${esc(nameID)}</b> has been <b style="color:#f87171">deactivated</b> by your organization's identity provider (SCIM deprovisioning). Contact your IT administrator.</p>
            <a class="btn ghost" href="/">Back</a>
          </div>`));
      }
      if (!account) {
        jitProvisionGlobexUser(nameID, attrText(attributes?.displayName || nameID));
      }

      const sid = crypto.randomUUID();
      sessions.set(sid, {
        nameID,
        attributes: attributes || {},
        issuer: Array.isArray(issuer) ? issuer[0] : issuer,
        authnInstant: attrText(parsed.extract.sessionIndex?.authnInstant || new Date().toISOString()),
        rawResponse: Buffer.from(req.body.SAMLResponse, "base64").toString("utf-8"),
      });
      res.setHeader("Set-Cookie", `globex_sid=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=3600`);
      res.redirect(typeof req.body.RelayState === "string" && req.body.RelayState.startsWith("/") ? req.body.RelayState : "/");
    } catch (err: any) {
      console.error("[Globex SP] ACS verification failed:", err);
      res.status(401).send(page("Access denied", `
        <div class="card">
          <div class="err"><b>SAML assertion rejected:</b> ${esc(String(err.message || err))}</div>
          <p class="sub">The response failed signature or condition validation against the IdP certificate.</p>
          <a class="btn ghost" href="/">Back</a>
        </div>`));
    }
  });

  app.get("/logout", (req, res) => {
    const sid = readSid(req);
    if (sid) sessions.delete(sid);
    res.setHeader("Set-Cookie", "globex_sid=; HttpOnly; Path=/; Max-Age=0");
    res.redirect("/");
  });

  app.listen(SP_PORT, "0.0.0.0", () => {
    console.log(`[Globex SP] Sample enterprise app running on ${SP_URL}`);
    console.log(`[Globex SP] Trusting IdP metadata at ${AEGIS_URL}/saml/metadata`);
  });
}

startSp();
