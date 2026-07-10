import { Router } from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { IdentityProvider, ServiceProvider, SamlLib, Constants, setSchemaValidator } from "samlify";
import selfsigned from "selfsigned";
import { loadDb, saveDb, pushLog, User } from "./store";
import { getSessionUser } from "./session";

// ---------------------------------------------------------------------------
// REAL SAML 2.0 Identity Provider.
//
// This is the "enterprise" half of AegisID made real: it publishes IdP
// metadata with an X.509 signing certificate and answers SP-initiated
// AuthnRequests at /saml/sso with an RSA-SHA256-signed SAMLResponse
// (signed Assertion, InResponseTo, audience restriction, NameID + attribute
// statement). Any standards-compliant Service Provider can federate with it —
// the bundled sample app in sample-sp/ is wired up out of the box.
//
// XML schema validation is stubbed (samlify offloads it to an optional
// xmllint module); signatures, conditions and bindings are fully enforced.
// ---------------------------------------------------------------------------

setSchemaValidator({ validate: () => Promise.resolve("skipped") });

const KEYS_FILE = path.join(process.cwd(), "saml-keys.json");
const binding = Constants.namespace.binding;

export const SAML_ATTRIBUTES = [
  { name: "email", valueTag: "user.email", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
  { name: "displayName", valueTag: "user.displayName", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
  { name: "role", valueTag: "user.role", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
  { name: "department", valueTag: "user.department", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
];

interface SamlKeys {
  privateKey: string;
  cert: string;
  createdAt: string;
}

// Load (or mint on first boot) the IdP's RSA signing keypair + self-signed cert.
async function loadOrCreateKeys(): Promise<SamlKeys> {
  try {
    if (fs.existsSync(KEYS_FILE)) {
      return JSON.parse(fs.readFileSync(KEYS_FILE, "utf-8"));
    }
  } catch {
    // fall through and regenerate
  }
  const pems = await selfsigned.generate([{ name: "commonName", value: "aegisid.local" }], {
    keySize: 2048,
    algorithm: "sha256",
    notAfterDate: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
  });
  const keys: SamlKeys = { privateKey: pems.private, cert: pems.cert, createdAt: new Date().toISOString() };
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2), "utf-8");
  console.log("[SAML IdP] Generated new RSA signing keypair + self-signed certificate (saml-keys.json)");
  return keys;
}

export interface SamlIdpConfig {
  idpBaseUrl: string; // e.g. http://localhost:3200
  spBaseUrl: string; // e.g. http://localhost:3400
}

// Convention shared with the sample SP: entityID = <base>/saml/metadata, ACS = <base>/acs.
export function spSettings(spBaseUrl: string) {
  return {
    entityID: `${spBaseUrl}/saml/metadata`,
    assertionConsumerService: [{ Binding: binding.post, Location: `${spBaseUrl}/acs` }],
    wantAssertionsSigned: true,
    authnRequestsSigned: false,
  };
}

export async function samlIdpRouter(config: SamlIdpConfig): Promise<Router> {
  const keys = await loadOrCreateKeys();
  const idpEntityId = `${config.idpBaseUrl}/saml/metadata`;
  const acsUrl = `${config.spBaseUrl}/acs`;
  const spEntityId = `${config.spBaseUrl}/saml/metadata`;

  const idp = IdentityProvider({
    entityID: idpEntityId,
    privateKey: keys.privateKey,
    signingCert: keys.cert,
    wantAuthnRequestsSigned: false,
    nameIDFormat: ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"],
    singleSignOnService: [
      { Binding: binding.redirect, Location: `${config.idpBaseUrl}/saml/sso` },
      { Binding: binding.post, Location: `${config.idpBaseUrl}/saml/sso` },
    ],
    loginResponseTemplate: { context: SamlLib.defaultLoginResponseTemplate.context, attributes: SAML_ATTRIBUTES },
  });

  // IdP-side view of the registered SP (built from the shared convention, so no
  // metadata exchange step is needed for the local sample app).
  const sp = ServiceProvider(spSettings(config.spBaseUrl));

  // Build the signed SAMLResponse for an authenticated directory user.
  const buildLoginResponse = async (user: User, requestInfo: any, relayState?: string) => {
    const now = new Date();
    const fiveMin = new Date(now.getTime() + 5 * 60 * 1000);
    const responseId = "_" + crypto.randomBytes(16).toString("hex");
    const assertionId = "_" + crypto.randomBytes(16).toString("hex");
    const inResponseTo = requestInfo?.extract?.request?.id || "";

    const createTemplateCallback = (template: string) => {
      const attributeStatement = SamlLib.attributeStatementBuilder(SAML_ATTRIBUTES as any);
      const authnStatement = `<saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${responseId}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`;
      // XML fragments must be spliced in before tag replacement — replaceTagsByValue
      // XML-escapes every value it substitutes.
      const withFragments = template
        .replace("{AttributeStatement}", attributeStatement)
        .replace("{AuthnStatement}", authnStatement);
      const context = SamlLib.replaceTagsByValue(withFragments, {
        ID: responseId,
        AssertionID: assertionId,
        Destination: acsUrl,
        Audience: spEntityId,
        EntityID: spEntityId,
        SubjectRecipient: acsUrl,
        Issuer: idpEntityId,
        IssueInstant: now.toISOString(),
        AssertionConsumerServiceURL: acsUrl,
        StatusCode: "urn:oasis:names:tc:SAML:2.0:status:Success",
        ConditionsNotBefore: now.toISOString(),
        ConditionsNotOnOrAfter: fiveMin.toISOString(),
        SubjectConfirmationDataNotOnOrAfter: fiveMin.toISOString(),
        NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        NameID: user.email,
        InResponseTo: inResponseTo,
        attrUserEmail: user.email,
        attrUserDisplayName: user.fullName,
        attrUserRole: user.role,
        attrUserDepartment: user.department,
      });
      return { id: responseId, context };
    };

    const result = await idp.createLoginResponse(
      sp,
      requestInfo,
      "post",
      { email: user.email },
      createTemplateCallback,
      false,
      relayState,
    );
    return result as { id: string; context: string };
  };

  const router = Router();

  // IdP metadata (XML) — what a real SP admin would paste into their SSO config.
  router.get("/metadata", (req, res) => {
    res.type("application/xml").send(idp.getMetadata());
  });

  // Single Sign-On endpoint (HTTP-Redirect binding in, HTTP-POST binding out).
  router.get("/sso", async (req, res) => {
    // 1. The user must have an authenticated AegisID session. If not, bounce to
    //    the login screen with a continue URL so the flow resumes after login.
    const user = getSessionUser(req);
    if (!user) {
      return res.redirect(`/?samlContinue=${encodeURIComponent(req.originalUrl)}`);
    }
    if (user.status !== "Active") {
      return res.status(403).send("Your AegisID account is not active.");
    }

    try {
      // 2. Parse + validate the SP's AuthnRequest.
      const octetString = req.originalUrl.split("?")[1] || "";
      const loginRequest = await idp.parseLoginRequest(sp, "redirect", { query: req.query, octetString } as any);

      // 3. Authorization: the authenticated user must be ASSIGNED to the
      //    application this AuthnRequest came from. Being logged in to AegisID
      //    is not enough — this is the entitlement check a real IdP enforces,
      //    and what makes admin assign/unassign actually gate access.
      const db = loadDb();
      const rawIssuer = loginRequest?.extract?.issuer;
      const spIssuer = Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer;
      const appRecord = db.apps.find((a) => a.entityId === spIssuer);
      const directoryUser = db.users.find((u) => u.id === user.id);
      if (!appRecord || !directoryUser || !directoryUser.assignedApps.includes(appRecord.id)) {
        pushLog(db, {
          level: "WARN",
          category: "SSO",
          message: `SAML SSO denied for ${user.email}: not assigned to application ${appRecord?.name || spIssuer}. No assertion issued.`,
          user: user.email,
          ipAddress: req.ip || "127.0.0.1",
          location: "SAML IdP",
        });
        saveDb(db);
        return res.status(403).send(`<!DOCTYPE html>
<html>
  <head><title>AegisID — access denied</title></head>
  <body style="font-family: -apple-system, sans-serif; background:#09090b; color:#e4e4e7; display:flex; align-items:center; justify-content:center; height:100vh; margin:0;">
    <div style="max-width:420px; text-align:center; padding:32px; border:1px solid #27272a; border-radius:16px; background:#18181b;">
      <div style="font-size:34px; margin-bottom:10px;">&#128683;</div>
      <h1 style="font-size:16px; margin:0 0 8px; color:#fafafa;">Access denied</h1>
      <p style="font-size:13px; color:#a1a1aa; line-height:1.6; margin:0 0 18px;">
        Your AegisID account (<b style="color:#e4e4e7">${user.email}</b>) is not assigned to
        <b style="color:#e4e4e7">${appRecord?.name || "this application"}</b>.
        Contact your IT administrator to request access.
      </p>
      <a href="/" style="font-size:12px; color:#34d399; text-decoration:none; font-weight:600;">&larr; Back to AegisID portal</a>
    </div>
  </body>
</html>`);
      }

      // 4. Issue the signed SAMLResponse and auto-POST it to the SP's ACS.
      const relayState = typeof req.query.RelayState === "string" ? req.query.RelayState : "";
      const { context: samlResponse } = await buildLoginResponse(directoryUser, loginRequest, relayState);

      pushLog(db, {
        level: "INFO",
        category: "SSO",
        message: `SAML SSO: issued signed assertion for ${user.email} to SP ${spEntityId} (InResponseTo: ${loginRequest?.extract?.request?.id || "n/a"}).`,
        user: user.email,
        ipAddress: req.ip || "127.0.0.1",
        location: "SAML IdP",
      });
      saveDb(db);

      res.send(`<!DOCTYPE html>
<html>
  <head><title>AegisID SSO — redirecting…</title></head>
  <body style="font-family: ui-monospace, monospace; background:#09090b; color:#a1a1aa; display:flex; align-items:center; justify-content:center; height:100vh; margin:0;">
    <p>Signing you in to the application…</p>
    <form id="sso" method="post" action="${acsUrl}">
      <input type="hidden" name="SAMLResponse" value="${samlResponse}" />
      <input type="hidden" name="RelayState" value="${relayState.replace(/"/g, "&quot;")}" />
    </form>
    <script>document.getElementById('sso').submit();</script>
  </body>
</html>`);
    } catch (err: any) {
      console.error("[SAML IdP] SSO error:", err);
      res.status(400).send(`SAML SSO failed: ${err.message || err}`);
    }
  });

  return router;
}
