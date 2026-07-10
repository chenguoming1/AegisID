# AegisID — Enterprise IAM & SSO

An enterprise-grade Identity & Access Management dashboard demo. AegisID showcases a
federated SSO directory with multi-factor security, biometric verification, SAML/OIDC
single sign-on, real-time threat detection, automated SCIM user provisioning, and an
AES-256-GCM credential encryption visualizer.

> This is an interactive **simulation** built for demonstration. It generates realistic
> SAML assertions, audit logs, and threat telemetry against a local JSON store — it does
> not connect to real identity providers.

## Features

- **IT Admin Console** — directory overview, live access/threat telemetry charts, threat
  intel feed, SSO app catalog, and an immutable audit trail.
- **Employee Portal** — a MyApps launcher that issues federated SSO handshakes and renders
  the signed SAML 2.0 XML assertion.
- **Mobile MFA Emulator** — a simulated authenticator with rolling TOTP codes and push
  approvals gated by a biometric (fingerprint) scan.
- **SCIM Provisioning** — provision/deprovision identities and watch the audit trail update.
- **Threat Simulation & Remediation** — inject mock threats (impossible travel, API-key
  abuse) and remediate them (block subnet, suspend account).
- **AI Compliance Reports** — generate SOC 2 / NIST SP 800-61 incident reports via Gemini,
  with a built-in rules-based fallback when no API key is configured.
- **Crypto Visualizer** — seal/unseal secrets with server-side AES-256-GCM (PBKDF2 key
  derivation) and verify the GCM integrity tag.

## Tech stack

React 19 · Vite 6 · Tailwind CSS 4 · Express · TypeScript · Recharts · Lucide · `@google/genai`

The Express server (`server.ts`) exposes the JSON API and serves the Vite app (via
middleware in dev, static `dist/` in production). State persists to a local `database.json`.

## Run locally

**Prerequisites:** Node.js 18+

1. Install dependencies:
   ```
   npm install
   ```
2. (Optional) Copy `.env.example` to `.env` and set `GEMINI_API_KEY` to enable live AI
   incident reports. Everything works without it via the fallback report engine.
3. Start the dev server:
   ```
   npm run dev
   ```
   The app runs at http://localhost:3000 (override with `PORT`).

## Production build

```
npm run build   # bundles the client (dist/) and the server (dist/server.cjs)
npm start       # NODE_ENV=production node dist/server.cjs
```

## Signing in (the login gate)

The whole app sits behind a real login wall (`server/auth.ts` + `server/session.ts`).
You authenticate to your AegisID account, and the dashboard loads as that identity:

1. **Password** (primary factor) — demo directory accounts share the password
   **`aegis1234`** (hashed with scrypt on first use). Try:
   - Admin: `alex.rivera@enterprise.io`
   - Employee: `marcus.c@enterprise.io`
2. **Step-up MFA** — if the account has enrolled a real second factor (TOTP or a
   passkey via **Account Security**), login requires it after the password.
3. **OIDC** — "Sign in with Keycloak" is an alternative primary factor; it maps the
   federated identity to a directory user (just-in-time provisioning if new).

Your **role drives the view**: Admin / Security Engineer accounts get the Admin
Console (and can flip to their own Employee Portal); everyone else gets the Employee
Portal only. Every `/api` route except `/api/auth/*` and `/api/oidc/*` requires a
valid session cookie, and all secrets are stripped from responses.

> Note: this demo gates the **UI** by role and gates the **API** by session. It does
> not yet enforce per-role RBAC on individual admin endpoints — a sensible next step.

## Real integrations (not simulated)

Most of AegisID is an interactive simulation, but the **Account Security** panel
(left column) wires up genuine, standards-based auth you can test for real — no
enterprise account required. Backed by routes under `server/`:

| Feature | Library | Needs |
| --- | --- | --- |
| **TOTP** (`server/totp.ts`) | `otplib` + `qrcode` | Nothing — works on localhost |
| **Passkeys / WebAuthn** (`server/webauthn.ts`) | `@simplewebauthn/*` | A device with Touch ID / Face ID / Windows Hello |
| **OIDC SSO** (`server/oidc.ts`) | native fetch (Auth Code + PKCE) | An OIDC provider (local Keycloak is easiest) |

Secrets (TOTP seeds, passkey public keys, challenges) are stored server-side in
`database.json` and **stripped from every `/api/db` response** (`sanitizeUser`).

### TOTP — real authenticator codes
1. Open **Account Security → Authenticator (TOTP) → Set up authenticator**.
2. Scan the QR with Google Authenticator / Authy / 1Password / Microsoft Authenticator.
3. Enter the 6-digit code to verify. Codes are checked with RFC 6238 server-side
   (±30s skew). Use **Test a code** to validate anytime.

### Passkeys — real device biometrics
1. **Account Security → Passkey (WebAuthn) → Add a passkey**.
2. Approve the real **Touch ID / Face ID / Windows Hello** prompt. The private key
   is created in your device's secure enclave; the server only stores the public key.
3. **Sign in with passkey** performs a real assertion + signature-counter check.
   > Passkeys require a secure context — use `http://localhost:<PORT>` (localhost is
   > treated as secure), not a raw IP. Override host/origin with `WEBAUTHN_RP_ID` /
   > `WEBAUTHN_ORIGIN` if needed.

### OIDC SSO — real login via local Keycloak (no account)
1. Run a real identity provider locally:
   ```bash
   docker run -p 8080:8080 \
     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
     -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:latest start-dev
   ```
2. In the Keycloak admin console (`http://localhost:8080`, admin/admin):
   - Create a realm, e.g. **`aegisid`**.
   - Create a client **`aegisid-app`**: Client type *OpenID Connect*, enable
     *Standard flow*, set **Valid redirect URIs** to `http://localhost:3000/api/oidc/callback`
     (match your `PORT`). Leave it a *public* client to use PKCE without a secret.
   - Create a test user (set a password under *Credentials*).
3. Configure AegisID (`.env`) and restart:
   ```
   OIDC_ISSUER="http://localhost:8080/realms/aegisid"
   OIDC_CLIENT_ID="aegisid-app"
   ```
4. **Account Security → Enterprise SSO → Sign in with Keycloak** runs a real
   Authorization Code + PKCE flow and shows the identity returned by the provider.

Other free hosted providers work too (Auth0, Okta Developer, Microsoft Entra) —
just point `OIDC_ISSUER` / `OIDC_CLIENT_ID` at them and set the redirect URI.

## Managing enterprise apps & user access

Both are admin operations (sign in as an Admin, e.g. `alex.rivera@enterprise.io`):

- **Register a new app** — Admin Console → **SSO Apps** → **Register New App**.
  Choose SAML 2.0 or OIDC, set the Entity ID (audience) and optional ACS/SSO URL
  and SCIM endpoint. OIDC apps get a generated `client_id` + `client_secret`
  shown **once** at registration (never re-exposed by the API). Apps can be
  deregistered from their card, which revokes them from every user.
- **Assign a user to an app** — Admin Console → **User Directory** → key icon
  on the user's row → toggle app chips. Changes appear in that user's Employee
  Portal launcher immediately and are written to the audit trail.

Assignment is **enforced at the IdP**, not just cosmetic: the SAML SSO endpoint
refuses to issue an assertion for a user who isn't assigned to the requesting
application ("Access denied — not assigned"), and logs the denial. Note that
unassignment does not kill an app session that already exists (no Single Logout
in this demo) — it blocks the *next* sign-in.

### Real SCIM provisioning (to the Globex sample app)

For the bundled live app, provisioning is **real SCIM 2.0 over HTTP**, not just
audit-log narration. Globex serves a bearer-token-protected SCIM API
(`:3400/scim/v2/Users` — see [sample-sp/scim.ts](sample-sp/scim.ts)) and AegisID
pushes to it ([server/scim-client.ts](server/scim-client.ts)) on lifecycle events:

| AegisID action | SCIM call to Globex |
| --- | --- |
| Provision new identity | `POST /Users` (create, active) |
| Offboard / deprovision | `PATCH /Users/:id` → `active: false` |
| Suspend / re-activate | `PATCH` → `active: false / true` |
| Assign / unassign the app | create-or-reactivate / deactivate |

Watch it at **http://localhost:3400/directory**: accounts appear there *before*
the user ever logs in (SCIM push) or at first SSO login (JIT). A **deactivated
Globex account cannot sign in even with a valid SAML assertion** — the app
blocks it at the ACS. Every push is audit-logged with the real HTTP outcome.
The seeded Slack/Salesforce/GitHub SCIM endpoints remain decorative; only live
apps (with a local `launchUrl`) are actually called. Token: `SCIM_TOKEN`
(defaults match on both processes).

API: `POST /api/apps/register`, `POST /api/apps/remove`, `POST /api/apps/assign`
(`{ userId, appId, assigned }`) — all session-gated.

## Real enterprise SSO: AegisID as a SAML 2.0 Identity Provider

AegisID is a working **SAML IdP** (`server/saml-idp.ts`) and ships with a real
enterprise app to federate with: **Globex Industries Intranet**
([sample-sp/server.ts](sample-sp/server.ts)), a separate web app that has no
passwords of its own and trusts AegisID for login.

What's real: RSA-2048 signing keys + self-signed X.509 cert (minted to
`saml-keys.json` on first boot), published IdP/SP metadata, SP-initiated
AuthnRequests, **RSA-SHA256-signed assertions** (InResponseTo, audience
restriction, 5-minute validity window, NameID + attribute statement), and
signature verification at the SP against the metadata certificate. Tampered
assertions are rejected. (XML *schema* validation is stubbed; signatures and
conditions are fully enforced.)

### Run it

```bash
npm run dev                                  # terminal 1 — AegisID (IdP)
AEGIS_URL=http://localhost:3000 npm run sp   # terminal 2 — Globex (SP), port 3400
```
Match `AEGIS_URL` to the port AegisID runs on (e.g. `http://localhost:3200`).

### Test the flow

1. Open the Globex app at **http://localhost:3400** → "Sign in with AegisID SSO".
2. You're redirected to AegisID (`/saml/sso`). Not signed in? You get the AegisID
   login screen first (password / passkey / TOTP) and the SSO flow resumes after.
3. AegisID posts a signed SAMLResponse to Globex's ACS; Globex verifies the
   signature and shows your identity + SAML claims (email, displayName, role,
   department) — plus the raw signed XML.
4. Or start from inside AegisID: the **Globex Intranet** card (marked **LIVE**)
   in the Employee Portal opens the app; since your AegisID session already
   exists, sign-in is instant — that's real SSO.

Endpoints: IdP metadata `GET /saml/metadata` (AegisID) · SP metadata
`GET :3400/saml/metadata` · ACS `POST :3400/acs`.

## Configuration

| Variable            | Required | Default            | Purpose                                             |
| ------------------- | -------- | ------------------ | --------------------------------------------------- |
| `GEMINI_API_KEY`    | No       | —                  | Enables live Gemini incident reports.               |
| `GEMINI_MODEL`      | No       | `gemini-2.5-flash` | Gemini model used for reports.                      |
| `PORT`              | No       | `3000`             | Server port (Cloud Run / AI Studio inject this).    |
| `APP_URL`           | No       | —                  | Public URL of the deployment.                       |
| `WEBAUTHN_RP_ID`    | No       | `localhost`        | WebAuthn relying-party ID (the host).               |
| `WEBAUTHN_ORIGIN`   | No       | `http://localhost:<PORT>` | Extra allowed WebAuthn origin.               |
| `OIDC_ISSUER`       | No       | —                  | OIDC provider issuer URL (enables real SSO).        |
| `OIDC_CLIENT_ID`    | No       | —                  | OIDC client ID.                                     |
| `OIDC_CLIENT_SECRET`| No       | —                  | OIDC client secret (omit for public/PKCE clients).  |
| `OIDC_REDIRECT_URI` | No       | auto-derived       | OIDC callback URL.                                  |

## Scripts

| Script          | Description                                          |
| --------------- | --------------------------------------------------- |
| `npm run dev`   | Start the Express + Vite dev server.                |
| `npm run build` | Build the client and bundle the server.             |
| `npm start`     | Run the production build.                            |
| `npm run lint`  | Type-check with `tsc --noEmit`.                      |
| `npm run clean` | Remove `dist/` and the local `database.json`.       |

## Data reset

The **Reset DB** button (top-right) restores the seed directory, apps, logs, and threats.
You can also delete `database.json` (or run `npm run clean`) to reseed on next launch.
