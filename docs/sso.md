# Access and single sign-on

## Roles and projects

Every project has its own members. A user with no membership in a project cannot tell that it exists: every page and
API call about it answers 404, exactly as for a project that is not there. Global administrators (a Django superuser
or the `sys_admin` role) are admins of every project.

| Role | May |
|---|---|
| **Read-only** | Open every page of the project, use the search and the read APIs, download exports and reports. Every change is refused with 403: adding or confirming assets, scans, tags, waivers, notes, report schedules, generating a report. |
| **Standard** | Everything read-only may do, plus every change in the project. Not: members and roles, integrations and secrets (notification settings, proxies, tool configuration and the keys in it, user administration), deleting the project. |
| **Admin** | Everything in the project, including the Members page. |

Instance-wide settings are not part of any project role: scan engines, notification settings, proxies, tool configuration, user administration, creating projects and the first-run setup need a global administrator. Scan result files (`/media/<target>_<scan id>/`) follow the project of the scan.

A project always keeps at least one admin: the last one cannot be demoted or removed. The creator of a project
becomes its admin. These roles sit on top of the older global roles (sys admin, penetration tester, auditor): a
request needs both to allow it, so an auditor stays unable to start scans whatever the project role says.

Upgrading gives every existing user an admin membership in every existing project, so nothing stops working. Tighten
it on the Members page afterwards.

### Members page

Open it from the account menu (project admins only), or at `/<project>/members/`. Add an existing user by username or
email, change a role, remove a member. Each change is written to an audit trail shown on the same page. The same
actions over REST (session login and CSRF token, like the rest of the portal):

| Request | Does |
|---|---|
| `GET /<project>/members/api/` | List members |
| `POST /<project>/members/api/` with `{"user": "<username or email>", "role": "read_only"}` | Add a member |
| `PATCH /<project>/members/api/<member id>/` with `{"role": "standard"}` | Change a role |
| `DELETE /<project>/members/api/<member id>/` | Remove a member |

### API tokens (MCP)

A token acts as its owner. A read-only member's token can call the read tools of the projects they belong to and no
write tool, even when the token itself is `read_write`. A project the user is not in is `not_found`. Role changes
apply to the next call.

## Single sign-on (OpenID Connect)

Limes is an OpenID Connect relying party using the authorization code flow with PKCE (S256), `state` and `nonce`.
Any compliant provider works (Microsoft Entra ID, Okta, Ping, Google, Keycloak, ...). Nothing is installed or
configured in the portal: it is all environment variables in `.env`.

### Set up

1. Register a web application ("confidential client") at your provider. The redirect URI is exactly
   `https://<your limes host>/sso/callback/`. Scopes: `openid email profile`.
2. Set in `.env` and restart:

   ```
   LIMES_OIDC_ENABLED=true
   LIMES_OIDC_ISSUER=https://login.example.com        # the issuer URL; its /.well-known/openid-configuration must exist
   LIMES_OIDC_CLIENT_ID=...
   LIMES_OIDC_CLIENT_SECRET=...
   LIMES_OIDC_REDIRECT_BASE=https://limes.example.com
   ```

   Provider examples. Entra ID: issuer `https://login.microsoftonline.com/<tenant id>/v2.0`. Okta:
   `https://<org>.okta.com` (or the issuer of your custom authorization server). Google: `https://accounts.google.com`.
   Keycloak: `https://<host>/realms/<realm>`.
3. The login page now shows **Sign in with SSO**. Without all five values set, SSO stays off and the button is hidden.

The provider must be reachable on a public address over https. Discovery, key and token requests go through the same
guarded fetcher as the scan pipeline: https only, public addresses only (a name that resolves to a private address
is refused), the connection pinned to the vetted address, no redirects, size and time limits.

### Who can sign in

Accounts are matched on the provider's stable subject (`sub`) together with the issuer, never on an email address
alone. At the first SSO sign-in of an identity that has no link yet, exactly one of these happens, in this order:

1. **Auto-create** (`LIMES_OIDC_AUTO_CREATE=true`, default off): a new account is made with an unusable password, no
   staff or superuser flag, the global role *auditor* (read-only) or *penetration tester* (standard) and the project
   role `LIMES_OIDC_DEFAULT_ROLE` (`read_only` or `standard`; anything else, including `admin`, falls back to
   `read_only`) in each project of `LIMES_OIDC_DEFAULT_PROJECTS`. With no projects listed the account can sign in and
   sees nothing until an admin adds it on the Members page.
2. **Link by email** (`LIMES_OIDC_LINK_BY_EMAIL=true`, default off): if the provider says `email_verified` is `true`,
   exactly one active local account has that email, it has no link to this provider yet, and it is not a superuser,
   staff or sys admin account, the identity is linked to it.
3. Otherwise sign-in is refused.

SSO never creates, links or promotes a superuser, staff or sys admin account. Give someone admin rights from the
Members page, after the account exists. To unlink an identity, delete its row under "OIDC identities" in the Django
admin (superusers).

`LIMES_OIDC_ALLOWED_DOMAINS` (comma list) restricts sign-in, including for already linked accounts, to emails in those
domains. It requires the provider to send `email_verified: true`; a provider that omits the claim (Entra ID does by
default) cannot satisfy it. Use a single-tenant issuer instead, or add the optional claim at the provider.

### What is checked on every sign-in

* `state` must match the value kept in the server-side session, which is single use and expires after ten minutes.
* The ID token's signature is verified against the provider's JWKS, chosen by `kid`. Only RS256 and ES256 are
  accepted (never `none`, never HS*). RSA keys under 2048 bits are refused.
* `iss` equals the configured issuer exactly, `aud` contains the client id (with `azp` when there are several),
  `exp`, `iat` and `nbf` hold within 60 seconds of clock skew, `nonce` equals the one issued, `sub` is present.
* Discovery must report the same issuer, https endpoints and, when it lists them, `S256` for PKCE.
* The session id is replaced on login. `next` after login must be a path on this site; anything else is ignored.
* Failures show one generic message. The log gets a short reason code, never a token, code or claim.

### Local login

Password login stays available by default. `LIMES_LOCAL_LOGIN=false` removes the form and refuses password posts, but
only while SSO is configured and working, so a typo in the SSO settings cannot lock everyone out. Create at least one
SSO-linked admin account and test it before switching it off. The break-glass path is the `.env` change itself, or
`make username` for a new superuser.

### Limits

* Sign-out ends the Limes session only; it does not sign out of the provider (no RP-initiated logout).
* An SSO session lasts as long as any Limes session, whatever the provider's session does. Disable the user in
  Limes (or remove memberships) to cut access at once.
* Provider group or role claims are not mapped to project roles. Roles are managed on the Members page.
* The sign-in endpoints are not rate limited by Limes; the provider's own protections apply.
