---
id: authentication_session
version: 1
covers: ["cwe:287", "cwe:288", "cwe:290", "cwe:294", "cwe:306", "cwe:307", "cwe:347", "cwe:352", "cwe:384", "cwe:521", "cwe:613", "cwe:614", "cwe:620", "cwe:640", "cwe:1004", "cwe:1275", "func:authn:*", "func:session:*"]
standards: ["cwe", "capec", "attack", "asvs5", "api-top10-2023"]
max_tokens: 1500
---
## Viewpoint
An identity attacker. The goal is to become someone else or no one at all: skip the login, forge
or replay a token, fixate or steal a session, or recover an account through a weaker side door.
Every route that changes state must answer "who is this, and how do we know?"

## Coverage
GENERATED

## Likely failure modes
- Routes or RPC methods outside the authentication middleware: allowlist patterns that match too
  much (`/api/public*`), handlers registered before the filter, alternate paths (`/admin;.css`,
  trailing slash, case, HTTP method override) that skip it.
- JWT: `alg: none` accepted, HS/RS confusion where the public key is used as an HMAC secret,
  `decode` instead of `verify`, missing `exp`/`aud`/`iss` checks, `kid` or `jku` from the token used
  to fetch keys.
- OAuth/OIDC: missing OAuth state parameter or PKCE, `redirect_uri` prefix matching, ID token accepted without
  nonce or audience check, access token from another client accepted as login.
- SAML: signature verified on one assertion but attributes read from another (wrapping), comments
  splitting `NameID`, unsigned responses accepted.
- Password handling: comparison with `==` on stored plaintext, no attempt throttling, reset tokens
  that are guessable, long-lived, reusable, or not bound to the account.
- Sessions: id not rotated at login (fixation), cookie without `Secure`, `HttpOnly`, or
  `SameSite`; logout that only clears the client; refresh tokens never revoked.
- CSRF: state-changing `GET`, cookie-authenticated `POST` without token or origin check, CORS
  reflection with credentials undermining the token.
- API keys or mTLS identity trusted from a header set by the client instead of the proxy.

## Effective controls
- Default-deny authentication applied at the router or interceptor level, with explicit and narrow
  anonymous exceptions.
- Library verification calls with pinned algorithms and required claims (`jwt.decode(...,
  algorithms=["RS256"], audience=...)`, `JwtBearer` with `ValidateIssuer`/`ValidateAudience`).
- Session regeneration on privilege change (`session.regenerate`, `request.changeSessionId()`),
  server-side invalidation, bounded idle and absolute timeouts.
- Framework CSRF protection on (Django, Spring Security, ASP.NET antiforgery) or `SameSite=Lax/Strict`
  with origin checks for unsafe methods.
- Constant-time comparison for secrets and one-time codes; attempt counters keyed per account.

## False positives
- Unauthenticated health, metrics, or static routes that expose nothing sensitive.
- CSRF exemptions on endpoints that accept only bearer tokens, not cookies.
- `decode` without verification used only for logging after a separate verifying middleware ran.
- Test or local-profile auth bypasses not compiled or enabled in production configuration.

## Evidence by predicate
- `affected_construct`: the route registration, filter chain, token verifier, session handler, or
  reset flow that should bind identity.
- `attacker_input_control`: the token, cookie, header, assertion, or reset parameter the client
  controls, and how it is produced.
- `source_to_sink_reachability`: the request path from listener through middleware ordering to the
  handler that acts on the identity.
- `missing_or_ineffective_guard`: the absent filter, permissive matcher, skipped claim check, or
  non-rotated session at the specific line.
- `configuration_enables`: security config classes, middleware order, identity-provider settings,
  cookie flags, and profile-specific toggles.
- `security_impact`: account takeover, action as another user, anonymous use of a privileged
  function, or persistent session theft.

## Hand-offs
Per-object or per-tenant permission checks go to `authorization_access_control`. Key strength and
token crypto primitives go to `cryptography_data_protection`. CORS policy goes to
`network_api_surface`. Mobile biometric or keystore login goes to `mobile_platform`.
