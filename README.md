# pure-tcl-oauth2-server

Framework-independent OAuth2 authorization server primitives in Tcl. Supports
authorization code with S256 PKCE, rotating refresh tokens, client credentials,
revocation, introspection and resource checks. Optional RS256 ID tokens, discovery,
JWKS and UserInfo support a basic OpenID Connect login flow. This is not a claim
of OpenID certification or support for every OIDC extension.

```tcl
package require pure-tcl-oauth2-server 0.1.0
set server [::oauth2::server::create -issuer https://auth.example \
    -store $sqlStore -signing_key $privateRs256Handle]
$server register_client browser-app -redirect_uris {https://app.example/callback} \
    -scope {openid email profile} -audiences https://api.example
```

The host owns login, account lookup, consent UI, session/CSRF protection, HTTP
routing, rate limits and key provisioning. No implicit grants, password grants,
dynamic registration or untrusted redirect patterns are included. Registration
is a trusted administrative call. Use exact registered redirect URIs.

## API

Constructor options: `-issuer`, `-store` (required), `-signing_key {}`, `-allow_http
false` (loopback only), `-clock {clock seconds}`, `-code_ttl 300`, `-access_ttl 3600`,
`-refresh_ttl 2592000`. Lifetimes are seconds, bounded 1–31536000. Signing keys
must be RS256 JWT keysets. Keep persistent keys outside source control, retain
old public keys during rotation, and share the same keyset across workers.

`register_client id` accepts `-redirect_uris`, `-scope` (space-delimited),
`-auth_method none|client_secret_basic|client_secret_post`, `-secret`, `-grants
{authorization_code refresh_token}`, `-audiences`, and `-introspection false`.
Confidential clients need a high-entropy secret of at least 32 characters; generate
one with `::oauth2::core::random`. Client credentials and introspection require
confidential clients. A client secret is stored as a SHA-256 digest.

1. Parse authorization parameters strictly and call `authorize_validate fields`.
   This checks client, exact redirect, response type, PKCE, scopes and resource,
   and returns a random `request_id` plus validated display fields.
2. Bind that ID to the host's browser session. Authenticate a user and obtain
   consent through a CSRF-protected POST. Call `authorize_complete requestId
   authenticatedSubject ?-claims typedProfileFields? ?-consent true?`. The result
   is a `{statusCode headers body}` redirect. Never take the subject or profile
   claims from the authorization request. Denial redirects only after validation.
3. On a URL-encoded token POST call `endpoint token rawBody ?authorizationHeader?`.
   The same adapter supports `revoke` and `introspect`. Enforce HTTP method,
   content type and request size in your host. Responses use no-store headers
   and standard OAuth error codes. Duplicate query/body fields are rejected.

Lower-level `token fields ?authorization?` returns typed JSON fields;
`introspect fields ?authorization?` returns typed active/inactive metadata;
`revoke fields ?authorization?` is idempotent. Introspection requires explicit
registration permission and the token's audience in the caller's allowed list.

`resource token audience requiredScopes` returns internal verified grant data
after active-family, expiry, audience and scope checks. Extract credentials with
`::oauth2::core::bearer`. A resource host maps rejection to its appropriate
401/403 response and `WWW-Authenticate` header. `userinfo token` requires openid
scope and returns typed profile fields with the stable subject.

`metadata` and `jwks` return typed objects to serialize with the core response
helper. Mount metadata at `/.well-known/openid-configuration`; its advertised
paths are the configured issuer plus `/authorize`, `/token`, `/revoke`,
`/introspect`, `/jwks`, `/userinfo`. The authorization response includes `iss`.
OIDC requests require a nonce. Profile claims must already be filtered by the
host for the granted scopes; reserved token claims cannot be overridden.

## Persistence and replay handling

Use a separately scoped core SQL store and initialize its schema explicitly.
Codes and bearer tokens are indexed by hashes. Redemption binds the client,
redirect and PKCE verifier. Access tokens are opaque random values. Refreshes
rotate the token once and retain used-token records through the family's absolute
lifetime. Refresh reuse revokes the entire family, including its newest access
token; code reuse during the code retention window does the same. Revocations
commit even when redemption returns `invalid_grant`. Revoking either an access
or refresh token revokes its family. Client-credentials grants do not issue
refresh or ID tokens. A refresh can narrow but cannot expand scopes.

Run `tclsh9.1 tests/all.tcl`. Memory and SQLite tests exercise identical replay,
transaction, audience and authentication policies. PostgreSQL is supported by
the backend but requires a provisioned database for integration testing.
