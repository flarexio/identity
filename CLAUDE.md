# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Go microservice for user identity management (`github.com/flarexio/identity`), built with go-kit, plus an Angular frontend in `web/`. It authenticates users via Google, LINE, or Passkeys, issues its own ed25519-signed JWTs, and publishes user lifecycle events over NATS JetStream. It also brokers one-time SCEP enrollment challenges for device certificates issued by a StepCA instance.

## Commands

```sh
# Build the CLI binary
go build -o $GOPATH/bin/identity ./cmd/identity

# Build (as CI does it; requires CGO for the sqlite driver)
CGO_ENABLED=1 go build ./cmd/identity

# Run all tests
go test -v ./...

# Run tests for one package
go test ./persistence/db/...

# Run a single test (suites use testify, e.g. the end-to-end suite in cmd/identity)
go test -run TestIdentity/TestLinkAndUnlink ./cmd/identity/

# Generate a new ed25519 keypair for jwt.privkey in config.yaml
go run ./cmd/identity genkey

# Frontend (web/)
npm ci                      # install
npm start                   # dev server on :4200, proxying API paths to :8080 (proxy.conf.json)
npm test -- --watch=false   # vitest unit tests
npm run build               # production build into web/dist
```

Running the service requires a reachable NATS server with JetStream (see README) — `run()` in `cmd/identity/main.go` connects to it and blocks (with a 30s timeout) on `AddJetStream`/`AddStreamAndConsumer` before the HTTP server starts. Config is loaded from `$IDENTITY_PATH/config.yaml` only; there is deliberately no fallback to `config.example.yaml`, and `conf.LoadConfigFile` refuses the example's placeholder key, a key whose public half doesn't match its seed, `jwt.admins` entries that aren't user IDs, and a weak SCEP secret. `$IDENTITY_PATH` defaults to `~/.flarex/identity`. YAML values support `$ENV_VAR` expansion (`conf/env_reader.go`). The frontend is served from `http.web` (default `$IDENTITY_PATH/web`) when that directory holds an `index.html`.

## Architecture

### Layering (go-kit style)

1. **Service** (`service.go`, `passkeys/service.go`, `scep/service.go`) — business logic behind a `Service` interface. `identity.Service` is wrapped by `LoggingMiddleware` (`logging.go`). Credential verification is delegated to `provider.Verifier`s (see below), injected as a `map[user.SocialProvider]identity.Provider`.
2. **Endpoint** (`endpoint.go`, `passkeys/endpoint.go`, `scep/endpoint.go`) — go-kit endpoints. `identity.NewEndpointSet(svc, tokens)` builds them; the sign-in, session, refresh and mTLS endpoints also mint tokens via `token.Issuer`, so every transport issues tokens the same way.
3. **Transport** (`transport/http`, `transport/line`, `transport/pubsub`) — gin or NATS handlers that decode, call the endpoint, and encode. Route wiring lives in `cmd/identity/server.go` (`publicRouter`, `mtlsRouter`), process wiring in `cmd/identity/main.go`.

The domain model lives in `user/`: a `User` aggregate independent of transport and persistence. Its invariants (no duplicate social account, never remove the last one) are enforced there and return sentinel errors (`user.ErrSocialAccountExists`, …). `errors.go` holds the service-level errors; `transport/http/errors.go` maps every error to a status and a generic message — internal and upstream error text never reaches clients.

### Event sourcing round trip

Domain methods on `*user.User` (`Register`, `Activate`, `AddSocialAccount`, `RemoveSocialAccount`, `Delete`) mutate the in-memory struct and queue a `events.DomainEvent`. Service methods then call `u.Notify()`, which publishes them to NATS JetStream (stream `USERS`, subjects `users.<id>.<event>`); a publish failure fails the command.

The repository writes happen on the other end: `identity.NewEventHandler(repo)` (`projection.go`, wrapped by `EventLoggingMiddleware`) consumes `users.>` via `transport/pubsub.EventHandler` and calls `Store`/`Delete`. So `SignIn` creating a new user returns the user immediately, but it is persisted only once its events round-trip — asynchronously, in the same process. JetStream delivers at least once, so projection handlers are idempotent. `transport/pubsub` acks events that can never apply (undecodable, topic/payload user mismatch, not-found, conflicts) and leaves others unacked for redelivery.

### Authentication providers

`provider/` reduces each provider's credential to a `provider.Identity` (subject, name, verified email, picture). Failures wrap `provider.ErrInvalidCredential`.

- **Google** — `idtoken.Validate` against `providers.google.client.id`; e-mail kept only if `email_verified`.
- **LINE** — HS256 ID token signed with the channel secret; issuer, audience, expiry and the `nonce` (passed in the context via `provider.WithNonce`) are checked. `transport/line` runs the authorization-code flow with PKCE, binding each flow's `state` to the starting browser with the `__Host-identity_line_state` cookie (prevents login and account-linking CSRF). The sign-in callback sets the session cookie and redirects to the frontend.
- **Passkeys** — an external Passkeys API (`passkeys/service.go`, `providers.passkeys`; disabled when `baseURL` is empty). Ceremonies are proxied; its tokens are verified against its JWKS. `RegisterPasskey` uses the user's own ID as the WebAuthn user handle, and `AddSocialAccount` only links a passkey token whose subject is that ID.

Google and LINE open an account on first sign-in (`identity.Provider.OpensAccounts`); passkeys never do. Usernames come from the verified e-mail's local part, sanitized to `[a-z0-9._-]`, with a random suffix on collision. Only `Activated` users may sign in or receive tokens.

### Tokens and sessions (`token/`)

Identity mints its own EdDSA JWTs. **Access tokens**: `sub` is the *username*; `uid` is the user ID; `auth_time` is when the user last really authenticated; `roles` is `user` plus `admin` for user IDs in `jwt.admins`; `passkey_user_id` is the user's passkey social ID — **omitted** when none is linked, so a relying party sees nothing rather than an empty string it might match against (`flarexio/wallet` compares it against the `user_id` in its sign requests). Tokens are verified against `jwt.audiences[0]`; the JWKS is at `/.well-known/jwks.json`.

Nothing is ever issued past `auth_time + jwt.refresh.maximum` (or `+ jwt.timeout` when refresh is disabled). `PATCH /identity/v1/token/refresh` checks the account is still active and is still the one in `uid` (usernames are freed on deletion and can be reused); tokens without `uid`/`auth_time` must sign in again.

**Browser session**: sign-in also sets `__Host-identity_session` (HttpOnly, Secure, SameSite=Strict) holding a session JWT (distinct `typ` and audience; names the user by ID). The frontend keeps the access token in memory only and trades the cookie for a fresh one at `POST /identity/v1/session/token`; `DELETE /identity/v1/session` signs out. Cookie-touching routes also go through `transHTTP.SameOrigin` (Sec-Fetch-Site / Origin check) and accept JSON only.

### Two HTTP servers

- **Public** (`--port`/`IDENTITY_HTTP_PORT`, default 8080) — `/identity/v1/*` (owner routes protected by `transHTTP.Authorizator`: bearer token, then the Rego policy in `permissions.json` via `flarexio/core/policy`), `/auth/line*`, `/.well-known/*`, and the frontend as the `NoRoute` fallback (SPA routing; never for `/identity`, `/auth`, `/.well-known`). Every response gets security headers; pages get a CSP whose only third party is Google Identity Services. Sign-in routes are rate limited per client IP; `http.trustedProxies` decides whose `X-Forwarded-For` counts.
- **mTLS** (`--mtls-enabled`, `--mtls-port`/`IDENTITY_MTLS_PORT`, default 8443) — certs under `$IDENTITY_PATH/certs/`. `/users/:subject[?provider=]` mints a token for a social ID and `/scep/challenge/generate` mints SCEP challenges; both require a client cert OU in `mtls.allowedOUs` (devices hold certs from the same CA). `/scep/challenge/verify` is StepCA's webhook: pinned client cert CN plus HMAC over the body.

### Persistence

`user.Repository` is implemented by `sqlite` (`persistence/db`, gorm), `badger` (`persistence/kv`) and `inmem` (`persistence/inmem`, tests), chosen by `persistence.driver`. Social accounts are looked up by `(provider, social id)`. Every backend refuses a username or social account already held by another user, and hands out copies. All three run the same conformance suite, `persistence/repotest`. Badger stores each user once under `user:<id>` with ID-only indexes (`username:`, `social:<provider>:`); stores from before schema 1 are migrated on open. `scep.Store` (in-memory, `persistence/inmem/scep.go`) is unrelated to users.

### Frontend (`web/`)

Angular (standalone, zoneless, signals). `core/auth.ts` holds the session; `core/auth.interceptor.ts` adds the bearer token to identity's own user routes only and retries once through the session on `invalid_token`; `core/google.ts` loads Google Identity Services; `core/webauthn.ts`/`core/passkeys.ts` run passkey ceremonies. Pages: `login/` and `account/` (profile, link/unlink methods, delete account). UI text is Traditional Chinese. Production builds disable inlined critical CSS and SRI, which would otherwise need inline handlers or an inline import map the CSP forbids.
