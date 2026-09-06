# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Go microservice for user identity management (`github.com/flarexio/identity`), built with go-kit. It authenticates users via Google, LINE, or Passkeys, issues its own ed25519-signed JWTs, and publishes user lifecycle events over NATS JetStream. It also brokers one-time SCEP enrollment challenges for device certificates issued by a StepCA instance.

## Commands

```sh
# Build the CLI binary
go build -o $GOPATH/bin/identity cmd/identity/main.go

# Build (as CI does it; requires CGO for the sqlite driver)
CGO_ENABLED=1 go build cmd/identity/main.go

# Run all tests
go test -v ./...

# Run tests for one package
go test ./persistence/db/...

# Run a single test (persistence tests use testify suites, e.g. userRepositoryTestSuite)
go test -run TestUserRepositoryTestSuite ./persistence/db/...

# Generate a new ed25519 keypair for jwt.privkey in config.yaml
go run cmd/identity/main.go genkey
```

Running the service requires a reachable NATS server with JetStream (see README) — `run()` in `cmd/identity/main.go` connects to it and blocks (with a 30s timeout) on `AddJetStream`/`AddStreamAndConsumer` before the HTTP server starts. Config is loaded from `$IDENTITY_PATH/config.yaml` (falls back to `config.example.yaml` if absent); `$IDENTITY_PATH` defaults to `~/.flarex/identity`. YAML values support `$ENV_VAR` expansion (`conf/env_reader.go`). Loaded config is available process-wide via `conf.G()`.

## Architecture

### Layering (go-kit style)

Each bounded piece of functionality (`identity` root package, `passkeys/`, `scep/`) follows the same three layers:

1. **Service** (`service.go`, `passkeys/service.go`, `scep/service.go`) — business logic, defined as a `Service` interface plus a concrete struct. `identity.Service` is wrapped by `LoggingMiddleware` (`logging.go`) using the `ServiceMiddleware` decorator pattern.
2. **Endpoint** (`endpoint.go`, `passkeys/endpoint.go`, `scep/endpoint.go`) — go-kit `endpoint.Endpoint` adapters, one per service method, doing request-type assertions only.
3. **Transport** (`transport/http`, `transport/line`, `transport/pubsub`, `passkeys/transport.go`, `transport/http/scep.go`) — gin HTTP handlers or NATS handlers that decode a request, call the endpoint, and encode the response. All wiring happens in `cmd/identity/main.go`.

The domain model itself lives in `user/` (`user.go`, `event.go`, `repository.go`, `context.go`) — a `User` aggregate independent of any transport or persistence concern.

### Event sourcing round trip

This is the part that isn't obvious from file layout alone. Domain methods on `*user.User` (`Register`, `Activate`, `AddSocialAccount`, `RemoveSocialAccount`, `Delete`) don't write to the repository directly — they mutate the in-memory struct and queue a `events.DomainEvent` via the embedded `events.EventStore`. Service methods then call `u.Notify()` (deferred), which publishes those queued events to NATS JetStream (stream `USERS`, subjects `users.>`, topic per event via `Event.Topic()`).

The actual repository writes happen on the *other end*: `cmd/identity/main.go` sets up a JetStream pull consumer that feeds `identity.EventEndpoint` → `EventHandler` (implemented by the same `service`/`loggingMiddleware`, see `UserRegisteredHandler` etc. in `service.go`/`logging.go`), which is what calls `svc.users.Store(...)`/`Delete(...)`. So a command like `SignIn` creating a new user returns a `*user.User` to the HTTP caller immediately, but that user isn't actually persisted until the published event round-trips back through the consumer — asynchronously, in the same process.

### Authentication providers

Three `user.SocialProvider` values are implemented in `service.go` (`SignIn`/`AddSocialAccount`); `FACEBOOK` is defined in `user/user.go` but has no implementation anywhere.

- **Google** — verifies the ID token via `idtoken.Validate` against `providers.google.client.id`.
- **LINE** — manually parses the ID token as a JWT HMAC-signed with the channel secret (`providers.line.channel.secret`), checking issuer/audience and comparing the token's `nonce` claim against the OAuth session nonce stored server-side by `transport/line/transport.go` (state/nonce dance for both the `SignIn` and `LinkAccount` operations, driven by `/auth/line` → `/auth/line/callback`).
- **Passkeys** — delegates to an external Passkeys-as-a-service API (`passkeys/service.go`, configured under `providers.passkeys`); registration/login/transaction ceremonies are proxied there, and tokens it issues are verified against its own JWKS.

Only Google and LINE can create a brand-new user on first sign-in (see the `FindBySocialID` → not-found → `user.NewUser(...)` branches in `signInWithGoogle`/`signInWithLINE`). Passkey sign-in (`signInWithPasskeys`) only looks up an existing account — `RegisterPasskey` itself requires an already-existing username. `POST /users` (the plain `Register` endpoint, for opening an account without any social provider) is wired in `endpoint.go` but commented out in `main.go`, so it is not currently reachable. `OTPVerify` exists as an endpoint but its verification logic is an unimplemented stub in `service.go`.

### Two HTTP transports

- **Public server** (`--port`/`IDENTITY_HTTP_PORT`, default 8080) — serves `/identity/v1/*` (JWT + Rego-policy protected via `transHTTP.Authorizator`, policy rules in `permissions.json`, evaluated by `flarexio/core/policy`), the LINE OAuth routes, and `/.well-known/jwks.json`.
- **mTLS server** (`--mtls-enabled`, `--mtls-port`/`IDENTITY_MTLS_PORT`, default 8443) — for service-to-service calls, using certs under `$IDENTITY_PATH/certs/`. Routes: `/users/:subject` (mints a JWT directly for the given social ID — no further credential check beyond the client cert, gated by `transHTTP.RequireClientOU` against `mtls.allowedOUs` in config), and `/scep/challenge/generate` + `/scep/challenge/verify` (one-time SCEP enrollment challenges for StepCA device certs, additionally checked in `transport/http/scep.go` via a pinned webhook client cert CN and an HMAC-signed webhook body).

### JWT

Identity mints its own ed25519 (EdDSA) JWT after a successful sign-in — independent of whatever token the social provider issued — via `transport/http/token.go` (`Init`, `ParseToken`) and `transport/http/transport.go` (`SignInHandler`). `sub` is the *username*, not a social ID. The public key is exposed as JWKS at `/.well-known/jwks.json` so other services (and `transport/http/middleware.go`'s own `Authorizator`) can verify tokens issued here. `PATCH /token/refresh` reissues a token within `jwt.refresh.maximum` of the original `iat`.

Alongside `sub` and `roles`, the token carries `passkey_user_id` — the subject's `SocialAccount` id for provider `passkeys`, read via `user.User.SocialID`. A relying party that gates an action behind a passkey assertion needs it: the passkey provider's user id is a different namespace from the username in `sub`, so without this claim nothing ties a verified assertion to an account. `flarexio/wallet` compares it against the `user_id` in its sign requests. The claim is **omitted** for users with no passkey linked, so a relying party sees nothing rather than an empty string it might match against.

`RefreshHandler` re-signs the claims it parsed, so a token issued before the claim existed gains it on a fresh sign-in, not on refresh. Relying parties have to treat an absent claim as "unknown" until circulation turns over.

### Persistence

`user.Repository` is the single interface all storage backends implement; `persistence.NewUserRepository` picks one by `persistence.driver` in config: `sqlite` (`persistence/db`, gorm), `badger` (`persistence/kv`), or `inmem` (`persistence/inmem`, tests only). `scep.Store` (only a plain in-memory challenge store today, `persistence/inmem/scep.go`) is separate and unrelated to the user repository.
