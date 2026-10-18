# Identity [![Build](https://github.com/flarexio/identity/actions/workflows/build.yml/badge.svg)](https://github.com/flarexio/identity/actions/workflows/build.yml)

Identity is a scalable and decentralized microservice for user identity management.


# Prerequisites

NATS Server with JetStream: Refer to the official NATS website for installation instructions.

##  Dependency on NATS with JetStream

This project relies on NATS Server with JetStream functionality for its operations. Ensure that you have NATS Server with JetStream installed and running before using this project.

For installation instructions and details about NATS Server with JetStream, please refer to the official NATS website (https://nats.io).

## Installation

You can install Identity using one of the following methods:

### Binary

1. Clone the repository, navigate to the project directory, build, and install the binary using the following command:

   ```shell
   # clone the repository
   git clone https://github.com/flarexio/identity.git
   
   # navigate to the project directory
   cd identity
   
   # build and install
   go build -o $GOPATH/bin/identity ./cmd/identity

   # build the web frontend (optional) and install it into the working directory
   (cd web && npm ci && npm run build) && cp -r web/dist ~/.flarex/identity/web
   ```

2. Copy `config.example.yaml` to `config.yaml` in the working directory (`~/.flarex/identity` by default) and replace its placeholder keys: run `identity genkey` for `jwt.privkey`, and set the SCEP webhook secret. Identity refuses to start with the placeholders, or without a `config.yaml`.
3. Set the necessary environment variables, such as `IDENTITY_PATH` and `IDENTITY_HTTP_PORT`, if required.
4. Run the installed binary to start the Identity microservice:

   ```shell
   identity
   ```

### Docker

The image contains the service and the built frontend, but no configuration. Mount your `config.yaml` (and `user.creds` for NATS):

```shell
docker run -d -p 8080:8080 \
  -v $PWD/config.yaml:/root/.flarex/identity/config.yaml:ro \
  -v $PWD/user.creds:/root/.flarex/identity/user.creds:ro \
  flarexio/identity:latest
```

## Web frontend

`web/` is an Angular app for signing in (Google, LINE, passkeys) and managing your account: linked sign-in methods, adding a passkey, deleting the account. The service serves it from `$IDENTITY_PATH/web` (or `http.web`) on the public port. For development, run the service on :8080 and `npm start` in `web/`; the dev server proxies API calls to it.

The browser never stores a bearer token: signing in sets an HttpOnly, `SameSite=Strict` session cookie, and the app trades it for short-lived access tokens kept in memory.

## Upgrading

- **`jwt.admins` now lists user IDs**, not usernames. Usernames are derived from e-mail addresses and freed when an account is deleted, so a username could end up with someone else. Startup fails until entries are user IDs.
- **User events are signed.** Add `eventBus.signing.key` (generate with `identity genkey`; use a different key from `jwt.privkey`), the same key on every instance consuming the stream. Unsigned events are ignored. Events already in the stream from before the upgrade are unsigned: an existing instance has applied them already, so this changes nothing for it. To build a fresh instance from that history, start it once with `eventBus.signing.allowUnsigned: true` until it has caught up, then turn it off. To rotate the key, move the old public key into `eventBus.signing.trusted`.
- **No fallback to `config.example.yaml`**, and its placeholder signing key is rejected. Anyone can sign tokens with a key published in this repository.
- **Badger stores are migrated on first start** to a layout where unlinked social accounts really stop resolving. Back up the data directory first.
- **Social accounts are looked up per provider.** The mTLS `GET /users/:subject` accepts `?provider=`; without it the ID must be unique across providers.
- **The LINE link URL must be fetched from the browser that will complete the flow** (`GET /auth/line/link/:user`, same origin), because the flow is now bound to it by a cookie.
- **`POST /identity/v1/passkeys/registration` needs a bearer token.** A passkey can only be linked by the user it was registered for.
- **`/scep/challenge/generate` requires a client certificate OU in `mtls.allowedOUs`.**
- **Refreshing an access token** works only up to `jwt.refresh.maximum` after the original sign-in. Tokens issued before this version cannot be refreshed; sign in again.
- **Errors are JSON** (`{"error": "<code>", "message": "..."}`) with conventional status codes instead of 417 with the raw error text.
- `POST /users/:user/verify` (OTP, never implemented) is gone.

## License

This project is licensed under the [MIT License](LICENSE).
