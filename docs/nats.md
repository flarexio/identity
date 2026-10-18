# NATS permissions

The `USERS` stream is identity's source of truth: the projection rebuilds accounts from it. Event signatures (`eventBus.signing`) stop anyone else from writing events identity will apply. They do nothing about two other things anyone with broad NATS access can do:

- publish to `users.>` anyway (dropped, but noisy, and other consumers may not verify), and
- **delete or purge the stream**, losing history a fresh instance would rebuild from.

So, in NATS itself, let only identity publish user events or manage the stream, and give every other service read-only access.

This assumes decentralized JWT auth managed with `nsc`, which is what a `.creds` file means. Every command below was run against a nats-server with the `nats` account resolver; the checks at the end are the ones used.

## Where permissions live

A user's permissions are in its **user JWT**, inside its `.creds` file, not on the server. Two consequences:

- After `nsc edit user`, the service only gets the new permissions once you **issue it a new `.creds` file** and deploy that. `nsc push` is not needed for this, since the account does not change.
- **Old `.creds` files keep their old, broader permissions** until they expire. Tightening permissions only helps once the old JWTs are **revoked**.

Revocation is by time: `nsc revocations add-user --at T` rejects every JWT for that user issued at or before `T`. `nsc generate creds` reuses the user's current JWT, so a JWT must be re-issued (by `nsc edit user`) *after* `T` to survive.

## Rolling it out without downtime

For each user (identity's and every other service's):

```sh
ACCOUNT=<your account>
USER=<the service's user>

# 1. Note the cutoff, then wait a second: revocation has 1s granularity.
CUTOFF=$(date +%s); sleep 2

# 2. Set the permissions (sections below). This issues a new JWT.
nsc edit user -a "$ACCOUNT" -n "$USER" ...

# 3. Issue and deploy the new creds; restart the service with them.
nsc generate creds -a "$ACCOUNT" -n "$USER" > "$USER.creds"

# 4. Once every instance runs on the new creds, revoke the old ones.
nsc revocations add-user -a "$ACCOUNT" -n "$USER" --at "$CUTOFF"
nsc push -a "$ACCOUNT"
```

Between steps 2 and 4 both old and new creds connect, so services can be redeployed one at a time. After step 4 the old creds fail with `Authorization Violation`, including on their existing connections. With a memory resolver instead of the `nats` resolver, regenerate the server config and reload it in place of `nsc push`.

## identity

identity publishes events, runs its JetStream consumer and the `identity.signin` service:

```sh
nsc edit user -a "$ACCOUNT" -n identity \
  --allow-pub 'users.>' \
  --allow-pub '$JS.API.>' \
  --allow-pub '$JS.ACK.USERS.>' \
  --allow-pub '$SRV.>' \
  --allow-pub '_INBOX.>' \
  --allow-sub 'identity.>' \
  --allow-sub '$SRV.>' \
  --allow-sub '_INBOX.>' \
  --allow-pub-response
```

`$JS.API.>` is broad because identity creates its stream and consumer at startup if they are missing. Once both exist you can narrow it to `$JS.API.INFO`, `$JS.API.STREAM.INFO.USERS`, `$JS.API.CONSUMER.>` and `$JS.API.CONSUMER.MSG.NEXT.USERS.>`.

## Every other service in the account

Deny publishing user events and changing the stream; reading, including through their own consumers, stays allowed:

```sh
nsc edit user -a "$ACCOUNT" -n <service> \
  --deny-pub 'users.>' \
  --deny-pub '$JS.API.STREAM.CREATE.USERS' \
  --deny-pub '$JS.API.STREAM.UPDATE.USERS' \
  --deny-pub '$JS.API.STREAM.DELETE.USERS' \
  --deny-pub '$JS.API.STREAM.PURGE.USERS' \
  --deny-pub '$JS.API.STREAM.MSG.DELETE.USERS'
```

Calling `identity.signin` keeps working with these.

## Keys

Anyone holding the account's identity key or one of its signing keys can mint a user with any permissions, which undoes all of the above. Keep them in the `nsc` keystore on an operator's machine, never on the hosts that run services; services only ever need their own `.creds`. Optionally give user JWTs an expiry (`nsc edit user --expiry 90d`) so a leaked `.creds` file stops working on its own.

## Checking it

With another service's new creds, the first two must fail with a permissions violation (the stream commands time out because the server drops the request); the last must succeed:

```sh
nats --creds service.creds pub users.01J0000000000000000000000.activated '{}'
nats --creds service.creds stream purge USERS -f
nats --creds service.creds stream info USERS
```

With that service's old creds, after step 4, every command must fail with `Authorization Violation`.

Consumers other than identity that rely on user events should also verify them, with `eventsig.NewVerifier` and identity's event-signing public key (the "Public Key" line `identity genkey` printed with it).
