# NATS permissions

The `USERS` stream is identity's source of truth: the projection rebuilds accounts from it. Event signatures (`eventBus.signing`) stop anyone else from writing events identity will apply. They do nothing about two other things anyone with broad NATS access can do:

- publish to `users.>` anyway (dropped, but noisy, and other consumers may not verify), and
- **delete or purge the stream**, losing history a fresh instance would rebuild from.

So, in NATS itself, let only identity publish user events or manage the stream, and give every other service read-only access.

These examples use `nsc`, since identity connects with a `.creds` file (operator/JWT mode). Replace the account and user names with yours, then push the account with `nsc push`. Credentials issued from the edited users pick up the new permissions when they reconnect.

## identity

identity publishes events, runs its JetStream consumer and the `identity.signin` service:

```sh
nsc edit user identity \
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

`$JS.API.>` is broad because identity creates (or updates) its own stream and consumer at startup. Once both exist you can narrow it to `$JS.API.INFO`, `$JS.API.STREAM.INFO.USERS`, `$JS.API.CONSUMER.>` and `$JS.API.CONSUMER.MSG.NEXT.USERS.>`.

## Every other service in the account

Deny publishing user events and changing the stream; reading through their own consumers stays allowed:

```sh
nsc edit user <service> \
  --deny-pub 'users.>' \
  --deny-pub '$JS.API.STREAM.CREATE.USERS' \
  --deny-pub '$JS.API.STREAM.UPDATE.USERS' \
  --deny-pub '$JS.API.STREAM.DELETE.USERS' \
  --deny-pub '$JS.API.STREAM.PURGE.USERS' \
  --deny-pub '$JS.API.STREAM.MSG.DELETE.USERS'
```

A service that only calls `identity.signin` needs nothing beyond the defaults plus `_INBOX.>` for the reply.

## Checking it

With a non-identity user's credentials, both of these should be refused with a permissions violation:

```sh
nats --creds other.creds pub users.01J0000000000000000000000.activated '{}'
nats --creds other.creds stream purge USERS -f
```

Consumers other than identity that rely on user events should verify them as well, with `eventsig.NewVerifier` and identity's event-signing public key (the "Public Key" line `identity genkey` printed with it).
