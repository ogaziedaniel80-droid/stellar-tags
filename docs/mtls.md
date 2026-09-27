# Internal service-to-service mTLS

Mutual TLS between the platform's own services. Every request that crosses a
service boundary — the edge proxy to the API, the fraud worker to the API, a
webhook that points at another internal deployment — is encrypted and
authenticated with certificates issued by an internal CA. A peer with no valid
certificate never reaches a route.

Off by default. With `MTLS_ENABLED` unset the API listens on plain HTTP, which
is what local development and CI use.

- [Running it](#running-it)
- [How it behaves](#how-it-behaves)
- [The PKI](#the-pki)
- [Rotation](#rotation)
- [Configuration](#configuration)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)

## Running it

### Docker Compose

```sh
MTLS_ENABLED=true docker compose --profile dev --profile mtls up --build
```

The `mtls` profile adds a one-shot `pki-init` service that generates the CA and
each service's certificate, then exits. The stack waits for it, so no service
starts without material to read.

Issuer keys (`root/ca.key`, `intermediate/ca.key`) live in the `pki-ca` volume,
which is mounted into `pki-init` and nothing else. Services read the `certs`
volume: the trust bundle and their own keypair. A compromised backend therefore
cannot mint a certificate for a service it does not own.

### Local

```sh
npm run pki:init          # writes ./certs
MTLS_ENABLED=true \
MTLS_CA_FILE=./certs/ca-bundle.crt \
MTLS_CERT_FILE=./certs/services/api.crt \
MTLS_KEY_FILE=./certs/services/api.key \
npm start
```

`npm run pki:init` uses 4096-bit CA keys, which takes a few seconds. The
generated material is git-ignored and excluded from the Docker build context.

## How it behaves

**The listener.** `createHttpServer()` returns an HTTPS server when mTLS is on
and a plain HTTP server when it is off. Client-certificate enforcement sits
ahead of routing, so an unauthenticated caller is rejected during the handshake
rather than reaching a handler:

| Situation                                    | Result |
| -------------------------------------------- | ------ |
| No certificate presented (`required`)        | handshake fails, logged as `[mtls] TLS handshake rejected` |
| Certificate from an untrusted authority       | handshake fails |
| Valid certificate, identity not allowlisted  | `403`; the presented identity is logged |
| Valid certificate, identity allowlisted      | request proceeds with `req.serviceIdentity` set |

**Identity.** `serviceIdentity` reads the first URI SAN, then the first DNS
SAN, then the CN. Issued certificates carry a URI SAN
(`spiffe://stellar-tags/internal/<service>`), so the allowlist is written in
terms of a service identity rather than a hostname.

**Outbound calls.** `internalFetch()` (used by the Horizon health probe and the
webhook worker) attaches the client certificate only to hosts on
`MTLS_INTERNAL_DOMAINS`. Anything else stays on plain `fetch` and is never
given a credential — the internal identity does not leave the mesh. A plaintext
request to an internal host is refused rather than silently downgraded.

**Health.** `GET /health` reports the active transport alongside the existing
checks, so a probe can tell an `https` listener from an `http` one without
reading the logs.

## The PKI

`scripts/pki/pki.sh` is POSIX `sh` and wraps `openssl`; it runs identically on a
developer machine and inside the `alpine/openssl` image Compose uses.

```
root/                      offline-capable root CA
intermediate/              the issuing CA leaves are signed by
intermediate/retired/      superseded issuing CAs, kept until pruned
services/<name>.crt|.key   one leaf per service, valid for server and client auth
ca-bundle.crt              root + every live intermediate: the trust anchor
manifest.env               what was issued, and when it expires
```

Every leaf carries DNS, IP and URI SANs covering the service name, `localhost`
and `127.0.0.1`, so the same certificate works for container-to-container calls
and for a local test run. Private keys are written mode 600 in a 700 directory.

The trust bundle holding *every* live intermediate is what makes a CA rotation
possible without downtime: a peer that has already reloaded trusts both the old
and the new issuer, so the fleet can be switched over in any order.

## Rotation

```sh
npm run pki:rotate          # re-issue every leaf from the current intermediate
npm run pki:check           # report expiries; exit 1 inside the warning window
npm run pki:rotate:ca       # mint a new intermediate as well
npm run pki:prune           # drop superseded intermediates once the fleet is cut over
```

With `MTLS_HOT_RELOAD=true` (the default) a running process notices the change
within `MTLS_RELOAD_INTERVAL_MS` and rebuilds its secure context. The previous
context stays in service until the new material validates, so a truncated or
half-written file during a rotation cannot drop connections — a bad file is
logged and the running context is kept.

A full CA rotation is a four-step cutover, in this order:

1. `pki:rotate:ca` — the bundle now trusts both intermediates; leaves are
   re-issued from the new one.
2. Wait for every process to reload (`MTLS_RELOAD_INTERVAL_MS`, or restart).
3. Deploy. Old leaves remain valid because the old intermediate is still in the
   bundle.
4. `pki:prune` — removes the retired intermediate from the bundle. In Compose:

   ```sh
   docker compose --profile mtls run --rm pki-init \
     -c '/pki/pki.sh prune --out /ca && /export.sh'
   ```

In Compose, run the rotation through the same one-shot service so the runtime
volume is refreshed. `pki-init` keeps the issuer material in `pki-ca` and
republishes only the runtime subset, so a rotation never hands a CA key to a
running service:

```sh
# re-issue every leaf
docker compose --profile mtls run --rm pki-init \
  -c '/pki/pki.sh rotate --out /ca --days 397 && /export.sh'

# or, during a CA cutover, add --new-intermediate to the rotate above
```

Running `docker compose --profile mtls up pki-init` without overriding the
command only re-publishes the existing material, which is what a restarted
service needs after a volume that was never initialized.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MTLS_ENABLED` | `false` | Master switch. Off means plain HTTP. |
| `MTLS_CA_FILE` | — | Trust bundle. Required when enabled. |
| `MTLS_CERT_FILE` | — | This service's certificate. |
| `MTLS_KEY_FILE` | — | This service's private key. |
| `MTLS_CLIENT_CERT_FILE` | `MTLS_CERT_FILE` | Certificate for outbound calls. |
| `MTLS_CLIENT_KEY_FILE` | `MTLS_KEY_FILE` | Key for outbound calls. |
| `MTLS_CLIENT_AUTH` | `required` | `required`, `verify-if-given` or `none`. |
| `MTLS_REQUIRED_SANS` | — | Identities allowed to call this service. |
| `MTLS_MIN_VERSION` | `TLSv1.2` | Protocol floor. |
| `MTLS_CIPHERS` | Node defaults | Cipher list, in OpenSSL order. |
| `MTLS_INTERNAL_DOMAINS` | — | Hosts treated as internal. |
| `MTLS_HOT_RELOAD` | `true` | Watch the material and reload in place. |
| `MTLS_RELOAD_INTERVAL_MS` | `30000` | How often to look. |
| `MTLS_MAX_SOCKETS` | `64` | Pooled outbound connections. |
| `MTLS_CERT_DIR` | `./certs` | Base directory for relative paths. |

Each `*_FILE` variable has a `*_PEM` counterpart for platforms that inject the
material as a secret rather than mounting a file.

Configuration is validated at startup and the process exits non-zero on a bad
value: a missing certificate, an unreadable file, an identity allowlist that
cannot be parsed. The API never starts half-configured.

## Operations

`npm run pki:check` is meant for a schedule. It prints every certificate and its
expiry and exits 1 when anything is inside `--warn-days` (default 30), so it can
gate a deploy. Run it before the leaves get close to expiry, not after.

The `MTLS_REQUIRED_SANS` list has to include the healthcheck identity. The
container probe is rejected by the same policy it is verifying otherwise, and
Compose will report the service as unhealthy while the API is perfectly fine.

Certificate material never enters the git repository or the Docker build
context: `.gitignore` and `.dockerignore` exclude `*.key`, `*.crt` and the
`certs` directories.

## Troubleshooting

**`[mtls] TLS handshake rejected` with `alert number 40`.** A client reached the
listener without a certificate it could present. Check that the caller mounts
its own keypair and trusts the bundle.

**`ERR_SSL_NO_SUITABLE_SIGNATURE_ALGORITHM` after a reload.** The context was
swapped by handing `setSecureContext` a prebuilt `SecureContext`. On Node 24
that leaves the listener unable to pick a signature algorithm and every later
handshake fails; the watcher passes plain options instead. If you are writing
your own reload path, do the same.

**`Unable to read MTLS_CA_FILE`.** The path is resolved against
`MTLS_CERT_DIR`, and in containers that is `/app/certs`. The message names the
resolved path it tried.

**A peer is rejected with 403 despite a valid certificate.** Its identity is not
in `MTLS_REQUIRED_SANS`. `/health` reports the active allowlist under
`tls.requiredSans`, and the rejection is logged with the identity that was
presented.

**Certificates look fine but verification fails.** Check the trust bundle: a leaf
issued by a rotated-out intermediate needs the current `ca-bundle.crt`, not the
one the peer is holding.
