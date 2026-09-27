# Stellar Tags

Stellar Tags is a payment platform that combines a Soroban smart contract, a Node.js server, and a React dashboard. It is structured as a small mono-repo so each piece can be developed and deployed independently while still working together as a single product.

## What is inside

- `payment-dashboard/` - React + Vite frontend dashboard.
- `stellar-payment-platform/` - Node.js server for API and business logic.
- `payment_router/` - Rust/Soroban contract.

## Key features

- Desired specific username
- Fast transfer
- Secured payment flows

## Architecture Map

The following diagram maps exactly how data flows between the user, Render, and the Stellar network.

```text
[ User / Browser ]
       |
       | (Vite App hosted on Vercel)
       v
[ payment-dashboard ]
  (src/App.jsx: Wallet connections & UI)
       |
       | HTTP API Calls (via VITE_API_BASE)
       v
[ stellar-payment-platform ] <---> [ PostgreSQL Database ]
  (server.js: Server router on Render)        (via Prisma ORM: User/payment layout)
       |
       | Stellar Network / RPC
       v
[ payment_router ]
  (src/lib.rs: Soroban smart contract routing logic)
```

**Data Flow:**
1. **User** accesses the `payment-dashboard` and connects their Stellar wallet.
2. The dashboard queries the `stellar-payment-platform` server for user registrations and payment routing information.
3. The server interacts with its PostgreSQL database (via the Prisma ORM) to resolve usernames to addresses using the endpoints documented below.
4. When a payment is initiated, it's routed through the `payment_router` Soroban contract on the Stellar network.

## Repository structure

```text
.
├── payment-dashboard/
│   ├── .env                 # Frontend environment variables
│   └── src/
│       └── App.jsx          # Wallet connections and React UI
├── payment_router/
│   └── src/
│       └── lib.rs           # Soroban smart contract logic
└── stellar-payment-platform/
    ├── server.js            # Server router (Express API endpoints)
    └── prisma/
        └── schema.prisma    # Prisma schema for the PostgreSQL database
```

## Getting started

> These steps are split by module so you can run only what you need.

### Docker Compose profiles

Every service in `docker-compose.yml` belongs to a profile, so
`docker compose up` on its own starts nothing and you always say which stack
you want:

| Command | Starts |
| --- | --- |
| `docker compose --profile dev up` | backend, postgres, redis |
| `docker compose --profile full up` | the same, plus the built frontend on :3000 |
| `docker compose --profile test up` | the API under test on :5001 and its own database |
| `docker compose --profile integration up` | a local standalone Stellar network on :8000 |

`dev` is the everyday one. `full` adds the frontend, which is the slowest
thing in the file to build and is not needed for backend work.

The dev and test stacks use separate databases on separate host ports (5432
and 5433), so you can run both at once:

```bash
docker compose --profile dev --profile test up -d
```

`COMPOSE_PROFILES` works too, if you would rather not repeat the flag:

```bash
export COMPOSE_PROFILES=dev
docker compose up -d
```

Stop a stack with the same profile you started it with, otherwise Compose
will not know which services it is meant to remove:

```bash
docker compose --profile dev down
```

The `integration` profile pulls `stellar/quickstart`, a multi-gigabyte image
used only by the Soroban contract tests in `tests/integration/`. It is kept
out of `test` so the API tests do not drag it in.

### Frontend dashboard

```bash
cd payment-dashboard
npm install
npm run dev
```

### Server

The server uses **PostgreSQL** as its database, accessed through the
[Prisma ORM](https://www.prisma.io/). You need a running Postgres instance
(local install, Docker, or a hosted provider) before starting the server.

```bash
cd stellar-payment-platform
npm install

# 1. Create your local env file and point DATABASE_URL at your Postgres DB
cp .env.example .env
#    then edit .env (see "Database setup" below)

# 2. Apply the schema to your database
npm run prisma:migrate

# 3. Fill the database with test data
npm run db:seed

# 4. Start the server
npm run dev
```

#### Database setup

The connection string lives in `stellar-payment-platform/.env` as `DATABASE_URL`.
Copy `.env.example` to `.env` and set it to your own Postgres database:

```env
DATABASE_URL="postgresql://USER:PASSWORD@HOST:PORT/DATABASE?schema=public"
```

For a typical local install that becomes, for example:

```env
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/stellar_tags?schema=public"
```

The quickest way to get a local database is the dev profile, which also
brings up Redis:

```bash
docker compose --profile dev up -d postgres redis
```

Or a single container, if you want nothing else:

```bash
docker run --name stellar-postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=stellar_tags -p 5432:5432 -d postgres:16
```

Useful Prisma commands (run from `stellar-payment-platform/`):

| Command | Description |
| --- | --- |
| `npm run prisma:migrate` | Create/apply migrations against your dev database |
| `npm run prisma:deploy` | Apply existing migrations (CI / production) |
| `npm run prisma:generate` | Regenerate the Prisma Client after schema changes |
| `npm run prisma:studio` | Open Prisma Studio to browse the data |
| `npm run db:seed` | Populate the database with test data (see below) |

> `.env` is gitignored — never commit real credentials. Each contributor keeps
> their own local `DATABASE_URL`.

#### Seed data

`npm run db:seed` populates an empty database with 50 users, 10 webhooks,
20 payment intents and 2 API keys, so the API has something to answer with
before you have registered anything by hand. `prisma migrate reset` runs it
automatically.

The data covers the cases the endpoints branch on: usernames with every memo
type, several addresses carrying aliases alongside their primary username,
flagged and soft-deleted users, webhooks that are healthy, never delivered,
and failing on both sides of the retry cutoff, and payment intents in each
status.

Re-running is safe. Every record is upserted on its natural key and the
identities are derived from a fixed seed, so a second run updates the same
rows rather than adding a set. Pass `--reset` to delete the seeded rows first:

```bash
npm run db:seed -- --reset
```

Both API keys are printed on each run, since only their hashes are stored.
Use the active one as `X-Api-Key`; the revoked one is there to exercise the
rejection path. The script refuses to run against a non-local `DATABASE_URL`
unless `SEED_ALLOW_REMOTE=1` is set.

### Render deployment

The repository includes a [render.yaml](render.yaml) blueprint for the backend API and its PostgreSQL database. When you deploy from Render, import the blueprint or create the service from the repo so `DATABASE_URL` is injected automatically from the managed database.

If you deploy the backend without the blueprint, make sure the web service has a PostgreSQL `DATABASE_URL` secret configured before startup. The container runs Prisma migrations on boot, so the variable must already exist.

### Smart contract (Soroban)

```bash
cd payment_router
cargo build
```

### Contract TypeScript bindings

The TypeScript client for the `payment_router` contract lives in
[`packages/types`](packages/types) and is **auto-generated** from the contract
ABI, so the React dashboard gets end-to-end type safety with the Rust contract
instead of manually copying contract IDs and argument shapes.

Regenerate the bindings after any change to the contract's public interface
(the contract must build with the `wasm32-unknown-unknown` target, and the
`stellar` CLI must be on your PATH):

```bash
npm run generate:bindings
```

The result is committed to `packages/types` and consumed by the frontend as
`@stellar-tags/payment-router` (a `file:` dependency). The `bindings-check` CI
job fails the build if the checked-in bindings ever drift from the contract
ABI.

## Webhook signature verification

Every webhook delivery includes an HMAC-SHA256 signature in the
`X-Webhook-Signature` header (and the backward-compatible alias
`X-Stellar-Tags-Signature`). Merchants must verify this signature before
trusting the payload.

See [docs/webhook-signature-verification.md](docs/webhook-signature-verification.md)
for step-by-step verification examples in Node.js, Python, and Go.

## Internal service-to-service mTLS

Service-to-service calls are encrypted and mutually authenticated: the API
requires a client certificate signed by an internal CA before a request is
routed, and a peer with no valid certificate never reaches a handler. An
internal CA issues, rotates and retires the certificates, including a
zero-downtime cutover to a new issuing CA. Off by default, so local development
and CI keep using plain HTTP.

```sh
MTLS_ENABLED=true docker compose --profile dev --profile mtls up --build
```

See [docs/mtls.md](docs/mtls.md) for the PKI layout, rotation runbook and
configuration reference.

## Tests

```bash
# frontend
cd payment-dashboard
npm test

# server
cd ../stellar-payment-platform
npm test

# contract
cd ../payment_router
cargo test
```

### Coverage

The server runs with coverage in CI via `npm run test:coverage` (same as
`npm test` plus `--coverage`). Minimum coverage thresholds are set in
`stellar-payment-platform/package.json` under `jest.coverageThreshold` — CI
fails the build when coverage drops below the floor, and the `lcov`/HTML report
is uploaded as a build artifact. Raise the thresholds as coverage improves so
the floor keeps pace with the suite.


## Environment variables

To ensure a seamless local developer installation requiring zero guesswork, please configure the following environment variables in their respective directories:

### Frontend (`payment-dashboard/.env`)
- `VITE_API_BASE` - The base URL where the frontend expects the Node.js server API to be running (e.g., `http://localhost:5000`).

### Server (`stellar-payment-platform/.env` or exported directly)
- `DATABASE_URL` - **(Required)** PostgreSQL connection string used by Prisma (see [Database setup](#database-setup)).
- `PORT` - (Optional) The port for the Node.js server to listen on. Defaults to `5000`.
- `HORIZON_NETWORK` - (Optional) Stellar network for the payment listener: `testnet` (default) or `public`.
- `STELLAR_TAG_DOMAIN` - (Optional) Extra origin to add to the CORS allow-list.
- `LOG_DIR` - (Optional) Directory for the rotating log files. Defaults to `stellar-payment-platform/logs`.
- `LOG_LEVEL` - (Optional) Minimum level to record. Defaults to `info` in production and `debug` elsewhere.
- `LOG_MAX_SIZE` - (Optional) Size at which the active log file rotates. Defaults to `20m`.
- `LOG_MAX_FILES` - (Optional) Retention for rotated files, as a count (`30`) or an age (`14d`). Defaults to `14d`.
- `MIGRATION_POLICY` - (Optional) What to do at startup when `prisma migrate status` reports the database is out of sync (pending migrations or drift). `warn` (default) logs a clear warning and continues; `strict` logs an error and exits non-zero before the server binds a port; `off` skips the check. Set to `strict` where you want deploys to fail fast on schema drift instead of failing on the first query.

For Render deployments, make sure the web service has `DATABASE_URL` set in its environment or linked from a Render PostgreSQL instance before startup. The container runs `prisma migrate deploy` during boot, so the variable must be available at runtime.

## Logging

The server logs through a shared [Winston](https://github.com/winstonjs/winston) logger
(`stellar-payment-platform/src/logger.js`). Import it instead of calling `console` directly:

```js
const { logger } = require('./src/logger');

logger.info('Registered tag', { correlationId: req.correlationId, tag });
logger.error(err);
```

Log records are written as JSON to `stellar-payment-platform/logs/`:

- `application-YYYY-MM-DD.log` - everything at `LOG_LEVEL` and above.
- `error-YYYY-MM-DD.log` - errors only, so incidents are easy to find.

Both files rotate **daily and whenever they pass 20MB**, older files are gzipped, and
anything beyond the retention window is deleted, so logs cannot exhaust the disk. A
human-readable copy is also printed to the console (silenced when `NODE_ENV=test`, which
also disables file output so test runs leave no logs behind).

## Error responses

Every API error leaves the server in one shape, produced by a single terminal
handler (`stellar-payment-platform/src/middleware/errorHandler.js`):

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Invalid request body",
    "details": [{ "field": "username", "message": "username is required" }]
  },
  "correlation_id": "3f2a…",
  "reference_id": "9b41…"
}
```

`error.code` is the stable part of the contract — branch on it rather than on
the status or the message text, which may be reworded. `details` appears only
when the failure is field-level. `correlation_id` is on every error;
`reference_id` is added on `5xx` and matches the logged stack.

| Code | Status | Raised when |
| --- | --- | --- |
| `INVALID_INPUT` | 400 | Malformed query, JSON, or a rejected value |
| `UNAUTHENTICATED` | 401 | Missing or failed signature verification |
| `FORBIDDEN` | 403 | Reserved name, blocked address |
| `NOT_FOUND` | 404 | No such tag, address, or route |
| `METHOD_NOT_ALLOWED` | 405 | Wrong verb on a known path |
| `CONFLICT` | 409 | Username already taken, or an address is at its 5-username limit |
| `PAYLOAD_TOO_LARGE` | 413 | Body over the 10kb cap |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Non-JSON body on a JSON endpoint |
| `VALIDATION_FAILED` | 422 | Body failed its schema |
| `RATE_LIMITED` | 429 | Rate limit exhausted |
| `INTERNAL_ERROR` | 500 | Unhandled failure |
| `UPSTREAM_ERROR` | 502 | Horizon or another upstream failed |
| `SERVICE_UNAVAILABLE` | 503 | Database or Redis unreachable, request timeout |

To raise one, throw or pass an `ApiError` — the handler is the only place that
turns an error into a response:

```js
const { ApiError } = require('./src/errors');

return next(new ApiError('CONFLICT', 'Username is already taken. Please choose another.'));
```

A `5xx` from an unexpected throw always reports the generic message so
internals are never leaked; the real error goes to the log under
`reference_id`. A message passed deliberately to `ApiError` is sent as written.

`GET /health` is exempt: it reports component status (`{ status, database,
redis, horizon }`) rather than an API error.

## Request validation

Incoming request bodies and query strings are validated by
[zod](https://zod.dev) schemas before any route handler runs. Schemas live in
`stellar-payment-platform/src/schemas/index.js`, and
`src/middleware/validateSchema.js` turns them into route middleware:

```js
const { validateSchema } = require('./src/middleware/validateSchema');
const { registerBodySchema, usersQuerySchema } = require('./src/schemas');

app.post('/register', validateSchema({ body: registerBodySchema }), handler);
app.get('/users', validateSchema({ query: usersQuerySchema }), handler);
```

The validated part is replaced with the parsed result, so handlers receive
values that are already trimmed and coerced — `req.query.limit` is a number,
not a string — and never re-check types themselves.

Failures short-circuit before the handler and respond with the field-level
errors, using the status that matches where the bad input came from:

| Failure | Status | Body |
| --- | --- | --- |
| Invalid `req.body` | `422 Unprocessable Entity` | `{ success: false, errors: [{ field, message }] }` |
| Invalid `req.query` | `400 Bad Request` | `{ success: false, errors: [{ field, message }] }` |

Two rules are deliberately *not* in the schemas, because the handlers own them
and answer `400` with their own domain-specific messages: Stellar address
format (checked with `StrKey`) and memo pairing/format (checked with
`validateMemo`). `page` and `limit` clamp to their bounds rather than being
rejected, so `?limit=1000` still returns the maximum page size.

## Detailed Endpoint Documentation

The Node.js server (`stellar-payment-platform/server.js`) exposes the following endpoints for username and payment lookups:

### `GET /federation`
Resolves a given username tag to a Stellar address.
- **Query Parameter:** `q` (string) - The username tag to lookup (e.g., `alice*localhost`).
- **Returns:** A JSON object with `stellar_address`, `account_id`, `memo_type`, and `memo`.
- **Status Codes:**
  - `200 OK`: Address found.
  - `400 Bad Request`: Missing `q` parameter.
  - `404 Not Found`: Name tag not found.
  - `500 Internal Server Error`: Database lookup failed.

### `POST /register`
Registers a new username and associates it with a Stellar address. An address
may hold up to 5 usernames (aliases), e.g. `payments*domain` and
`support*domain` for one business account. The first username registered for an
address is its primary; reverse (`type=id`) federation lookups resolve to it.
- **Body Parameters (JSON):** 
  - `username` (string) - The desired username.
  - `address` (string) - The user's Stellar address.
- **Returns:** A JSON object with registration details `{ ok: true, username, address, is_primary }`.
- **Status Codes:**
  - `200 OK`: Registration successful.
  - `400 Bad Request`: Missing `username` or `address`.
  - `409 Conflict`: Username already taken, or the address already has the maximum of 5 usernames.
  - `500 Internal Server Error`: Database lookup or insertion failed.

### `GET /lookup`
Resolves a given Stellar address to its registered username. When an address has
several usernames, the primary one is returned.
- **Query Parameter:** `address` (string) - The Stellar address to lookup.
- **Returns:** A JSON object with `username` and `address`.
- **Status Codes:**
  - `200 OK`: Username found.
  - `400 Bad Request`: Missing `address` parameter.
  - `404 Not Found`: Username not found for this address.
  - `500 Internal Server Error`: Database lookup failed.

### `GET /users/:username/activity`
Returns the caller's own activity trail: registrations, transfers,
unregistrations, webhook creation and deletion, and blocks applied to their
address.

Ownership is proven the same way the webhook endpoints prove it. Sign the
message `activity:<username>` with the account key and send the base64
signature:

```bash
curl "http://localhost:5000/users/ada*localhost/activity?limit=20" \
  -H "X-Stellar-Signature: <base64 signature>" \
  -H "X-Stellar-Signer: <G... public key>"
```

The signature may also be sent in the request body as `signature` /
`signerAddress`, matching `GET /webhooks`.

- **Query Parameters:**
  - `page` (optional) - 1-based page number, default 1.
  - `limit` (optional) - rows per page, default 10, capped at 100.
  - `startDate` / `endDate` (optional) - inclusive bounds on `created_at`.
- **Returns:** `{ data, meta: { total, page, limit, totalPages } }`, newest
  first. Each row carries `id`, `action`, `metadata`, `ip_address` and
  `created_at`.
- **Status Codes:**
  - `200 OK`: Trail returned.
  - `400 Bad Request`: Missing signature, or an unparseable/inverted date range.
  - `401 Unauthorized`: The signature does not belong to the account behind the
    username.
  - `404 Not Found`: Username not registered.

Actions are namespaced: `user.registered`, `user.unregistered`,
`user.transferred`, `user.blocked`, `webhook.created`, `webhook.deleted`. Rows
are removed with the user, so a purge does not leave a trail behind.

### `GET /health`
Aggregates the status of every external dependency: PostgreSQL (a `SELECT 1`
through Prisma), Redis (`PING`) and Stellar Horizon (an HTTP request to
`HORIZON_BASE`). The three probes run in parallel.
- **Returns:** `{ status, timestamp, database, redis, horizon }`, where each
  dependency is `up`, `down`, or `not configured` (Redis, when `REDIS_URL` is
  unset). A `DOWN` response also carries a `message` naming the failures.
- **Status Codes:**
  - `200 OK`: Every configured dependency responded.
  - `503 Service Unavailable`: At least one dependency is down.

`HEALTH_HORIZON_TIMEOUT_MS` (default 3000) bounds the Horizon probe so a
hanging Horizon cannot hold the response open.

### `GET /transactions/export`
Streams the account's payment history as a CSV download.
- **Query Parameters:** `address` (required) - Stellar public key. `order` (optional) - `desc` (default) or `asc`.
- **Returns:** `text/csv` with a `Content-Disposition` attachment header. Columns: `id`, `created_at`, `type`, `from`, `to`, `amount`, `asset_type`, `asset_code`, `asset_issuer`, `transaction_hash`.
- **Status Codes:**
  - `200 OK`: Stream started. Sent chunked, so there is no `Content-Length`.
  - `400 Bad Request`: Missing or invalid `address`.
  - `404 Not Found`: Account not found on Horizon.
  - `502 Bad Gateway`: Horizon request failed.

Pages of 200 records are fetched from Horizon with its cursor, converted, and
flushed as they arrive, so neither the full result set nor the full CSV is held
in memory: heap use plateaus around 18MB whether the export is 5,000 rows or
100,000. Writes respect socket backpressure, and `EXPORT_MAX_PAGES`
(default 500) bounds a single export — a truncated export is logged as a
warning. Because the response is committed once streaming starts, a mid-stream
failure can only be logged and the connection cut, since the JSON error
envelope needs unsent headers.

The `/payments` collection mixes operation types that name the same concepts
differently, so participant and amount columns are normalised per type: a
`create_account` reports `funder`/`account`/`starting_balance` and an
`account_merge` reports `account`/`into`.

### `GET /admin/export`
Streams transaction records from the database as a CSV or NDJSON download for external accounting.
- **Query Parameters:**
  - `format` (optional) – `csv` (default) or `json`.
  - `startDate` (optional) – `YYYY-MM-DD` inclusive lower bound on `createdAt`.
  - `endDate` (optional) – `YYYY-MM-DD` inclusive upper bound on `createdAt`.
- **Headers:** `x-api-key` (required) – must match `ADMIN_API_KEY`.
- **Returns:** `text/csv` or `application/x-ndjson` with a `Content-Disposition: attachment` header.
- **Status Codes:**
  - `200 OK`: Stream started.
  - `400 Bad Request`: Invalid date format or `startDate` after `endDate`.
  - `401 Unauthorized`: Missing or invalid API key.

Records are fetched 500 at a time and written directly to the response, so heap use stays bounded regardless of export size. JSON output is newline-delimited (one object per line) for easy streaming parsing.

### `GET /admin/stats/routing`
Returns historical payment routing statistics and aggregated volumes, fees, and transaction counts grouped by day, week, or month.
- **Query Parameters:**
  - `startDate` (optional) – `YYYY-MM-DD` inclusive lower bound on `createdAt`.
  - `endDate` (optional) – `YYYY-MM-DD` inclusive upper bound on `createdAt`.
  - `groupBy` (optional) – `'day'` (default), `'week'`, or `'month'`.
  - `interval` (optional) – Alias for `groupBy`.
  - `assetCode` (optional) – Filter transactions by asset code (e.g., `XLM`, `USDC`).
- **Headers:** `x-api-key` (required) – must match `ADMIN_API_KEY` (or pass `api_key` in query params).
- **Returns:** JSON object containing `interval`, `startDate`, `endDate`, `summary` (`total_volume`, `total_fees`, `total_count`), and `data` array of periodic records (`[{ period, volume, fees, count }]`).
- **Status Codes:**
  - `200 OK`: Statistics retrieved successfully.
  - `400 Bad Request`: Invalid date format, `startDate` after `endDate`, or invalid `groupBy`.
  - `401 Unauthorized`: Missing or invalid API key.

### `GET /admin/audit-logs`
Retrieves recent immutable audit trail records for mutating admin actions (`POST`, `PUT`, `DELETE`, `PATCH`).
- **Query Parameters:**
  - `limit` (optional) – Maximum number of records to return (1-100, default 50).
- **Headers:** `x-api-key` (required) – must match `ADMIN_API_KEY` (or pass `api_key` in query params).
- **Returns:** JSON object with `success: true`, `count`, and `data` array of audit records containing `action`, `method`, `path`, `userId`, `ipAddress`, `userAgent`, `statusCode`, `payload` (sensitive data redacted), and `createdAt`.
- **Status Codes:**
  - `200 OK`: Audit logs retrieved successfully.
  - `401 Unauthorized`: Missing or invalid API key.

Mutating admin requests are intercepted by `auditLogMiddleware` and recorded asynchronously upon response completion. Sensitive keys (`password`, `secret`, `apiKey`, `token`, `signature`, `privateKey`, `seed`) are deeply redacted before persistence.

### `GET /admin/webhooks/health`
Aggregates webhook delivery health so operators can spot broken merchant integrations.
- **Query Parameters:**
  - `username` (optional) – Scope the aggregates to one merchant's webhooks.
- **Headers:** `x-api-key` (required) – must match `ADMIN_API_KEY`.
- **Returns:** JSON object with `success: true`, a `summary` (`total`, `healthy`, `failing`, `successRate24h`), and `failingOver24h` — the webhooks that have been failing continuously for more than 24 hours.
- **Status Codes:**
  - `200 OK`: Health snapshot retrieved successfully.
  - `401 Unauthorized`: Missing or invalid API key.

A webhook is "failing" while its `failingSince` timestamp is set (cleared on the next successful delivery). `successRate24h` is the share of webhooks with a delivery attempt in the last 24h that are currently healthy; it is `null` when nothing has been active in that window.

### `GET /metrics`

Prometheus scrape endpoint, served in the Prometheus text format. Exempt from the
rate limiter so a scraper on a fixed interval is never throttled.
- **Returns:** all metrics below, prefixed `stellar_tags_`.
- **Status Codes:** `200 OK`.

| Metric | Type | Description |
| --- | --- | --- |
| `process_resident_memory_bytes`, `nodejs_heap_size_used_bytes`, ... | gauge | Memory usage |
| `process_cpu_user_seconds_total`, `process_cpu_system_seconds_total` | counter | CPU usage |
| `http_requests_total` | counter | Requests by `method`, `route`, `status_code` |
| `http_request_duration_seconds` | histogram | Request latency by `method`, `route`, `status_code`; buckets at 10ms, 50ms, 100ms, 500ms, 1s, 5s |
| `db_pool_connections_open` | gauge | Connections open in the Prisma pool |
| `db_pool_connections_busy` | gauge | Connections executing a query |
| `db_pool_connections_idle` | gauge | Connections open but unused |
| `db_pool_queries_waiting` | gauge | Queries queued waiting for a connection |
| `redis_connections_active` | gauge | `1` while Redis is ready for commands, else `0` |

Memory and CPU come from `prom-client`'s default collectors. The pool gauges read
Prisma's `$metrics` (which requires the `metrics` preview feature in
`schema.prisma`) and report `0` when it is unavailable.

## Smart Contract Refund Mechanism

When a recipient cannot receive routed tokens (e.g. missing trustline, invalid contract recipient, or transfer rejection), the `PaymentRouter` smart contract prevents whole-transaction aborts by capturing the unrouteable tokens into the contract and crediting the sender's internal refund ledger (`DataKey::RefundBalance(user, token)`).

### Claiming Refunds
Users can query and withdraw their credited refunds at any time using the pull-based withdrawal pattern:
- `get_refund_balance(user: Address, token: Address) -> i128`: Query available internal refund balance.
- `withdraw_refund(user: Address, token: Address, amount: i128) -> Result<(), Error>`: Withdraw a specific amount of credited tokens.
- `claim_all_refunds(user: Address, token: Address) -> Result<i128, Error>`: Claim and withdraw the entire available refund balance in a single transaction.

### Arbitrary-token swaps

`route_payment_with_swap` accepts a DEX adapter, an input/output token pair, a
full token `path`, and `min_amount_out`. The adapter receives the input token and
must return `[amount_received, unused_input]`; the router rejects malformed
paths or slippage below the caller's minimum and credits unused input to the
sender's refund balance. Existing same-token `route_payment` and
`route_payments` calls remain unchanged.

### Fee governance

The contract supports token-weighted fee proposals. A SuperAdmin first calls
`configure_governance(governance_token, quorum)`. A token holder can then call
`propose_fee_change` and `vote_fee_proposal`; after the voting period, anyone
can call `execute_fee_proposal` when yes votes exceed no votes and quorum is
met. A voter can vote only once per proposal, and fee updates are applied only
after successful finalization.

## Smart Contract Deployment & Upgrades

The repository includes a dedicated CLI tool (`scripts/deploy.js` and `./scripts/deploy_contract.sh`) to automate WASM compilation, optimization, network deployment, contract initialization, and contract upgrades.

### CLI Usage

```bash
# Display help and available options
./scripts/deploy_contract.sh --help

# Deploy contract to testnet (compiles, optimizes, deploys, and updates .env configs)
./scripts/deploy_contract.sh deploy --network testnet

# Dry-run deployment (simulates workflow without on-chain transactions)
./scripts/deploy_contract.sh deploy --network testnet --dry-run

# Deploy with custom admin and funding source
./scripts/deploy_contract.sh deploy --network testnet --source S... --admin G... --treasury G...

# Deploy to mainnet
./scripts/deploy_contract.sh deploy --network mainnet --source S... --admin G...

# Upgrade an existing contract to newly compiled WASM
./scripts/deploy_contract.sh upgrade --contract-id C... --network testnet --source S...

# Compile and optimize WASM only
./scripts/deploy_contract.sh build
```

### Automation & Config Updates

Upon successful deployment, the tool automatically updates the contract address across:
- `stellar-payment-platform/.env` (`PAYMENT_ROUTER_CONTRACT_ID`, `CONTRACT_ID`)
- `payment-dashboard/.env` (`VITE_CONTRACT_ID`, `CONTRACT_ID`)
- `payment-dashboard/src/views/shared.js` (`CONTRACT_ID`)

## Architecture notes

- The React dashboard runs on `http://localhost:3000` in dev (Vite) and provides the UI.
- The dashboard calls the Node.js API at `http://localhost:5000` via `VITE_API_BASE` and a `/api` proxy.
- The Soroban contract handles on-chain payment routing logic.

## License

See [LICENSE](LICENSE).
