require("./src/utils/tracing");
require("./config/envCheck");
const express = require("express");
const pinoHttp = require("pino-http");
const cors = require("cors");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const { securityMiddleware } = require("./src/middleware/security");
const crypto = require("crypto");
const { createClient } = require("redis");
const { createSignatureRateLimiter } = require("./src/middleware/signatureRateLimit");
const {
  createSlidingWindowRateLimiter,
} = require("./src/middleware/slidingWindowRateLimit");
const { createGraphQLMiddleware } = require("./src/graphql");
const { prisma, isPrismaConnectionError } = require("./prismaClient");
const { scheduleCleanupJob } = require("./src/cleanup-cron");
const { scheduleSoftDeletePurgeJob } = require("./src/soft-delete-purge-cron");
const { schedulePoolMonitoring } = require("./src/db-pool-monitor");
const { correlationId } = require("./middleware/correlation");
const { idempotencyMiddleware } = require("./middleware/idempotency");
const Filter = require("bad-words");
const dotenv = require("dotenv");
const timeout = require("connect-timeout");
const compression = require("compression");
const { verifyMultiSignerThreshold } = require("./src/multisigner-verifier");
const { logger, httpLogger } = require("./src/logger");
const xss = require("xss");
const { Keypair, StrKey } = require("@stellar/stellar-sdk");
const {
  metricsMiddleware,
  getMetrics,
  getContentType,
  setMetricsSources,
} = require("./src/metrics");
const { validateSchema } = require("./src/middleware/validateSchema");
const {
  buildErrorHandler,
  notFoundHandler,
} = require("./src/middleware/errorHandler");
const { ApiError, errorBody } = require("./src/errors");
const { requireJson } = require("./src/middleware/requireJson");
const { bodySizeLimit } = require("./src/middleware/bodyLimit");
const { apiVersion } = require("./src/middleware/apiVersion");
const { deprecationMiddleware } = require("./src/middleware/deprecation");
const {
  registerBodySchema,
  federationQuerySchema,
  lookupQuerySchema,
  usersQuerySchema,
} = require("./src/schemas");
const Sentry = require("@sentry/node");
const {
  ACTIVITY_ACTIONS,
  recordActivity,
} = require("./src/services/activityService");
const {
  lookupCached,
  federationNameKey,
  federationIdKey,
  federationLookupCached,
  invalidateFederationCache,
} = require("./src/cache");
const {
  paginatedResponse,
  parsePagination,
  parseCursorQuery,
  keysetWhereDesc,
  paginateByKeyset,
  cursorPaginatedResponse,
} = require("./src/pagination");
const {
  normalizeNameTag,
  validateMemo,
  RESERVED_NAMES,
  MAX_USERNAMES_PER_ADDRESS,
  PRIMARY_USERNAME_ORDER,
  USER_DATABASE,
} = require("./src/utils");
const { getCachedApprovedOrigins } = require("./src/originCache");
const { createHttpServer, describeTlsStatus } = require("./src/config/tls");
const { requireMutualTls, serviceIdentity } = require("./src/middleware/mtls");

dotenv.config();

// #295 ΓÇö Only report to Sentry when a DSN is configured, so local/dev/test
// runs without SENTRY_DSN never try to reach out to Sentry.
if (process.env.SENTRY_DSN) {
  Sentry.init({ dsn: process.env.SENTRY_DSN });
}

const app = express();

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Stellar Tags API",
      version: "1.0.0",
      description: "API for Stellar Tags",
    },
    servers: [
      {
        url: "http://localhost:5000",
      },
    ],
  },
  apis: ["./server.js", "./src/routes/v1/*.js"],
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);

// #31 — Attach a correlation ID to every request before anything else runs so
// all downstream middleware, handlers and logs can reference the same trace.
app.use(correlationId);

// #736 — Mutual TLS. `serviceIdentity` names the calling service from its
// client certificate so request logs and audit trails can attribute internal
// traffic, and `requireMutualTls` rejects anything that arrived without one.
// Both are no-ops while MTLS_ENABLED is false, and the /api-docs mount is
// deliberately below them so no route is reachable on an internal listener
// without a certificate.
app.use(serviceIdentity);
app.use(requireMutualTls);

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(pinoHttp({ logger, autoLogging: false })); // Use autoLogging: false if you want custom logs, or true if you want everything. PR says "Logs incoming HTTP requests", so let's enable it (default is true).
app.disable("x-powered-by");
app.use(securityMiddleware);

app.use(timeout("10s"));
app.use((err, req, res, next) => {
  if (req.timedout) {
    logger.error(err, `[Correlation ID: ${req.correlationId}] Request Timeout`);
    return next(new ApiError("SERVICE_UNAVAILABLE", undefined, { cause: err }));
  }
  next(err);
});

app.set("query parser", "simple");
const PORT = process.env.PORT || 5000;
const STELLAR_TAG_DOMAIN = process.env.STELLAR_TAG_DOMAIN;

const envOrigins = process.env.CORS_ALLOWED_ORIGINS
  ? process.env.CORS_ALLOWED_ORIGINS.split(",").map((o) => o.trim())
  : [];

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://stellar-tags.vercel.app",
  STELLAR_TAG_DOMAIN,
  process.env.VITE_API_BASE,
  ...envOrigins,
].filter(Boolean);

const corsOptions = {
  origin: async (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    try {
      const approvedOrigins = await getCachedApprovedOrigins(redisClient, () =>
        prisma.approvedOrigin
          .findMany({ select: { origin: true } })
          .then((rows) => rows.map((row) => row.origin)),
      );
      if (approvedOrigins && approvedOrigins.includes(origin)) {
        return callback(null, true);
      }
    } catch (err) {
      logger.error(
        err,
        "Failed to validate CORS origin against approved origins",
      );
    }
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

// Apply metrics middleware to track all HTTP requests
app.use(metricsMiddleware);

const REDIS_RETRY_MAX = 5;
const REDIS_RETRY_BASE_DELAY_MS = 500;

const redisClient = process.env.REDIS_URL
  ? createClient({
      url: process.env.REDIS_URL,
      socket: {
        reconnectStrategy(retries, cause) {
          if (retries >= REDIS_RETRY_MAX) {
            logger.error(
              { cause },
              `Redis connection failed after ${REDIS_RETRY_MAX} retries`,
            );
            return new Error(
              `Redis connection failed after ${REDIS_RETRY_MAX} retries`,
            );
          }
          const delay = Math.min(
            2 ** retries * REDIS_RETRY_BASE_DELAY_MS,
            10000,
          );
          logger.warn(
            { cause },
            `Redis connection attempt ${retries + 1} failed, retrying in ${delay}ms...`,
          );
          return delay;
        },
      },
    })
  : null;
if (redisClient) {
  redisClient.on("error", (err) => logger.error(err, "Redis client error:"));
  redisClient
    .connect()
    .catch((err) => logger.error(err, "Redis connection error:"));
}

setMetricsSources({ prisma, redisClient });

const v1Router = require("./src/routes/v1")(redisClient);
const v2Router = require("./src/routes/v2")(redisClient);
const graphQLMiddleware = createGraphQLMiddleware({ prismaClient: prisma });

const limiter = createSlidingWindowRateLimiter({
  redisClient,
  windowMs: 15 * 60 * 1000,
  max: 100,
  prefix: "global-rl:",
  message: errorBody(
    "RATE_LIMITED",
    "Too many requests, please try again later.",
  ),
  // Prometheus scrapes /metrics on a fixed interval from a single address, so
  // counting those scrapes against the shared quota would 429 the scraper.
  skip: (req) => req.path === "/metrics",
  // Key by authenticated user identifier when present (address/username),
  // otherwise fall back to client IP. This lets registered/identified users
  // get a per-account quota rather than being grouped by IP.
  keyGenerator: (req /*, res */) => {
    try {
      // 1) x-api-key (admin or API key users)
      const apiKey = req.headers["x-api-key"] || req.query.api_key;
      if (apiKey) return String(apiKey);

      // 2) JSON body address (e.g., /register)
      if (
        req.body &&
        typeof req.body.address === "string" &&
        req.body.address.trim()
      ) {
        return req.body.address.trim();
      }

      // 3) Query params: federation (q with type=id) or address param
      if (req.query) {
        if (
          req.query.type === "id" &&
          typeof req.query.q === "string" &&
          req.query.q.trim()
        ) {
          return req.query.q.trim();
        }
        if (typeof req.query.address === "string" && req.query.address.trim()) {
          return req.query.address.trim();
        }
        // Some endpoints use q for lookup by name; not an account id ΓÇö skip.
      }

      // 4) URL path pattern: /v1/accounts/:account
      const m =
        req.originalUrl && req.originalUrl.match(/\/v1\/accounts\/([^/]+)/i);
      if (m && m[1]) return decodeURIComponent(m[1]);

      // Default to IP
      return req.ip || (req.connection && req.connection.remoteAddress) || "";
    } catch (err) {
      // On error, fall back to IP so rate limiting still works
      return req.ip || "";
    }
  },
});

// Per-IP limiter specifically for sensitive, unauthenticated endpoints.
// Keys strictly by client IP so brute-force/spam from a single source is
// blocked regardless of how many account ids are rotated in the payload.
const ipLimiter = createSlidingWindowRateLimiter({
  redisClient,
  windowMs: 15 * 60 * 1000,
  max: 100,
  prefix: "ip-rl:",
  message: errorBody(
    "RATE_LIMITED",
    "Too many requests, please try again later.",
  ),
  keyGenerator: (req) =>
    req.ip || (req.connection && req.connection.remoteAddress) || "",
});

const signatureRateLimiter = createSignatureRateLimiter(redisClient);

app.use(cors(corsOptions));

// #588 ΓÇö Per-route request body size limits. A single JSON parser enforces a
// cap that depends on the endpoint type (auth 1kb / standard 10kb / bulk 100kb)
// instead of the previous uniform 10kb, and answers oversized payloads with 413.
app.use(bodySizeLimit);

app.use(limiter);
const isPrimitive = (v) =>
  v === null || v === undefined || typeof v !== "object";

const rejectNestedObjects = (req, res, next) => {
  // GraphQL variables are intentionally nested; field-level schema validation
  // replaces the flat-input guard used by the REST API.
  if (req.path === "/graphql") return next();

  const sources = [req.query, req.body];
  for (const source of sources) {
    if (source && typeof source === "object") {
      for (const val of Object.values(source)) {
        if (!isPrimitive(val)) {
          // Responds directly rather than delegating, so the middleware stays
          // usable on its own ΓÇö the same way validateSchema behaves.
          return res
            .status(400)
            .json(
              errorBody(
                "INVALID_INPUT",
                "Invalid parameter type: nested objects and arrays are not allowed.",
                { correlationId: req.correlationId },
              ),
            );
        }
      }
    }
  }
  next();
};

app.use(rejectNestedObjects);

// Enable HTTP response compression for responses exceeding 1KB (1024 bytes)
app.use(compression({ threshold: 1024 }));
app.use("/graphql", graphQLMiddleware);

scheduleCleanupJob(prisma);
scheduleSoftDeletePurgeJob(prisma);
const poolMonitor = schedulePoolMonitoring(prisma);

const RESERVED_USERNAMES = [
  "admin",
  "root",
  "stellar",
  "system",
  "superuser",
  "administrator",
  "support",
];

// ---------------------------------------------------------------------------
// #51 ΓÇö ETag Caching Middleware for Federation Endpoint
// ---------------------------------------------------------------------------
const etagCache = (req, res, next) => {
  const originalJson = res.json.bind(res);

  res.json = (body) => {
    const bodyString = JSON.stringify(body);
    const hash = crypto.createHash("sha256").update(bodyString).digest("hex");
    const etag = `"${hash}"`;

    res.set("ETag", etag);

    const clientEtag = req.get("If-None-Match");
    if (clientEtag && clientEtag === etag) {
      return res.status(304).end();
    }

    return originalJson(body);
  };

  next();
};

const getLocalUserByUsername = async (username) =>
  poolGet(
    "SELECT username, address FROM username_registry WHERE username = $1 LIMIT 1",
    [username],
  );

// Expose /metrics endpoint for Prometheus to scrape

/**
 * @openapi
 * /metrics:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /metrics
 *     responses:
 *       200:
 *         description: Success
 */
app.get("/metrics", async (req, res) => {
  try {
    res.set("Content-Type", getContentType());
    const metrics = await getMetrics();
    res.end(metrics);
  } catch (err) {
    logger.error(err, `[Correlation ID: ${req.correlationId}] Metrics error`);
    res.status(500).end(err.message);
  }
});

/**
 * @openapi
 * /federation:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /federation
 *     responses:
 *       200:
 *         description: Success
 */
app.get(
  "/federation",
  ipLimiter,
  etagCache,
  validateSchema({ query: federationQuerySchema }),
  async (req, res, next) => {
    const { q: queryValue, type } = req.query;

    try {
      if (type === "id") {
        const cacheKey = federationIdKey(queryValue);
        const cached = await federationLookupCached(cacheKey, async () => {
          // #613 ΓÇö an address can have several usernames; a reverse lookup
          // resolves to the primary one.
          const row = await prisma.user.findFirst({
            where: {
              address: { equals: queryValue, mode: "insensitive" },
              deletedAt: null,
            },
            select: {
              username: true,
              address: true,
              memoType: true,
              memo: true,
              flaggedAt: true,
            },
            orderBy: PRIMARY_USERNAME_ORDER,
          });

          if (!row) return null;
          if (row.flaggedAt) {
            const forbiddenError = new Error("Address is blocked");
            forbiddenError.statusCode = 403;
            throw forbiddenError;
          }

          const response = {
            stellar_address: `${row.username}*${process.env.DOMAIN || "localhost"}`,
            account_id: row.address,
          };
          if (row.memoType) {
            response.memo_type = row.memoType;
            response.memo = row.memo;
          }
          return response;
        });

        if (!cached) {
          const notFoundError = new Error("Address not found");
          notFoundError.statusCode = 404;
          return next(notFoundError);
        }

        return res.json(cached);
      } else if (type === "name" || !type) {
        const nameTag = normalizeNameTag(queryValue);
        const queryName = nameTag.toLowerCase();
        const cacheKey = federationNameKey(queryName);

        const cached = await federationLookupCached(cacheKey, async () => {
          let row = await prisma.user.findFirst({
            where: { username: queryName, deletedAt: null },
            select: {
              address: true,
              memoType: true,
              memo: true,
              flaggedAt: true,
            },
          });

          if (row && row.flaggedAt) {
            const forbiddenError = new Error("Address is blocked");
            forbiddenError.statusCode = 403;
            throw forbiddenError;
          }

          const address = row?.address || USER_DATABASE[queryName];
          if (!address) return null;

          const response = {
            stellar_address: address,
            account_id: address,
          };
          if (row?.memoType) {
            response.memo_type = row.memoType;
            response.memo = row.memo;
          }
          return response;
        });

        if (!cached) {
          const notFoundError = new Error("Name tag not found");
          notFoundError.statusCode = 404;
          return next(notFoundError);
        }

        return res.json(cached);
      } else {
        return next(
          new ApiError(
            "INVALID_INPUT",
            "Unsupported query type. Supported types: 'id', 'name'",
          ),
        );
      }
    } catch (error) {
      const dbError = new Error("Database lookup failed", { cause: error });
      dbError.statusCode = 500;
      return next(dbError);
    }
  },
);

// Initialise profanity filter once at module load (reused across requests).
const profanityFilter = new Filter();
const verifyFreighterRegistrationSignature = ({
  username,
  address,
  signature,
  signerAddress,
}) => {
  const message = `register:${username}:${address}`;
  const claimedSigner = signerAddress || address;

  if (!StrKey.isValidEd25519PublicKey(claimedSigner)) {
    const error = new Error("Invalid signer address format.");
    error.statusCode = 400;
    throw error;
  }

  const keypair = Keypair.fromPublicKey(claimedSigner);

  let signatureBuffer;
  if (Buffer.isBuffer(signature)) {
    signatureBuffer = signature;
  } else if (typeof signature === "string") {
    // If it's a 128-char hex string
    if (signature.length === 128 && /^[0-9a-fA-F]+$/.test(signature)) {
      signatureBuffer = Buffer.from(signature, "hex");
    } else {
      signatureBuffer = Buffer.from(signature, "base64");
      // If the resulting buffer is 86-88 bytes long, it might be the ASCII bytes of a base64 string (double encoded)
      if (signatureBuffer.length >= 80 && signatureBuffer.length <= 90) {
        const text = signatureBuffer.toString("utf8");
        if (/^[a-zA-Z0-9+/]+={0,2}$/.test(text)) {
          signatureBuffer = Buffer.from(text, "base64");
        }
      }
    }
  } else {
    throw new Error("Invalid message signature format.");
  }

  // --- SEP-0053 Verification Logic ---
  // Freighter adds a specific prefix and hashes the payload before signing
  const prefix = Buffer.from("Stellar Signed Message:\n", "utf8");
  const messageBytes = Buffer.from(message, "utf8");
  const payload = Buffer.concat([prefix, messageBytes]);
  const messageHash = crypto.createHash("sha256").update(payload).digest();

  // Verify against the hashed payload (SEP-0053) first
  if (!keypair.verify(messageHash, signatureBuffer)) {
    // If that fails, try verifying the raw message directly in case the wallet used signBlob
    if (!keypair.verify(messageBytes, signatureBuffer)) {
      // Also try verifying the payload without hashing it
      if (!keypair.verify(payload, signatureBuffer)) {
        const error = new Error("Signature verification failed.");
        error.statusCode = 401;
        throw error;
      }
    }
  }

  if (claimedSigner !== address) {
    const error = new Error(
      "Signer address does not match the connected wallet.",
    );
    error.statusCode = 401;
    throw error;
  }

  return claimedSigner;
};

/**
 * Registration endpoint with multi-signer threshold verification
 *
 * For single-signer accounts:
 * - Signature must be the account's public key or a registered signer
 * - Basic validation of address format
 *
 * For multi-signer accounts (enterprise):
 * - Fetches account signers and thresholds from Horizon
 * - Validates that provided signature(s) meet minimum threshold
 * - Ensures authorization requirements are satisfied
 */

/**
 * @openapi
 * /register:
 *   post:
 *     tags:
 *       - v1
 *     description: POST /register
 *     responses:
 *       200:
 *         description: Success
 */
app.post(
  "/register",
  signatureRateLimiter,
  idempotencyMiddleware(redisClient),
  requireJson,
  validateSchema({ body: registerBodySchema }),
  async (req, res, next) => {
    // registerBodySchema has already guaranteed that username is a trimmed
    // 3-20 character alphanumeric string and address is a non-empty trimmed
    // string, so those shape checks are not repeated here.
    const safeUsername = xss(req.body.username);
    const username = normalizeNameTag(safeUsername);
    const {
      address,
      memo_type: memoType,
      memo,
      signature = "",
      signerAddress = "",
    } = req.body;

    if (address.toUpperCase().startsWith("S")) {
      return next(
        new ApiError(
          "INVALID_INPUT",
          "Never share your Secret Key. Please register using your Public Key (starts with G).",
        ),
      );
    }

    // Extract the username part before the * for the profanity check
    const usernameLocalPart = username.includes("*")
      ? username.split("*")[0]
      : username;

    // Reject usernames containing profanity or offensive words.
    if (profanityFilter.isProfane(usernameLocalPart)) {
      return next(
        new ApiError("INVALID_INPUT", "Username contains restricted words"),
      );
    }

    if (!StrKey.isValidEd25519PublicKey(address)) {
      const error = new Error("Invalid Stellar Public Key format.");
      error.statusCode = 400;
      return next(error);
    }

    const memoError = validateMemo(memoType, memo);
    if (memoError) {
      return next(new ApiError("INVALID_INPUT", memoError));
    }

    const normalizedUsername = username.toLowerCase();

    const normalizedLocalPart = normalizedUsername.includes("*")
      ? normalizedUsername.split("*")[0]
      : normalizedUsername;
    if (RESERVED_USERNAMES.includes(normalizedLocalPart)) {
      return res.status(403).json({ error: "Username is reserved." });
    }

    const RESERVED_NAMES = [
      "admin",
      "root",
      "support",
      "system",
      "stellar",
      "api",
      "help",
    ];
    if (RESERVED_NAMES.includes(normalizedUsername)) {
      return next(
        new ApiError(
          "FORBIDDEN",
          "This username is reserved and cannot be registered.",
        ),
      );
    }

    try {
      // #613 ΓÇö an address may carry several usernames (aliases). Registration
      // adds another while the address is under the cap; the first username
      // registered for an address becomes its primary. Reverse (type=id)
      // federation lookups resolve to that primary.
      let usernameCount = await prisma.user.count({
        where: { address, deletedAt: null },
      });

      if (usernameCount >= MAX_USERNAMES_PER_ADDRESS) {
        return next(
          new ApiError(
            "CONFLICT",
            `This address already has the maximum of ${MAX_USERNAMES_PER_ADDRESS} federation usernames.`,
          ),
        );
      }
      const isPrimary = usernameCount === 0;

      let verificationResult = null;
      if (signature) {
        const isLegacyPublicKeyFlow =
          StrKey.isValidEd25519PublicKey(signature) && !signerAddress;

        if (isLegacyPublicKeyFlow) {
          verificationResult = await verifyMultiSignerThreshold(
            address,
            [signature],
            {
              operationType: "management",
            },
          );

          if (!verificationResult.success) {
            const verificationError = new Error(
              verificationResult.errorMessage ||
                "Signature verification failed",
            );
            verificationError.statusCode = 401;
            throw verificationError;
          }
        } else {
          const claimedSigner = verifyFreighterRegistrationSignature({
            username: req.body.username,
            address: req.body.address, // Make sure this is using the raw body too!
            signature,
            signerAddress,
          });

          verificationResult = {
            success: true,
            accountId: claimedSigner,
            operationType: "message",
            requiredThreshold: 1,
            totalWeight: 1,
            signatureCount: 1,
            uniqueSignerCount: 1,
            signatures: [
              {
                publicKey: claimedSigner,
                weight: 1,
                isValid: true,
              },
            ],
            thresholds: {
              low_threshold: 1,
              med_threshold: 1,
              high_threshold: 1,
            },
            signerCount: 1,
            errorMessage: null,
          };
        }
      }

      await prisma.user.create({
        data: {
          username: normalizedUsername,
          address,
          isPrimary,
          ...(memoType && { memoType, memo }),
        },
      });
      // Invalidate any stale federation cache entries for this username/address
      invalidateFederationCache(normalizedUsername, address);

      await recordActivity(prisma, {
        username: normalizedUsername,
        action: ACTIVITY_ACTIONS.USER_REGISTERED,
        metadata: {
          address,
          is_primary: isPrimary,
          ...(memoType && { memo_type: memoType }),
        },
        req,
      });

      return res.status(201).json({
        ok: true,
        username: normalizedUsername,
        address,
        is_primary: isPrimary,
        federation_address: `${normalizedUsername}*${process.env.DOMAIN || "localhost"}`,
        ...(verificationResult && {
          verification: {
            accountId: verificationResult.accountId,
            signerCount: verificationResult.signerCount,
            thresholdMet: verificationResult.success,
            requiredThreshold: verificationResult.requiredThreshold,
            providedWeight: verificationResult.totalWeight,
          },
        }),
        ...(memoType && { memo_type: memoType, memo }),
      });
    } catch (error) {
      if (
        error.code === "23505" ||
        error.code === "P2002" ||
        (error.message && error.message.includes("UNIQUE"))
      ) {
        return next(
          new ApiError(
            "CONFLICT",
            "Username is already taken. Please choose another.",
          ),
        );
      }

      // Handle verification errors
      if (error.message && error.message.includes("Account not found")) {
        const notFoundError = new Error(
          `Account not found on Horizon: ${address}`,
        );
        notFoundError.statusCode = 404;
        return next(notFoundError);
      }

      // Handle signature verification errors
      if (error.statusCode === 401) {
        return next(error);
      }

      // Handle other errors
      logger.error({ err: error.message }, "Registration error:");
      const registrationError = new Error(
        `Registration verification failed: ${error.message}`,
      );
      registrationError.statusCode = 500;
      return next(registrationError);
    }
  },
);

app.all("/register", (req, res, next) =>
  next(new ApiError("METHOD_NOT_ALLOWED")),
);

/**
 * @openapi
 * /lookup:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /lookup
 *     responses:
 *       200:
 *         description: Success
 */
app.get(
  "/lookup",
  validateSchema({ query: lookupQuerySchema }),
  async (req, res, next) => {
    const { address = "", search = "" } = req.query;

    if (address) {
      try {
        const result = await lookupCached(address, async () => {
          // #613 — an address can have several usernames; return the primary.
          let row = await prisma.user.findFirst({
            where: { address, deletedAt: null },
            select: { username: true },
            orderBy: PRIMARY_USERNAME_ORDER,
          });
          return row ? { username: row.username, address } : null;
        });

        if (!result) {
          const notFoundError = new Error(
            "Username not found for this address",
          );
          notFoundError.statusCode = 404;
          return next(notFoundError);
        }

        return res.json(result);
      } catch (err) {
        logger.error(err, "≡ƒÜ¿ ACTUAL PRISMA ERROR:");

        const dbError = new Error("Database lookup failed", { cause: err });
        dbError.statusCode = 500;
        return next(dbError);
      }
    }

    const {
      limit: cursorLimit,
      cursor,
      invalid: invalidCursor,
    } = parseCursorQuery(req.query);
    const { page, limit, skip } = parsePagination(req.query);
    if (invalidCursor) {
      return next(new ApiError("INVALID_INPUT", "Invalid cursor parameter"));
    }

    const where = {
      deletedAt: null,
      OR: [
        { username: { contains: search, mode: "insensitive" } },
        { address: { contains: search, mode: "insensitive" } },
      ],
    };

    try {
      let response = null;
        if (cursor) {
          // Keyset mode: seek straight past the cursor row instead of skipping
          // every preceding row, so deep pages cost the same as page one.
          const candidates = await prisma.user.findMany({
            where: { AND: [where, keysetWhereDesc(cursor)] },
            orderBy: [{ createdAt: "desc" }, { username: "desc" }],
            take: cursorLimit + 1,
          });
          const { rows, hasMore, nextCursor } = paginateByKeyset(
            candidates,
            cursorLimit,
          );
          response = cursorPaginatedResponse(
            rows.map((user) => ({
              username: user.username,
              address: user.address,
              created_at: user.createdAt.toISOString(),
            })),
            { limit: cursorLimit, nextCursor, hasMore },
          );
        } else {
          const [totalCount, rows] = await prisma.$transaction([
            prisma.user.count({ where }),
            prisma.user.findMany({
              where,
              orderBy: [{ createdAt: "desc" }, { username: "desc" }],
              skip,
              take: limit,
            }),
          ]);

          response = paginatedResponse(
            rows.map((user) => ({
              username: user.username,
              address: user.address,
              created_at: user.createdAt.toISOString(),
            })),
            totalCount,
            { page, limit },
          );
        }


      return res.json(response);
    } catch (error) {
      const dbError = new Error("Database lookup failed", { cause: error });
      dbError.statusCode = 500;
      return next(dbError);
    }
  },
);

/**
 * @openapi
 * /users:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /users
 *     responses:
 *       200:
 *         description: Success
 */
app.get(
  "/users",
  validateSchema({ query: usersQuerySchema }),
  async (req, res, next) => {
    const {
      limit: cursorLimit,
      cursor,
      invalid: invalidCursor,
    } = parseCursorQuery(req.query);
    const { page, limit, skip } = parsePagination(req.query);
    if (invalidCursor) {
      return next(new ApiError("INVALID_INPUT", "Invalid cursor parameter"));
    }
    const search = req.query.search ?? null;

    const where = search
      ? {
          deletedAt: null,
          OR: [
            { username: { contains: search, mode: "insensitive" } },
            { address: { contains: search, mode: "insensitive" } },
          ],
        }
      : { deletedAt: null };

    try {
      if (cursor) {
        // Keyset mode: seek straight past the cursor row instead of skipping
        // every preceding row, so deep pages cost the same as page one.
        const candidates = await prisma.user.findMany({
          where: { AND: [where, keysetWhereDesc(cursor)] },
          orderBy: [{ createdAt: "desc" }, { username: "desc" }],
          take: cursorLimit + 1,
        });
        const { rows, hasMore, nextCursor } = paginateByKeyset(
          candidates,
          cursorLimit,
        );
        const data = rows.map((user) => ({
          username: user.username,
          address: user.address,
          created_at: user.createdAt ? user.createdAt.toISOString() : undefined,
        }));
        return res.json(
          cursorPaginatedResponse(data, {
            limit: cursorLimit,
            nextCursor,
            hasMore,
          }),
        );
      }

      const [totalCount, rows] = await prisma.$transaction([
        prisma.user.count({ where }),
        prisma.user.findMany({
          where,
          orderBy: [{ createdAt: "desc" }, { username: "desc" }],
          skip,
          take: limit,
        }),
      ]);

      const totalPages = Math.ceil(totalCount / limit);
      const data = rows.map((user) => ({
        username: user.username,
        address: user.address,
        created_at: user.createdAt ? user.createdAt.toISOString() : undefined,
      }));

      res.json({
        data,
        meta: {
          total: totalCount,
          totalCount,
          page,
          currentPage: page,
          limit,
          totalPages,
        },
        totalCount,
        totalPages,
        currentPage: page,
      });
    } catch (error) {
      const dbError = new Error("Database error", { cause: error });
      dbError.statusCode = 500;
      return next(dbError);
    }
  },
);
// Request versioning: URI (/api/v1, /api/v2) first, then Accept-Version /
// API-Version header, defaulting to v1. Routers below then decide routing.
app.use(apiVersion);

// RFC 8594 deprecation headers: attaches Deprecation/Sunset/Link to endpoints
// listed in src/config/deprecations.js and logs a server-side warning.
app.use(deprecationMiddleware());

// v2 first so an explicit /api/v2 request wins over the unversioned fallback.
app.use("/api/v2", v2Router);
// Explicit v1 mount, then /api (no version) and the legacy unversioned root
// both resolve to v1 so existing clients keep working unchanged.
app.use("/api/v1", v1Router);
// #492 ΓÇö Strict rate limiter for auth/login endpoints. These are prime
// brute-force targets, so they get a much tighter budget than the global
// limiter. Uses the same Redis-backed store so the limit is shared across
// all distributed nodes.
const authLimiter = createSlidingWindowRateLimiter({
  redisClient,
  windowMs: 15 * 60 * 1000,
  max: 20,
  prefix: "auth-rl:",
  message: errorBody(
    "RATE_LIMITED",
    "Too many requests, please try again later.",
  ),
  keyGenerator: (req) =>
    req.ip || (req.connection && req.connection.remoteAddress) || "",
});

app.use("/api", v1Router);
app.use("/", v1Router);
// Auth endpoints (email OTP verification) - uses Redis when available
app.use(
  "/auth",
  authLimiter,
  require("./src/routes/v1/authRoutes")(redisClient),
);

// API key management endpoints (rotation, invalidation, listing)
app.use("/auth/api-keys", require("./src/routes/v1/apiKeyRoutes")(redisClient));

// #497 ΓÇö Expose RSA public key as a JWKS document so external services can
// verify RS256-signed tokens without sharing a secret.

/**
 * @openapi
 * /.well-known/jwks.json:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /.well-known/jwks.json
 *     responses:
 *       200:
 *         description: Success
 */
app.get("/.well-known/jwks.json", (_req, res) => {
  try {
    const { getJwks } = require("./src/utils/jwt");
    const jwks = getJwks();
    res.setHeader("Content-Type", "application/json");
    // Cache for 1 hour ΓÇö key rotations are infrequent and consumers should
    // re-fetch on verification failure anyway.
    res.setHeader("Cache-Control", "public, max-age=3600");
    return res.json(jwks);
  } catch (err) {
    logger.warn({ err }, "JWKS endpoint: JWT_PUBLIC_KEY is not configured");
    return res
      .status(503)
      .json({ error: "JWKS not available: public key not configured." });
  }
});

/**
 * @openapi
 * /.well-known/stellar.toml:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /.well-known/stellar.toml
 *     responses:
 *       200:
 *         description: Success
 */
app.get("/.well-known/stellar.toml", (_req, res) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.setHeader("Content-Type", "text/plain");
  res.send(
    `FEDERATION_SERVER="${process.env.FEDERATION_SERVER_URL || `https://${process.env.STELLAR_TAG_DOMAIN}/federation`}"\n`,
  );
});

/**
 * @openapi
 * /api/v1/time:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /api/v1/time
 *     responses:
 *       200:
 *         description: Success
 */
app.get("/api/v1/time", (_req, res) => {
  res.status(200).json({ time: new Date().toISOString() });
});

app.use(require("./src/routes/v1/healthRoutes")(redisClient));

// #295 ΓÇö Report 5xx errors to Sentry (via defaultShouldHandleError) before
// they reach our own JSON error handler below.
if (process.env.SENTRY_DSN) {
  Sentry.setupExpressErrorHandler(app);
}

// Unmatched routes and every error share the standard envelope.
app.use(notFoundHandler);
app.use(buildErrorHandler(isPrismaConnectionError));

const SHUTDOWN_TIMEOUT_MS =
  parseInt(process.env.SHUTDOWN_TIMEOUT_MS, 10) || 10_000;
let isShuttingDown = false;

const gracefulShutdown = (server, prismaClient, signal, redis = null) => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info(`\nReceived ${signal}. Shutting down gracefully...`);

  // Stop the pool monitor so it doesn't produce misleading warnings during
  // the shutdown window.
  poolMonitor.stop();

  const timer = setTimeout(() => {
    logger.error(
      `Graceful shutdown timed out after ${SHUTDOWN_TIMEOUT_MS / 1000}s, forcing exit.`,
    );
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);

  server.close(async () => {
    clearTimeout(timer);
    try {
      await prismaClient.$disconnect();
    } catch (err) {
      logger.error(err, "Error disconnecting Prisma during shutdown:");
    }
    if (redis) {
      try {
        await redis.quit();
      } catch (err) {
        logger.error(err, "Error disconnecting Redis during shutdown:");
      }
    }
    process.exit(0);
  });
};

if (require.main === module) {
  const {
    checkMigrations,
    enforceMigrationPolicy,
  } = require("./src/migrate-check");

  const startServer = () => {
    // createHttpServer returns an https listener that demands a client
    // certificate when mTLS is enabled, and a plain http listener otherwise.
    let server;
    try {
      server = createHttpServer(app);
    } catch (err) {
      // Refuse to start rather than silently serving in clear when the
      // certificate material is unusable.
      logger.error({ err: err.message }, "[mtls] Refusing to start: invalid TLS configuration.");
      process.exit(1);
    }
    const tlsStatus = describeTlsStatus();

    server.listen(PORT, "0.0.0.0", () => {
      logger.info(`Server successfully initialized on port ${PORT}`);
      logger.info(
        { tls: tlsStatus },
        `Transport: ${tlsStatus.transport.toUpperCase()}${
          tlsStatus.clientCertificateRequired
            ? " with mandatory client certificates"
            : ""
        }`,
      );
    });

    server.on("error", (e) => {
      if (e.code === "EADDRINUSE") {
        logger.error(
          e,
          `Port ${PORT} is in use, forcing shutdown so Railway can restart cleanly.`,
        );
        process.exit(1);
      }
    });

    process.on("SIGTERM", (sig) =>
      gracefulShutdown(server, prisma, sig, redisClient),
    );
    process.on("SIGINT", (sig) =>
      gracefulShutdown(server, prisma, sig, redisClient),
    );
  };

  // Verify the database is not out of sync with the Prisma migrations before
  // binding a port, so schema drift surfaces as a clear startup error instead
  // of a cryptic failure on the first query. In strict mode this exits
  // (non-zero) when migrations are pending; in permissive mode it warns and
  // continues. The server only boots once the result is known.
  checkMigrations()
    .then((result) => {
      const { shouldExit } = enforceMigrationPolicy(result);
      if (shouldExit) {
        logger.error(
          "[migrate-check] Aborting startup: database migrations are not applied.",
        );
        process.exit(1);
      }
      startServer();
    })
    .catch((err) => {
      // Unexpected failure running the check itself ΓÇö refuse to start deceptively
      // healthy when we couldn't validate schema parity.
      logger.error(
        err,
        "[migrate-check] Failed to verify migration status at startup.",
      );
      process.exit(1);
    });
}

module.exports = {
  app,
  createHttpServer,
  gracefulShutdown,
  rejectNestedObjects,
  validateMemo,
};
