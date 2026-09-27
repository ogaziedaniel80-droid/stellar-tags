const crypto = require('crypto');
const { Queue, Worker } = require('bullmq');
const { createRedisConnection, withRedisRetry } = require('./config/redis');
const { logger } = require('./logger');
const { shouldFallbackToLocalRegistry } = require('./utils');
const { internalFetch } = require('./utils/internalClient');

const WEBHOOK_TIMEOUT_MS = 10_000;
const WEBHOOK_QUEUE_NAME = 'webhook-deliveries';
const MAX_WEBHOOK_ATTEMPTS = 5;
const WEBHOOK_BACKOFF_DELAY_MS = 1_000;
const WEBHOOK_WORKER_CONCURRENCY = 5;
const MAX_RETRY_BACKLOG_DAYS = 3;
// A cluster failover can reject an enqueue while the slot map is being
// refreshed. Retry those transient errors so a delivery is never dropped.
const WEBHOOK_ENQUEUE_RETRY_ATTEMPTS = 5;
const WEBHOOK_ENQUEUE_RETRY_BASE_DELAY_MS = 50;

const WEBHOOK_JOB_OPTIONS = Object.freeze({
  attempts: MAX_WEBHOOK_ATTEMPTS,
  backoff: {
    type: 'exponential',
    delay: WEBHOOK_BACKOFF_DELAY_MS,
  },
  removeOnComplete: 1_000,
  removeOnFail: 5_000,
});

let webhookQueue;
let webhookWorker;
let queueConnection;
let workerConnection;

const computeSignature = (secret, rawBody) => {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
};

// Bound signature for the `Stellar-*` headers: the dispatch timestamp is
// cryptographically bound (`timestamp.rawBody`) so the header cannot be
// swapped in transit without invalidating the signature.
const computeBoundSignature = (secret, timestamp, rawBody) => {
  return crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
};

const webhookEventMatches = (webhook, eventName) => {
  const subscriptions = Array.isArray(webhook?.events) ? webhook.events : ['*'];
  const normalized = subscriptions
    .filter((value) => typeof value === 'string')
    .map((value) => value.trim())
    .filter(Boolean);

  if (normalized.length === 0 || normalized.includes('*')) return true;
  return normalized.includes(eventName);
};

const fetchWebhooksForAddress = async (prisma, stellarAddress) => {
  return prisma.webhook.findMany({
    where: {
      user: { address: stellarAddress },
    },
    select: {
      id: true,
      username: true,
      url: true,
      secret: true,
      events: true,
      failingSince: true,
    },
  });
};

const getWebhooksExhaustedRetries = async (prisma) => {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - MAX_RETRY_BACKLOG_DAYS);

  return prisma.webhook.findMany({
    where: {
      failingSince: { not: null, lt: cutoff },
    },
    select: {
      id: true,
      username: true,
      url: true,
      secret: true,
      failingSince: true,
    },
  });
};

const sendWebhook = async (url, payload, secret) => {
  const rawBody = JSON.stringify(payload);
  const signature = computeSignature(secret, rawBody);
  // `Stellar-Timestamp` is the ISO 8601 dispatch timestamp already present
  // in `payload.timestamp`; it is bound into `Stellar-Signature`.
  const timestamp = payload.timestamp;
  const stellarSignature = computeBoundSignature(secret, timestamp, rawBody);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
  try {
    // internalFetch is a pass-through to `fetch` for merchant endpoints on the
  // public internet, and presents this service's client certificate when a
  // webhook points at another internal service.
  const response = await internalFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Primary header per issue #496 spec.
        'X-Webhook-Signature': signature,
        // Legacy alias kept for backward compatibility.
        'X-Stellar-Tags-Signature': signature,
        'X-Webhook-Timestamp': timestamp,
        // Timestamp-bound headers per issue #727 spec.
        'Stellar-Signature': stellarSignature,
        'Stellar-Timestamp': timestamp,
      },
      body: rawBody,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`Webhook responded with HTTP ${response.status}`);
    }
    return { ok: true };
  } finally {
    clearTimeout(timeoutId);
  }
};

const markWebhookSuccess = async (prisma, webhookId, now) => {
  await prisma.webhook.update({
    where: { id: webhookId },
    data: { lastSentAt: now, failingSince: null },
  });
};

const markWebhookFailure = async (prisma, webhookId, now) => {
  const current = await prisma.webhook.findUnique({
    where: { id: webhookId },
    select: { failingSince: true },
  });
  await prisma.webhook.update({
    where: { id: webhookId },
    data: {
      lastSentAt: now,
      failingSince: current?.failingSince || now,
    },
  });
};

const processWebhookJob = async (job, { prisma }) => {
  const { webhook, payload } = job.data;
  const now = new Date();

  try {
    await sendWebhook(webhook.url, payload, webhook.secret);
  } catch (error) {
    try {
      await markWebhookFailure(prisma, webhook.id, now);
    } catch (databaseError) {
      logger.error(
        `[webhook-worker] Failed to mark failure for webhook ${webhook.id}: ${databaseError.message}`,
      );
    }
    throw error;
  }

  try {
    await markWebhookSuccess(prisma, webhook.id, now);
  } catch (databaseError) {
    logger.error(
      `[webhook-worker] Failed to mark success for webhook ${webhook.id}: ${databaseError.message}`,
    );
  }

  logger.info(
    `[webhook-worker] Delivered event=${payload.event_id} webhook=${webhook.id} attempt=${job.attemptsMade + 1}`,
  );
};

const getWebhookQueue = () => {
  if (!webhookQueue) {
    queueConnection = createRedisConnection();
    webhookQueue = new Queue(WEBHOOK_QUEUE_NAME, { connection: queueConnection });
    webhookQueue.on('error', (error) => {
      logger.error(`[webhook-queue] Redis error: ${error.message}`);
    });
  }
  return webhookQueue;
};

const startWebhookWorker = ({ prisma }) => {
  if (webhookWorker) return webhookWorker;

  workerConnection = createRedisConnection();
  webhookWorker = new Worker(
    WEBHOOK_QUEUE_NAME,
    (job) => processWebhookJob(job, { prisma }),
    {
      connection: workerConnection,
      concurrency: WEBHOOK_WORKER_CONCURRENCY,
    },
  );

  webhookWorker.on('failed', async (job, error) => {
    const maxAttempts = job?.opts?.attempts || MAX_WEBHOOK_ATTEMPTS;
    const attemptsMade = job?.attemptsMade || 1;
    
    if (attemptsMade >= maxAttempts && job?.data?.webhook) {
      logger.error(`[webhook-worker] Delivery failed job=${job?.id || 'unknown'}: ${error.message}; retries exhausted (${attemptsMade}/${maxAttempts})`);
      try {
        await moveToDLQ(prisma, job.data.webhook);
      } catch (dlqErr) {
        logger.error(`[webhook-worker] Failed to move webhook ${job.data.webhook.id} to DLQ: ${dlqErr.message}`);
      }
    } else {
      logger.error(`[webhook-worker] Delivery failed job=${job?.id || 'unknown'}: ${error.message}; retry scheduled (${attemptsMade}/${maxAttempts})`);
    }
  });

  webhookWorker.on('error', (error) => {
    logger.error(`[webhook-worker] Redis error: ${error.message}`);
  });

  logger.info(
    `[webhook-worker] Started queue=${WEBHOOK_QUEUE_NAME} concurrency=${WEBHOOK_WORKER_CONCURRENCY}`,
  );
  return webhookWorker;
};

const buildJobId = (webhookId, eventId) => {
  return crypto.createHash('sha256').update(`${webhookId}:${eventId}`).digest('hex');
};

const enqueueWebhookDelivery = async (webhook, payload, queue = getWebhookQueue()) => {
  return withRedisRetry(
    () => queue.add(
      'deliver',
      { webhook, payload },
      {
        ...WEBHOOK_JOB_OPTIONS,
        backoff: { ...WEBHOOK_JOB_OPTIONS.backoff },
        jobId: buildJobId(webhook.id, payload.event_id),
      },
    ),
    {
      attempts: WEBHOOK_ENQUEUE_RETRY_ATTEMPTS,
      baseDelayMs: WEBHOOK_ENQUEUE_RETRY_BASE_DELAY_MS,
      onRetry: (error, attempt) => {
        logger.warn(
          `[webhook-queue] Enqueue for webhook=${webhook.id} failed (${error.message}); retrying after transient Redis error (attempt ${attempt}/${WEBHOOK_ENQUEUE_RETRY_ATTEMPTS})`,
        );
      },
    },
  );
};

const formatAsset = (payment) => {
  if (!payment || payment.asset_type === 'native') return 'native';
  return `${payment.asset_code}:${payment.asset_issuer}`;
};

const dispatchPaymentWebhooks = async ({ prisma, payment, queue }) => {
  if (!payment || (payment.type !== 'payment' && payment.type_i !== 1)) return;

  const recipientAddress = payment.to;
  if (!recipientAddress) return;

  const webhooks = await fetchWebhooksForAddress(prisma, recipientAddress);
  if (!webhooks.length) return;

  const payload = {
    event: 'payment.received',
    event_id: `${payment.transaction_hash || ''}-${payment.id || crypto.randomBytes(8).toString('hex')}`,
    timestamp: new Date().toISOString(),
    network: process.env.HORIZON_NETWORK || 'testnet',
    data: {
      transaction_hash: payment.transaction_hash || null,
      from: payment.from || null,
      to: recipientAddress,
      amount: payment.amount || null,
      asset: formatAsset(payment),
      asset_type: payment.asset_type || 'native',
      asset_code: payment.asset_code || null,
      asset_issuer: payment.asset_issuer || null,
      created_at: payment.created_at || null,
      paging_token: payment.paging_token || null,
      metadata: payment.metadata ?? null,
    },
  };

  const deliveryQueue = queue || getWebhookQueue();
  await Promise.all(webhooks.map(async (webhook) => {
    if (!webhookEventMatches(webhook, payload.event)) {
      logger.info(`[webhook-worker] Skipping webhook id=${webhook.id} url=${webhook.url} for event=${payload.event} due to subscription filter`);
      return;
    }
    await enqueueWebhookDelivery(webhook, payload, deliveryQueue);
    logger.info(
      `[webhook-queue] Enqueued event=${payload.event_id} webhook=${webhook.id} recipient=${recipientAddress}`,
    );
  }));
};

const closeWebhookQueue = async () => {
  const resources = [webhookWorker, webhookQueue].filter(Boolean);
  await Promise.all(resources.map((resource) => resource.close()));

  const connections = [workerConnection, queueConnection].filter(Boolean);
  await Promise.all(connections.map((connection) => connection.quit()));

  webhookWorker = undefined;
  webhookQueue = undefined;
  workerConnection = undefined;
  queueConnection = undefined;
};

// ── Dead Letter Queue (DLQ) ──────────────────────────────────────────────

/**
 * Move a permanently-failed webhook delivery to the dead-letter queue.
 * The webhook row itself is left intact so the user can re-register if needed;
 * only the delivery record is preserved for manual replay.
 */
const moveToDLQ = async (prisma, webhook) => {
  const payload = {
    event: 'webhook.delivery_failed',
    event_id: `dlq-${webhook.id}-${crypto.randomBytes(8).toString('hex')}`,
    timestamp: new Date().toISOString(),
    data: {
      webhook_id: webhook.id,
      webhook_url: webhook.url,
      username: webhook.username,
      failing_since: webhook.failingSince ? (webhook.failingSince instanceof Date
        ? webhook.failingSince
        : new Date(webhook.failingSince)
      ).toISOString() : null,
    },
  };

  const now = new Date();
  await prisma.webhookDLQ.create({
    data: {
      webhookId: webhook.id,
      webhookUrl: webhook.url,
      webhookSecret: webhook.secret,
      username: webhook.username,
      eventType: payload.event,
      eventPayload: JSON.stringify(payload),
      failureReason: `Delivery exhausted after ${MAX_WEBHOOK_ATTEMPTS} attempts`,
      deliveryAttempts: 0,
      movedAt: now,
      replayed: false,
    },
  });

  // Clear failingSince on the webhook so it's not repeatedly moved to DLQ.
  // The webhook stays registered; a new payment will retry fresh.
  await markWebhookSuccess(prisma, webhook.id, now);

  logger.info(
    `[webhook-worker] Moved to DLQ: webhookId=${webhook.id} username=${webhook.username} url=${webhook.url}`,
  );
};

/**
 * List dead-letter-queue entries with optional username filter and pagination.
 */
const listDLQEntries = async (prisma, opts = {}) => {
  const { username, limit = 50, offset = 0 } = opts;
  const where = username
    ? { username: { equals: username, mode: 'insensitive' } }
    : {};

  const [entries, total] = await prisma.$transaction([
    prisma.webhookDLQ.findMany({
      where,
      orderBy: { movedAt: 'desc' },
      skip: offset,
      take: limit,
    }),
    prisma.webhookDLQ.count({ where }),
  ]);

  return { entries, total };
};

/**
 * Replay a single DLQ entry.
 */
const replayFromDLQ = async (prisma, dqlId) => {
  const entry = await prisma.webhookDLQ.findUnique({
    where: { id: dqlId },
  });

  if (!entry) {
    return { ok: false, error: 'DLQ entry not found' };
  }
  if (entry.replayed) {
    return { ok: false, error: 'DLQ entry has already been replayed' };
  }

  const payload = typeof entry.eventPayload === 'string'
    ? JSON.parse(entry.eventPayload)
    : entry.eventPayload;
  const secret = entry.webhookSecret;

  try {
    await sendWebhook(entry.webhookUrl, payload, secret);
    const now = new Date();
    await prisma.webhookDLQ.update({
      where: { id: dqlId },
      data: { replayed: true, replayedAt: now },
    });
    logger.info(`[webhook-worker] DLQ entry ${dqlId} replayed successfully`);
    return { ok: true };
  } catch (err) {
    try {
      await prisma.webhookDLQ.update({
        where: { id: dqlId },
        data: { deliveryAttempts: (entry.deliveryAttempts || 0) + 1 },
      });
    } catch (dbErr) {
      logger.error(`[webhook-worker] Failed to update DLQ attempt count for ${dqlId}: ${dbErr.message}`);
    }
    logger.error(`[webhook-worker] DLQ replay failed for ${dqlId}: ${err.message}`);
    return { ok: false, error: err.message };
  }
};

module.exports = {
  dispatchPaymentWebhooks,
  enqueueWebhookDelivery,
  startWebhookWorker,
  closeWebhookQueue,
  processWebhookJob,
  sendWebhook,
  markWebhookSuccess,
  markWebhookFailure,
  computeSignature,
  computeBoundSignature,
  WEBHOOK_TIMEOUT_MS,
  WEBHOOK_QUEUE_NAME,
  MAX_WEBHOOK_ATTEMPTS,
  WEBHOOK_BACKOFF_DELAY_MS,
  WEBHOOK_JOB_OPTIONS,
  MAX_RETRY_BACKLOG_DAYS,
  WEBHOOK_ENQUEUE_RETRY_ATTEMPTS,
  WEBHOOK_ENQUEUE_RETRY_BASE_DELAY_MS,
  getWebhooksExhaustedRetries,
  moveToDLQ,
  listDLQEntries,
  replayFromDLQ,
};


