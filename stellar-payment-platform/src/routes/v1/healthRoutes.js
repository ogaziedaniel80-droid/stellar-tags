'use strict';

const express = require('express');
const { prisma } = require('../../../prismaClient');
const { logger } = require('../../logger');
const { HORIZON_BASE } = require('../../services/stellarService');
const { internalFetch } = require('../../utils/internalClient');
const { describeTlsStatus } = require('../../config/tls');

const HORIZON_TIMEOUT_MS = parseInt(process.env.HEALTH_HORIZON_TIMEOUT_MS, 10) || 3000;

async function pingHorizon() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HORIZON_TIMEOUT_MS);
  try {
    // Routed through internalFetch so a Horizon mirror running on the internal
    // network is reached over mTLS; the public Horizon endpoint is untouched.
    const res = await internalFetch(HORIZON_BASE, { signal: controller.signal });
    if (!res.ok) throw new Error(`Horizon responded with ${res.status}`);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = (redisClient) => {
  const router = express.Router();

  router.get('/health', async (req, res) => {
    const checks = { database: null, redis: null, horizon: null };
    const failures = [];

    const check = async (key, label, probe) => {
      try {
        await probe();
        checks[key] = 'up';
      } catch (err) {
        checks[key] = 'down';
        failures.push(`${label} unavailable`);
        logger.error(err, `[Correlation ID: ${req.correlationId}] ${label} health check failed`);
      }
    };

    if (!redisClient) checks.redis = 'not configured';

    await Promise.all([
      check('database', 'Database', () => prisma.$queryRaw`SELECT 1`),
      ...(redisClient ? [check('redis', 'Redis', () => redisClient.ping())] : []),
      check('horizon', 'Horizon', pingHorizon),
    ]);

    const response = {
      status: failures.length ? 'DOWN' : 'UP',
      timestamp: new Date().toISOString(),
      // Surfaced so a health check can assert the listener is actually
      // encrypted and demanding client certificates, not just alive.
      tls: describeTlsStatus(),
      ...checks,
    };

    if (failures.length) {
      response.message = failures.join(', ');
      return res.status(503).json(response);
    }

    return res.status(200).json(response);
  });

  return router;
};
