'use strict';

/**
 * src/utils/internalClient.js
 *
 * Outbound half of the internal mTLS story.
 *
 * Service-to-service calls go through `internalFetch`, which presents this
 * process's client certificate to any destination on the internal allowlist
 * (MTLS_INTERNAL_DOMAINS). Three properties matter:
 *
 * - Internal hops are encrypted and mutually authenticated once mTLS is on; a
 *   plain `fetch` to `http://backend:5000` is impossible by construction.
 * - The certificate is scoped to the internal allowlist. External calls
 *   (merchant webhooks, public Stellar infrastructure) are plain `fetch`
 *   calls, so the internal identity never leaves the mesh.
 * - When mTLS is off, `internalFetch` is exactly `fetch`.
 *
 * The internal path uses `https.request` rather than `fetch` with a
 * `dispatcher`: global `fetch` is backed by a bundled undici whose dispatcher
 * protocol rejects both `https.Agent` and a separately installed undici
 * (`UND_ERR_INVALID_ARG`), while `https.Agent` natively understands
 * `ca`/`cert`/`key` and is what we need anyway.
 */

const https = require('https');
const { logger } = require('../logger');
const { getClientTlsOptions, getTlsConfig } = require('../config/tls');

let cachedAgent = null;
let cachedAgentFingerprint = null;

const optionsFingerprint = (options) => JSON.stringify(options || null);

const isInternalHost = (hostname, internalDomains) => {
  if (!hostname) return false;
  const host = String(hostname).toLowerCase().replace(/^\[|\]$/g, '');
  if (internalDomains.includes(host)) return true;
  // Match on a label boundary so `backend.internal` matches a `backend` entry
  // but `notbackend` never does.
  return internalDomains.some(
    (domain) => host === domain || host.endsWith(`.${domain}`),
  );
};

/**
 * Lazily builds (and reuses) the keep-alive https.Agent that carries the
 * client certificate, so connections are pooled and rotated material is picked
 * up by rebuilding the agent when the certificate on disk changes.
 */
const getMtlsAgent = () => {
  const options = getClientTlsOptions();
  if (!options) return null;

  const fingerprint = optionsFingerprint(options);
  if (cachedAgent && cachedAgentFingerprint === fingerprint) return cachedAgent;

  if (cachedAgent) cachedAgent.destroy();
  cachedAgent = new https.Agent({
    ...options,
    keepAlive: true,
    maxSockets: parseInt(process.env.MTLS_MAX_SOCKETS, 10) || 64,
  });
  cachedAgentFingerprint = fingerprint;
  return cachedAgent;
};

/** Test seam: drops the memoized agent so a new environment takes effect. */
const resetInternalClient = () => {
  if (cachedAgent) cachedAgent.destroy();
  cachedAgent = null;
  cachedAgentFingerprint = null;
};

/**
 * Minimal `Response` stand-in for the internal path. Call sites only need the
 * status line and the body, so buffering the (small) internal response is
 * cheaper and simpler than streaming.
 */
const toResponseLike = (res, body) => ({
  ok: res.statusCode >= 200 && res.statusCode < 300,
  status: res.statusCode,
  statusText: res.statusMessage || '',
  headers: {
    get: (name) => res.headers[String(name).toLowerCase()] ?? null,
  },
  async text() {
    return body.toString('utf8');
  },
  async json() {
    return JSON.parse(body.toString('utf8'));
  },
  async arrayBuffer() {
    return body.buffer.slice(
      body.byteOffset,
      body.byteOffset + body.byteLength,
    );
  },
});

/** Performs the mTLS call itself, rejecting on any transport or HTTP failure. */
const internalRequest = (url, options, agent) =>
  new Promise((resolve, reject) => {
    // Mirrors `fetch` semantics for an aborted caller (the health probe and the
    // webhook worker both hand us an AbortSignal): nothing is sent, and an
    // already-aborted signal never opens a socket.
    const abortError = () =>
      (options.signal && options.signal.reason) ||
      new Error('The operation was aborted');

    if (options.signal && options.signal.aborted) {
      reject(abortError());
      return;
    }

    const req = https.request(
      url,
      {
        method: options.method || 'GET',
        headers: options.headers,
        agent,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve(toResponseLike(res, Buffer.concat(chunks))),
        );
        res.on('error', reject);
      },
    );

    if (options.signal) {
      const onAbort = () => {
        req.destroy();
        reject(abortError());
      };
      options.signal.addEventListener('abort', onAbort, { once: true });
      req.on('close', () =>
        options.signal.removeEventListener('abort', onAbort),
      );
    }

    req.on('error', reject);
    if (options.body !== undefined && options.body !== null) {
      req.write(options.body);
    }
    req.end();
  });

/**
 * `fetch` with automatic mTLS for internal destinations.
 *
 * @param {string|URL} url
 * @param {RequestInit & { dispatcher?: unknown }} [options]
 * @returns {Promise<Response>}
 */
const internalFetch = (url, options = {}) => {
  let parsed;
  try {
    parsed = url instanceof URL ? url : new URL(String(url));
  } catch {
    // Not a URL we can reason about: let fetch produce its own error.
    return fetch(url, options);
  }

  const config = getTlsConfig();
  if (!config.enabled) return fetch(url, options);

  // The certificate must never be offered to a host outside the mesh.
  if (!isInternalHost(parsed.hostname, config.internalDomains)) {
    return fetch(url, options);
  }

  // An internal destination reached over plaintext would silently bypass the
  // whole point, so refuse it loudly instead of sending the request.
  if (parsed.protocol !== 'https:') {
    logger.error(
      { host: parsed.hostname, path: parsed.pathname },
      '[mtls] Refusing plaintext request to an internal service',
    );
    return Promise.reject(
      new Error(
        `Refusing to send an unauthenticated plaintext request to internal host "${parsed.hostname}". Use https:// or set MTLS_INTERNAL_DOMAINS appropriately.`,
      ),
    );
  }

  const agent = getMtlsAgent();
  if (!agent) {
    logger.error(
      { host: parsed.hostname },
      '[mtls] No client certificate available for an internal request',
    );
    return Promise.reject(
      new Error(
        `Cannot call internal host "${parsed.hostname}" without a client certificate.`,
      ),
    );
  }

  return internalRequest(url, options, agent);
};

/** True when a URL is an internal service endpoint covered by the mTLS client. */
const isInternalUrl = (url) => {
  try {
    const parsed = url instanceof URL ? url : new URL(String(url));
    return isInternalHost(parsed.hostname, getTlsConfig().internalDomains);
  } catch {
    return false;
  }
};

module.exports = {
  getMtlsAgent,
  internalFetch,
  isInternalHost,
  isInternalUrl,
  resetInternalClient,
};
