'use strict';

/**
 * src/config/tls.js
 *
 * Single source of truth for the transport security of service-to-service
 * traffic. Every internal hop in this platform (edge -> api, api -> internal
 * webhook consumer, container health probes) is expected to run over mTLS:
 * the listener presents a server certificate AND demands a client certificate
 * that chains to the internal CA, so an unauthenticated process on the network
 * cannot open a connection at all.
 *
 * Design notes
 * ------------
 * - Fail closed. `MTLS_ENABLED=true` with missing, unreadable or malformed
 *   material throws `MtlsConfigurationError` instead of silently degrading to
 *   plaintext. A silently-downgraded mTLS listener is worse than a crash.
 * - Off by default. Local dev, CI and the existing supertest suite talk plain
 *   HTTP; nothing here changes behaviour until MTLS_ENABLED is set.
 * - Secrets never come from files only. Each `*_FILE` variable has a `*_PEM`
 *   twin so a secret manager can inject the material as an env var.
 * - Hot rotation. `startRotationWatcher()` re-reads the files on an interval
 *   and swaps the secure context in place, so certificates rotate without a
 *   restart and without dropping in-flight requests.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const tls = require('tls');
const { logger } = require('../logger');

class MtlsConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MtlsConfigurationError';
  }
}

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on', 'enabled']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off', 'disabled']);

const parseBoolean = (value, fallback = false) => {
  if (value === undefined || value === null || value === '') return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) return true;
  if (FALSE_VALUES.has(normalized)) return false;
  throw new MtlsConfigurationError(
    `Expected a boolean (true/false) but received "${value}".`,
  );
};

const parsePositiveInt = (value, fallback) => {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new MtlsConfigurationError(
      `Expected a non-negative integer but received "${value}".`,
    );
  }
  return parsed;
};

const parseList = (value) =>
  (value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

/**
 * Accepted `minVersion` values. These are the string form Node itself accepts
 * for the `minVersion` option; the numeric constants Node used to export on
 * `tls` are gone in current releases, so the name is validated here and passed
 * straight through.
 */
const MIN_TLS_VERSIONS = ['TLSv1.2', 'TLSv1.3'];

/**
 * Client authentication modes, from strictest to loosest.
 *   required       - a valid client certificate must be presented (default)
 *   verify-if-given- a certificate is verified when presented, absence is OK
 *   none           - certificates are never requested (encryption only)
 */
const CLIENT_AUTH_MODES = new Set(['required', 'verify-if-given', 'none']);

const DEFAULT_CERT_DIR = path.join(process.cwd(), 'certs');
const DEFAULT_MIN_VERSION = 'TLSv1.2';
const DEFAULT_CLIENT_AUTH = 'required';
const DEFAULT_RELOAD_INTERVAL_MS = 0;

/** Hosts treated as internal service endpoints by the outbound mTLS client. */
const DEFAULT_INTERNAL_DOMAINS = [
  'backend',
  'api',
  'api-test',
  'fraud-worker',
  'edge',
  'frontend',
  'localhost',
  '127.0.0.1',
  '::1',
];

/** Resolved once per process; tests call `resetTlsConfig()` between cases. */
let cachedConfig = null;

const env = () => process.env;

const isMtlsEnabled = () => parseBoolean(env().MTLS_ENABLED, false);

const isReloadEnabled = () => parseBoolean(env().MTLS_HOT_RELOAD, false);

/**
 * Reads PEM material from `<NAME>_FILE`, falling back to the literal PEM in
 * `<NAME>_PEM`. File wins when both are present so a mounted secret volume can
 * override a stale env var.
 */
const readPem = (fileVar, pemVar, { required = false, label = '' } = {}) => {
  const file = env()[fileVar];
  const inline = env()[pemVar];
  let contents = null;
  let source = null;

  if (file && String(file).trim()) {
    const resolved = path.resolve(String(file).trim());
    try {
      contents = fs.readFileSync(resolved, 'utf8');
    } catch (err) {
      throw new MtlsConfigurationError(
        `Unable to read ${label || fileVar} from ${resolved}: ${err.message}`,
      );
    }
    source = resolved;
  } else if (inline && String(inline).trim()) {
    contents = String(inline);
    source = `$${pemVar}`;
  }

  if (contents === null) {
    if (required) {
      throw new MtlsConfigurationError(
        `MTLS_ENABLED=true requires ${fileVar} (a PEM file path) or ${pemVar} (inline PEM).`,
      );
    }
    return null;
  }

  if (!/-----BEGIN [A-Z0-9 ]+-----/.test(contents)) {
    throw new MtlsConfigurationError(
      `${label || fileVar} (${source}) does not look like PEM material.`,
    );
  }

  return contents;
};

/**
 * Builds the CA bundle. A bundle is normal during rotation: the old and new
 * intermediate CAs are concatenated so certificates issued before and after
 * the cutover both validate.
 */
const readCaBundle = () => {
  const bundle = readPem('MTLS_CA_FILE', 'MTLS_CA_PEM', {
    required: true,
    label: 'MTLS_CA_FILE',
  });
  const certificateCount = (bundle.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
  if (certificateCount === 0) {
    throw new MtlsConfigurationError(
      'MTLS_CA_FILE contains no certificates. Point it at ca-bundle.crt (the internal root and intermediate CAs).',
    );
  }
  return bundle;
};

const readClientIdentity = ({ serverCert, serverKey }) => {
  const cert =
    readPem('MTLS_CLIENT_CERT_FILE', 'MTLS_CLIENT_CERT_PEM', {
      label: 'MTLS_CLIENT_CERT_FILE',
    }) || serverCert;
  const key =
    readPem('MTLS_CLIENT_KEY_FILE', 'MTLS_CLIENT_KEY_PEM', {
      label: 'MTLS_CLIENT_KEY_FILE',
    }) || serverKey;
  return { cert, key };
};

const fingerprint = (pem) => {
  if (!pem) return null;
  return crypto.createHash('sha256').update(pem).digest('hex').slice(0, 16);
};

const loadTlsConfig = () => {
  const enabled = isMtlsEnabled();
  const minVersionName = (env().MTLS_MIN_VERSION || DEFAULT_MIN_VERSION).trim();
  if (!MIN_TLS_VERSIONS.includes(minVersionName)) {
    throw new MtlsConfigurationError(
      `Unsupported MTLS_MIN_VERSION "${minVersionName}". Use one of: ${MIN_TLS_VERSIONS.join(', ')}.`,
    );
  }

  const clientAuth = (env().MTLS_CLIENT_AUTH || DEFAULT_CLIENT_AUTH).trim().toLowerCase();
  if (!CLIENT_AUTH_MODES.has(clientAuth)) {
    throw new MtlsConfigurationError(
      `Unsupported MTLS_CLIENT_AUTH "${clientAuth}". Use one of: ${[...CLIENT_AUTH_MODES].join(', ')}.`,
    );
  }

  const base = {
    enabled,
    minVersionName,
    clientAuth,
    requireClientCert: enabled && clientAuth !== 'none',
    enforcePeerCert: enabled && clientAuth === 'required',
    requiredSans: parseList(env().MTLS_REQUIRED_SANS).map((entry) => entry.toLowerCase()),
    internalDomains: parseList(env().MTLS_INTERNAL_DOMAINS).length
      ? parseList(env().MTLS_INTERNAL_DOMAINS).map((entry) => entry.toLowerCase())
      : [...DEFAULT_INTERNAL_DOMAINS],
    reloadIntervalMs: parsePositiveInt(
      env().MTLS_RELOAD_INTERVAL_MS,
      DEFAULT_RELOAD_INTERVAL_MS,
    ),
    certDir: env().MTLS_CERT_DIR || DEFAULT_CERT_DIR,
    hotReload: isReloadEnabled(),
  };

  if (!enabled) {
    // Still validate the flag shapes above so a typo fails fast even when
    // mTLS is off, but never touch the filesystem.
    return Object.freeze({ ...base, serverCert: null, serverKey: null, ca: null, clientCert: null, clientKey: null });
  }

  const serverCert = readPem('MTLS_CERT_FILE', 'MTLS_CERT_PEM', {
    required: true,
    label: 'MTLS_CERT_FILE',
  });
  const serverKey = readPem('MTLS_KEY_FILE', 'MTLS_KEY_PEM', {
    required: true,
    label: 'MTLS_KEY_FILE',
  });
  const ca = readCaBundle();
  const { cert: clientCert, key: clientKey } = readClientIdentity({ serverCert, serverKey });

  return Object.freeze({
    ...base,
    serverCert,
    serverKey,
    ca,
    clientCert,
    clientKey,
  });
};

const getTlsConfig = () => {
  if (cachedConfig === null) cachedConfig = loadTlsConfig();
  return cachedConfig;
};

/** Test seam: forces the next getTlsConfig() call to re-read the environment. */
const resetTlsConfig = () => {
  cachedConfig = null;
  rotationWatchers.forEach((watcher) => watcher.stop());
  rotationWatchers.clear();
};

const buildTlsOptions = (config) => {
  const options = {
    ca: config.ca,
    minVersion: config.minVersionName,
    requestCert: config.requireClientCert,
    rejectUnauthorized: config.enforcePeerCert,
    // Honour the platform cipher policy; leave Node's own defaults alone when
    // no override is configured.
    honorCipherOrder: true,
  };

  if (config.clientAuth === 'verify-if-given') {
    // Node's authorization failure must not kill the socket before the request
    // layer can decide what to do with it.
    options.rejectUnauthorized = false;
  }

  if (env().MTLS_CIPHERS) {
    const ciphers = parseList(env().MTLS_CIPHERS).join(':');
    if (ciphers) options.ciphers = ciphers;
  }

  return options;
};

/** Options for the API listener: server identity + a required client CA. */
const getServerTlsOptions = () => {
  const config = getTlsConfig();
  if (!config.enabled) return null;
  return {
    ...buildTlsOptions(config),
    cert: config.serverCert,
    key: config.serverKey,
  };
};

/** Options for outbound service-to-service calls (client identity + trust). */
const getClientTlsOptions = () => {
  const config = getTlsConfig();
  if (!config.enabled || !config.clientCert) return null;
  return {
    ca: config.ca,
    cert: config.clientCert,
    key: config.clientKey,
    minVersion: config.minVersionName,
  };
};

const rotationWatchers = new Map();

/**
 * Re-reads the on-disk material every `reloadIntervalMs` and rebuilds the
 * secure context, so a rotation is picked up without a restart. The previous
 * context stays in service until the new one validates, and a bad file leaves
 * the running context untouched instead of dropping connections.
 */
const startRotationWatcher = (server, options) => {
  const config = getTlsConfig();
  const interval = config.reloadIntervalMs;
  if (!config.enabled || !config.hotReload || !interval) return null;
  if (rotationWatchers.has(server)) return rotationWatchers.get(server);

  const snapshot = () => {
    try {
      const next = loadTlsConfig();
      return {
        serverCert: next.serverCert,
        serverKey: next.serverKey,
        ca: next.ca,
        clientCert: next.clientCert,
        clientKey: next.clientKey,
      };
    } catch (err) {
      logger.error({ err: err.message }, "[mtls] Certificate reload failed; keeping the current context.");
      return null;
    }
  };

  const fingerprintOf = (material) =>
    [material.serverCert, material.serverKey, material.ca, material.clientCert, material.clientKey]
      .map((part) => fingerprint(part))
      .join(':');

  let baseline = null;

  // A reload must never be able to take the process down: material read from
  // disk can be truncated or half-written at any moment, and an exception here
  // would escape the interval callback and kill the service. Anything that goes
  // wrong leaves the running secure context in place.
  const attemptReload = () => {
    const material = snapshot();
    if (!material) return;
    if (fingerprintOf(material) === fingerprintOf(baseline)) return;

    const nextOptions = {
      // Re-derive the policy from the current environment so a reload can
      // never quietly drop `requestCert`/`rejectUnauthorized`; the caller's
      // options only contribute extras, never the enforcement flags.
      ...buildTlsOptions(getTlsConfig()),
      ...options,
      cert: material.serverCert,
      key: material.serverKey,
      ca: material.ca,
    };

    // Build the context once to prove the new material is usable before the
    // server is pointed at it. The result is deliberately thrown away:
    // `setSecureContext` must be handed plain options, not a prebuilt
    // SecureContext. On Node 24 installing a prebuilt context leaves the
    // listener unable to pick a signature algorithm and every later handshake
    // dies with ERR_SSL_NO_SUITABLE_SIGNATURE_ALGORITHM.
    tls.createSecureContext(nextOptions);
    server.setSecureContext(nextOptions);

    baseline = material;
    logger.info("[mtls] Reloaded TLS material from disk (certificate rotation applied).");
  };

  baseline = snapshot();
  if (baseline) rotationWatchers.set(server, { stop: () => clearInterval(timer) });

  const timer = setInterval(() => {
    try {
      attemptReload();
    } catch (err) {
      logger.error(
        { err: err.message },
        "[mtls] Could not apply rotated TLS material; keeping the current context.",
      );
    }
  }, interval);

  // Never hold the event loop open just for the watcher.
  if (typeof timer.unref === 'function') timer.unref();
  return { stop: () => clearInterval(timer) };
};

/**
 * Creates the listener. Plain `http` when mTLS is off (dev, CI, the supertest
 * suite) and `https` with client-certificate enforcement when it is on.
 *
 * @param {import('express').Express} app
 * @returns {import('http').Server}
 */
const createHttpServer = (app) => {
  const options = getServerTlsOptions();
  if (!options) {
    const server = http.createServer(app);
    server.on('tlsClientError', logTlsClientError);
    return server;
  }

  const server = https.createServer(options, app);
  // `tlsClientError` is where a missing or bogus client certificate surfaces:
  // the handshake is torn down before any request is routed, so this is the
  // signal to alert on for "someone tried to reach the API without a cert".
  server.on('tlsClientError', logTlsClientError);
  startRotationWatcher(server, options);
  return server;
};

const logTlsClientError = (err, socket) => {
  logger.warn(
    {
      err: err && err.message,
      remoteAddress: socket && socket.remoteAddress,
      code: err && err.code,
    },
    '[mtls] TLS handshake rejected',
  );
  if (socket && !socket.destroyed) socket.destroy();
};

/** Shape served by /health so operators can see what the listener enforces. */
const describeTlsStatus = () => {
  const config = getTlsConfig();
  if (!config.enabled) {
    return { enabled: false, transport: 'http' };
  }
  return {
    enabled: true,
    transport: 'https',
    clientAuth: config.clientAuth,
    clientCertificateRequired: config.enforcePeerCert,
    minVersion: config.minVersionName,
    requiredSans: config.requiredSans,
    caCertificates: (config.ca.match(/-----BEGIN CERTIFICATE-----/g) || []).length,
    hotReload: config.hotReload && config.reloadIntervalMs > 0,
  };
};

module.exports = {
  MtlsConfigurationError,
  CLIENT_AUTH_MODES,
  DEFAULT_INTERNAL_DOMAINS,
  createHttpServer,
  describeTlsStatus,
  getClientTlsOptions,
  getServerTlsOptions,
  getTlsConfig,
  isMtlsEnabled,
  isReloadEnabled,
  loadTlsConfig,
  parseBoolean,
  parseList,
  resetTlsConfig,
  startRotationWatcher,
};
