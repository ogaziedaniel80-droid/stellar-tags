'use strict';

/**
 * scripts/healthcheck.js
 *
 * Container health probe for the API.
 *
 * A `wget` against http://127.0.0.1:PORT/health stops working the moment the
 * listener is moved behind mTLS, because the handshake is refused before any
 * HTTP status exists. This probe speaks whichever transport the service is
 * actually configured for, so the same command works in both modes:
 *
 *   MTLS_ENABLED unset/false -> http://127.0.0.1:$PORT/health
 *   MTLS_ENABLED=true        -> https://127.0.0.1:$PORT/health, presenting the
 *                               healthcheck client certificate
 *
 * Exit code 0 means healthy, 1 means not. Never throws: a health check that
 * crashes the container is a health check that lies.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const TRUTHY = new Set(['1', 'true', 'yes', 'on', 'enabled']);
const mtlsEnabled = TRUTHY.has(
  String(process.env.MTLS_ENABLED || '').trim().toLowerCase(),
);

const port = process.env.PORT || '5000';
const certDir = process.env.MTLS_CERT_DIR || path.join(process.cwd(), 'certs');
const timeoutMs = Number.parseInt(process.env.HEALTHCHECK_TIMEOUT_MS, 10) || 5000;

const readIfPresent = (file) => {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
};

const firstAvailable = (candidates) => candidates.find((file) => readIfPresent(file));

const buildRequestOptions = () => {
  if (!mtlsEnabled) {
    return {
      module: http,
      options: {
        host: '127.0.0.1',
        port,
        path: process.env.HEALTHCHECK_PATH || '/health',
        method: 'GET',
        timeout: timeoutMs,
      },
    };
  }

  // Prefer an explicit healthcheck identity, then the dedicated leaf issued by
  // `pki.sh init`, then this service's own certificate.
  const cert = firstAvailable([
    process.env.MTLS_HEALTHCHECK_CERT_FILE,
    path.join(certDir, 'services', 'healthcheck.crt'),
    process.env.MTLS_CLIENT_CERT_FILE,
    process.env.MTLS_CERT_FILE,
  ]);
  const key = firstAvailable([
    process.env.MTLS_HEALTHCHECK_KEY_FILE,
    path.join(certDir, 'services', 'healthcheck.key'),
    process.env.MTLS_CLIENT_KEY_FILE,
    process.env.MTLS_KEY_FILE,
  ]);
  const ca = firstAvailable([
    process.env.MTLS_CA_FILE,
    path.join(certDir, 'ca-bundle.crt'),
  ]);

  if (!cert || !key || !ca) {
    throw new Error(
      'MTLS_ENABLED=true but no healthcheck certificate material was found. Run `npm run pki:init` or mount the generated certs directory.',
    );
  }

  return {
    module: https,
    options: {
      host: '127.0.0.1',
      port,
      path: process.env.HEALTHCHECK_PATH || '/health',
      method: 'GET',
      timeout: timeoutMs,
      ca,
      cert,
      key,
      // The certificate covers IP:127.0.0.1; disabling name checking is not
      // needed for an IP SAN, so leave Node's verification on.
      servername: 'localhost',
    },
  };
};

const main = () =>
  new Promise((resolve) => {
    let request;
    try {
      const { module: transport, options } = buildRequestOptions();
      request = transport.request(options, (res) => {
        res.resume();
        resolve(res.statusCode >= 200 && res.statusCode < 400 ? 0 : 1);
      });
    } catch (err) {
      process.stderr.write(`healthcheck: ${err.message}\n`);
      resolve(1);
      return;
    }

    request.on('timeout', () => {
      request.destroy(new Error('timed out'));
    });
    request.on('error', (err) => {
      process.stderr.write(`healthcheck: ${err.message}\n`);
      resolve(1);
    });
    request.end();
  });

main().then((code) => process.exit(code));
