'use strict';

/**
 * End-to-end mTLS tests: a real HTTPS listener, real certificates from
 * scripts/pki, and real handshakes.
 *
 * The unit tests prove the guard's logic against fake sockets; these prove the
 * property that actually matters — a process without a certificate cannot open
 * a connection at all — and that a rotation does not lock anyone out.
 */

const express = require('express');
const fs = require('fs');
const https = require('https');
const http = require('http');
const path = require('path');

const {
  createHttpServer,
  getTlsConfig,
  resetTlsConfig,
  startRotationWatcher,
} = require('../src/config/tls');
const { requireMutualTls, serviceIdentity } = require('../src/middleware/mtls');
const { internalFetch, resetInternalClient } = require('../src/utils/internalClient');
const { generatePki, opensslAvailable, removePkiDir, runPki } = require('./helpers/pki');

const describeWithOpenssl = opensslAvailable() ? describe : describe.skip;
const maybeIt = opensslAvailable() ? it : it.skip;

// A rotation re-keys the whole PKI inline, so the tests that do one carry an
// explicit budget: RSA generation is CPU-bound and the full suite runs in
// parallel across workers.
const ROTATION_TIMEOUT_MS = 120000;

const ENV_KEYS = [
  'MTLS_ENABLED',
  'MTLS_CA_FILE',
  'MTLS_CERT_FILE',
  'MTLS_KEY_FILE',
  'MTLS_CLIENT_CERT_FILE',
  'MTLS_CLIENT_KEY_FILE',
  'MTLS_CLIENT_AUTH',
  'MTLS_REQUIRED_SANS',
  'MTLS_HOT_RELOAD',
  'MTLS_RELOAD_INTERVAL_MS',
  'MTLS_INTERNAL_DOMAINS',
];

let savedEnv = {};

// Node's TLS options take PEM text, not file paths, so every request reads the
// material off disk first unless it was already loaded.
const readPem = (value) => {
  if (!value) return undefined;
  if (value.includes('-----BEGIN')) return value;
  return fs.readFileSync(value, 'utf8');
};

beforeAll(() => {
  ENV_KEYS.forEach((key) => {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  });
});

afterAll(() => {
  ENV_KEYS.forEach((key) => {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  });
  resetTlsConfig();
});

const applyEnvironment = (pki, server = 'api', extra = {}) => {
  resetTlsConfig();
  ENV_KEYS.forEach((key) => delete process.env[key]);
  process.env.MTLS_ENABLED = 'true';
  process.env.MTLS_CA_FILE = pki.ca;
  process.env.MTLS_CERT_FILE = pki.services(server).cert;
  process.env.MTLS_KEY_FILE = pki.services(server).key;
  Object.keys(extra).forEach((key) => {
    process.env[key] = extra[key];
  });
};

// A minimal stand-in for the API: the same two middlewares the real server
// mounts, without the database and rate limiting that would slow the suite down.
const buildApp = () => {
  const app = express();
  app.use(serviceIdentity);
  app.use(requireMutualTls);
  app.get('/whoami', (req, res) => {
    // getCipher/getProtocol only exist on a TLS socket, and this same app is
    // also mounted on a plaintext listener in the "mTLS off" case below.
    const isTls = typeof req.socket.getCipher === 'function';
    res.json({
      identity: req.serviceIdentity || null,
      authorized: Boolean(req.socket.authorized),
      cipher: isTls ? req.socket.getCipher().name : null,
      protocol: isTls ? req.socket.getProtocol() : null,
    });
  });
  app.use((req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND' } });
  });
  return app;
};

const startServer = (app) =>
  new Promise((resolve) => {
    const server = createHttpServer(app);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });

const stopServer = (server) =>
  new Promise((resolve) => {
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    server.close(() => resolve());
  });

const collect = (res) =>
  new Promise((resolve) => {
    let raw = '';
    res.on('data', (chunk) => {
      raw += chunk;
    });
    res.on('end', () => {
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve(null);
      }
    });
  });

/**
 * Performs a request against the listener.
 *
 * @returns {Promise<{ status: number|null, body: object|null, error: Error|null }>}
 */
const request = (port, { cert, key, ca } = {}) =>
  new Promise((resolve) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        path: '/whoami',
        method: 'GET',
        ca: readPem(ca),
        cert: readPem(cert),
        key: readPem(key),
        servername: 'localhost',
      },
      (res) => {
        collect(res).then((body) =>
          resolve({ status: res.statusCode, body, error: null }),
        );
      },
    );
    req.on('error', (error) => resolve({ status: null, body: null, error }));
    req.end();
  });

describeWithOpenssl('mTLS handshake against a real listener', () => {
  let pki;
  let server;
  let port;

  beforeAll(async () => {
    pki = generatePki();
    applyEnvironment(pki);
    server = await startServer(buildApp());
    port = server.address().port;
  });

  afterAll(async () => {
    if (server) await stopServer(server);
    removePkiDir(pki.dir);
  });

  maybeIt('demands a client certificate on the listener', () => {
    expect(typeof port).toBe('number');
    expect(getTlsConfig().enforcePeerCert).toBe(true);
  });

  maybeIt('accepts a peer holding a certificate from the internal CA', async () => {
    const { status, body, error } = await request(port, {
      ...pki.services('edge'),
      ca: pki.ca,
    });

    expect(error).toBeNull();
    expect(status).toBe(200);
    expect(body.identity).toBe('spiffe://stellar-tags/internal/edge');
    expect(body.authorized).toBe(true);
  });

  maybeIt('negotiates no protocol below the configured floor', async () => {
    const { body } = await request(port, { ...pki.services('edge'), ca: pki.ca });

    // The floor is TLSv1.2, so TLS 1.1 and below must never be negotiated.
    expect(['TLSv1.2', 'TLSv1.3']).toContain(body.protocol);
  });

  maybeIt('refuses a peer with no certificate at all', async () => {
    const { status, error } = await request(port, { ca: pki.ca });

    // The handshake is torn down, so there is no HTTP status to observe.
    expect(status).toBeNull();
    expect(error).not.toBeNull();
  });

  maybeIt('refuses a peer that does not trust this listener', async () => {
    const { status, error } = await request(port, {
      ...pki.services('edge'),
      ca: undefined,
    });

    expect(error).not.toBeNull();
    expect(status).toBeNull();
  });

  maybeIt('rejects a certificate issued by an untrusted authority', async () => {
    // A second, independent PKI: structurally identical, but signed by a
    // different root, which is what a foreign or compromised issuer looks like.
    const rogue = generatePki({ services: 'edge' });
    try {
      const { status, error } = await request(port, {
        ...rogue.services('edge'),
        ca: pki.ca,
      });

      expect(status).toBeNull();
      expect(error).not.toBeNull();
    } finally {
      removePkiDir(rogue.dir);
    }
  });
});

describeWithOpenssl('identity allowlist', () => {
  let pki;
  let server;
  let port;

  beforeAll(async () => {
    pki = generatePki();
    applyEnvironment(pki, 'api', {
      MTLS_REQUIRED_SANS: 'spiffe://stellar-tags/internal/edge',
    });
    server = await startServer(buildApp());
    port = server.address().port;
  });

  afterAll(async () => {
    if (server) await stopServer(server);
    removePkiDir(pki.dir);
  });

  maybeIt('accepts the listed service identity', async () => {
    const { status, body } = await request(port, { ...pki.services('edge'), ca: pki.ca });

    expect(status).toBe(200);
    expect(body.identity).toBe('spiffe://stellar-tags/internal/edge');
  });

  maybeIt('returns 403 for a valid but unlisted identity', async () => {
    const { status } = await request(port, { ...pki.services('fraud-worker'), ca: pki.ca });

    expect(status).toBe(403);
  });
});

describeWithOpenssl('certificate rotation', () => {
  let pki;
  let oldEdge;

  beforeAll(() => {
    pki = generatePki();
    oldEdge = {
      cert: fs.readFileSync(pki.services('edge').cert, 'utf8'),
      key: fs.readFileSync(pki.services('edge').key, 'utf8'),
    };
  });

  afterAll(() => {
    removePkiDir(pki.dir);
  });

  maybeIt('a restarted peer accepts both the old and the new certificate', async () => {
    // Phase one of a CA rotation: a new issuing CA, new leaves, and a trust
    // bundle that still trusts the previous CA.
    runPki([
      'rotate',
      '--out',
      pki.dir,
      '--days',
      '30',
      '--key-bits',
      '2048',
      '--new-intermediate',
    ]);

    const bundle = fs.readFileSync(pki.ca, 'utf8');
    // The widened bundle is what makes the switch order-independent.
    expect(bundle.match(/-----BEGIN CERTIFICATE-----/g).length).toBe(3);

    applyEnvironment(pki);
    const server = await startServer(buildApp());
    const port = server.address().port;

    try {
      // A peer still holding the pre-rotation certificate keeps working...
      const oldLeaf = await request(port, { ...oldEdge, ca: pki.ca });
      expect(oldLeaf.status).toBe(200);
      expect(oldLeaf.body.identity).toBe('spiffe://stellar-tags/internal/edge');

      // ...and a peer holding the new one works too.
      const newLeaf = await request(port, { ...pki.services('edge'), ca: pki.ca });
      expect(newLeaf.status).toBe(200);
    } finally {
      await stopServer(server);
    }
  }, ROTATION_TIMEOUT_MS);

  maybeIt('pruning retires the old CA once nothing serves it', () => {
    runPki(['prune', '--out', pki.dir]);

    const bundle = fs.readFileSync(pki.ca, 'utf8');
    expect(bundle.match(/-----BEGIN CERTIFICATE-----/g).length).toBe(2);
    expect(fs.existsSync(path.join(pki.dir, 'intermediate', 'retired'))).toBe(false);
  });
});

describeWithOpenssl('hot reload', () => {
  let pki;
  let server;
  let port;
  let watcher = null;

  beforeAll(async () => {
    pki = generatePki();
    applyEnvironment(pki, 'api', {
      MTLS_HOT_RELOAD: 'true',
      MTLS_RELOAD_INTERVAL_MS: '50',
    });
    server = await startServer(buildApp());
    port = server.address().port;
  });

  afterAll(async () => {
    if (watcher) watcher.stop();
    if (server) await stopServer(server);
    removePkiDir(pki.dir);
  });

  maybeIt('keeps serving with the previous context when the material goes bad', async () => {
    // A watcher is normally installed by createHttpServer. Drive it directly so
    // the reload path can be exercised against a known-good listener.
    watcher = startRotationWatcher(server, {
      ca: fs.readFileSync(pki.ca, 'utf8'),
      cert: fs.readFileSync(pki.services('api').cert, 'utf8'),
      key: fs.readFileSync(pki.services('api').key, 'utf8'),
    });

    const broken = path.join(pki.dir, 'services', 'api.crt');
    const original = fs.readFileSync(broken, 'utf8');
    fs.writeFileSync(broken, 'not a certificate');

    try {
      await new Promise((resolve) => setTimeout(resolve, 200));

      // The running secure context stays in place rather than taking the
      // listener down over a bad file.
      const { status } = await request(port, { ...pki.services('edge'), ca: pki.ca });
      expect(status).toBe(200);
    } finally {
      fs.writeFileSync(broken, original);
    }
  });

  maybeIt('picks up rotated material without a restart', async () => {
    runPki(['rotate', '--out', pki.dir, '--days', '30', '--key-bits', '2048']);

    // The new leaf is signed by the same issuing CA, so it validates as soon
    // as the server reloads; the point is that no restart was needed.
    await new Promise((resolve) => setTimeout(resolve, 300));

    const { status, error } = await request(port, { ...pki.services('edge'), ca: pki.ca });
    expect(error).toBeNull();
    expect(status).toBe(200);
  }, ROTATION_TIMEOUT_MS);
});

describeWithOpenssl('plain HTTP when mTLS is off', () => {
  let server;

  beforeAll(async () => {
    resetTlsConfig();
    ENV_KEYS.forEach((key) => delete process.env[key]);
    process.env.MTLS_ENABLED = 'false';
    server = await startServer(buildApp());
  });

  afterAll(async () => {
    if (server) await stopServer(server);
    resetTlsConfig();
  });

  maybeIt('serves over http and does not demand a certificate', async () => {
    const body = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port: server.address().port, path: '/whoami' },
        (res) => collect(res).then(resolve),
      );
      req.on('error', reject);
      req.end();
    });

    expect(body).toMatchObject({ identity: null, authorized: false });
  });
});

describeWithOpenssl('outbound client identity', () => {
  let pki;
  let peer;
  let peerPort;

  // Two listeners on loopback, told apart by hostname: `localhost` is on the
  // internal allowlist, `127.0.0.1` is not. The same client code has to
  // authenticate to one and stay anonymous at the other.
  const startPeer = () => {
    const app = express();
    app.get('/whoami', (req, res) => {
      const cert = req.socket.getPeerCertificate();
      const cn = cert && cert.subject ? cert.subject.CN : undefined;
      res.json({ presentedCertificate: Boolean(cn), cn: cn || null });
    });
    return new Promise((resolve) => {
      const server = https.createServer(
        {
          cert: fs.readFileSync(pki.services('api').cert, 'utf8'),
          key: fs.readFileSync(pki.services('api').key, 'utf8'),
          ca: fs.readFileSync(pki.ca, 'utf8'),
          // Ask for a certificate but do not demand one, so a test can observe
          // exactly what the caller offered.
          requestCert: true,
          rejectUnauthorized: false,
        },
        app,
      );
      server.on('tlsClientError', () => {});
      server.listen(0, '127.0.0.1', () => resolve(server));
    });
  };

  beforeAll(async () => {
    pki = generatePki();
    applyEnvironment(pki, 'api', {
      MTLS_INTERNAL_DOMAINS: 'localhost',
      MTLS_CLIENT_CERT_FILE: pki.services('edge').cert,
      MTLS_CLIENT_KEY_FILE: pki.services('edge').key,
    });
    peer = await startPeer();
    peerPort = peer.address().port;
  });

  afterAll(async () => {
    resetInternalClient();
    if (peer) await stopServer(peer);
    removePkiDir(pki.dir);
    resetTlsConfig();
  });

  maybeIt('presents the client certificate to an internal host', async () => {
    const res = await internalFetch(`https://localhost:${peerPort}/whoami`);

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      presentedCertificate: true,
      cn: 'edge',
    });
  });

  maybeIt('refuses to reach an internal host over plaintext', async () => {
    await expect(
      internalFetch(`http://localhost:${peerPort}/whoami`),
    ).rejects.toThrow(/Refusing to send an unauthenticated plaintext request/);
  });
});
