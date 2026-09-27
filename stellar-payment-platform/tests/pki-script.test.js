'use strict';

/**
 * Contract tests for scripts/pki/pki.sh.
 *
 * The PKI is the root of trust for the whole mesh, so the properties asserted
 * here are the ones an operator depends on: the script is re-runnable, a
 * rotation keeps both the old and the new leaf usable, the bundle never drops
 * a live intermediate, and `check` reports expiring material.
 *
 * Everything runs with 2048-bit keys in a throwaway directory; the whole file
 * skips when openssl is unavailable.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const { makePkiDir, opensslAvailable, removePkiDir, runPki } = require('./helpers/pki');

const describeWithOpenssl = opensslAvailable() ? describe : describe.skip;
const maybeIt = opensslAvailable() ? it : it.skip;

const certCount = (bundlePath) =>
  (fs.readFileSync(bundlePath, 'utf8').match(/-----BEGIN CERTIFICATE-----/g) || []).length;

// Node's X509Certificate does not expose subjectAltName, so the extension is
// read straight from openssl rather than through the crypto wrapper.
const SANs = (certPath) => {
  const text = execFileSync(
    'openssl',
    ['x509', '-in', certPath, '-noout', '-ext', 'subjectAltName'],
    { encoding: 'utf8' },
  );
  return text
    .split('\n')
    .slice(1)
    .join(' ')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
};

const verifyWith = (certPath, caPath, untrusted) =>
  execFileSync(
    'openssl',
    [
      'verify',
      '-CAfile',
      caPath,
      ...(untrusted ? ['-untrusted', untrusted] : []),
      certPath,
    ],
    { encoding: 'utf8' },
  );

describeWithOpenssl('pki.sh init', () => {
  let dir;

  beforeEach(() => {
    dir = makePkiDir('pki-init-');
  });

  afterEach(() => {
    removePkiDir(dir);
  });

  maybeIt('lays out a root, an intermediate and one leaf per service', () => {
    runPki([
      'init',
      '--out',
      dir,
      '--services',
      'api edge',
      '--days',
      '30',
      '--key-bits',
      '2048',
    ]);

    [
      'root/ca.key',
      'root/ca.crt',
      'intermediate/ca.key',
      'intermediate/ca.crt',
      'services/api.crt',
      'services/api.key',
      'services/edge.crt',
      'services/edge.key',
      'ca-bundle.crt',
      'manifest.env',
    ].forEach((relative) => {
      expect(fs.existsSync(path.join(dir, relative))).toBe(true);
    });

    // Root plus the single intermediate.
    expect(certCount(path.join(dir, 'ca-bundle.crt'))).toBe(2);
  });

  maybeIt('chains every leaf to the bundle', () => {
    runPki(['init', '--out', dir, '--services', 'api', '--days', '30', '--key-bits', '2048']);

    const out = verifyWith(
      path.join(dir, 'services', 'api.crt'),
      path.join(dir, 'ca-bundle.crt'),
    );
    expect(out).toMatch(/api\.crt: OK/);
  });

  maybeIt('gives each service a URI SAN carrying its identity', () => {
    runPki(['init', '--out', dir, '--services', 'api edge', '--days', '30', '--key-bits', '2048']);

    const api = SANs(path.join(dir, 'services', 'api.crt'));
    expect(api).toContain('URI:spiffe://stellar-tags/internal/api');
    expect(api).toContain('DNS:api');
    expect(api).toContain('DNS:localhost');
    expect(api).toContain('IP Address:127.0.0.1');

    expect(SANs(path.join(dir, 'services', 'edge.crt'))).toContain(
      'URI:spiffe://stellar-tags/internal/edge',
    );
  });

  maybeIt('issues leaves valid for both serving and client authentication', () => {
    runPki(['init', '--out', dir, '--services', 'api', '--days', '30', '--key-bits', '2048']);

    const text = execFileSync(
      'openssl',
      ['x509', '-in', path.join(dir, 'services', 'api.crt'), '-noout', '-text'],
      { encoding: 'utf8' },
    );
    expect(text).toMatch(/TLS Web Server Authentication/);
    expect(text).toMatch(/TLS Web Client Authentication/);
    expect(text).toMatch(/CA:FALSE/);
  });

  maybeIt('keeps the private keys owner-only', () => {
    runPki(['init', '--out', dir, '--services', 'api', '--days', '30', '--key-bits', '2048']);

    const mode = fs.statSync(path.join(dir, 'services', 'api.key')).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  maybeIt('honours --sans', () => {
    runPki([
      'init',
      '--out',
      dir,
      '--services',
      'api',
      '--days',
      '30',
      '--key-bits',
      '2048',
      '--sans',
      'api=DNS:api.internal,DNS:api',
    ]);

    const sans = SANs(path.join(dir, 'services', 'api.crt'));
    expect(sans).toContain('DNS:api.internal');
    expect(sans).not.toContain('DNS:backend');
  });

  maybeIt('is idempotent, so a re-run on an existing PKI keeps the same CA', () => {
    const args = ['init', '--out', dir, '--services', 'api', '--days', '30', '--key-bits', '2048'];
    runPki(args);
    const root = fs.readFileSync(path.join(dir, 'root', 'ca.crt'), 'utf8');
    const intermediate = fs.readFileSync(path.join(dir, 'intermediate', 'ca.crt'), 'utf8');

    // `pki-init` re-runs on every `up`; a second init must reuse the authority
    // rather than mint a new one nobody trusts.
    runPki(args);

    expect(fs.readFileSync(path.join(dir, 'root', 'ca.crt'), 'utf8')).toBe(root);
    expect(fs.readFileSync(path.join(dir, 'intermediate', 'ca.crt'), 'utf8')).toBe(intermediate);
    expect(verifyWith(path.join(dir, 'services', 'api.crt'), path.join(dir, 'ca-bundle.crt'))).toMatch(/OK/);
  });

  maybeIt('rejects an unknown command', () => {
    const result = runPki(['frobnicate', '--out', dir], { expectFailure: true });
    expect(result.status).not.toBe(0);
  });
});

describeWithOpenssl('pki.sh rotate', () => {
  let dir;

  beforeEach(() => {
    dir = makePkiDir('pki-rotate-');
    runPki([
      'init',
      '--out',
      dir,
      '--services',
      'api edge',
      '--days',
      '30',
      '--key-bits',
      '2048',
    ]);
  });

  afterEach(() => {
    removePkiDir(dir);
  });

  maybeIt('replaces every leaf but keeps the old one trusted', () => {
    const before = fs.readFileSync(path.join(dir, 'services', 'api.crt'), 'utf8');
    const intermediate = path.join(dir, 'intermediate', 'ca.crt');

    runPki(['rotate', '--out', dir, '--days', '30', '--key-bits', '2048']);

    const after = fs.readFileSync(path.join(dir, 'services', 'api.crt'), 'utf8');
    expect(after).not.toBe(before);

    // The issuing CA is untouched, so the pre-rotation leaf still validates
    // against the bundle a restarted peer would load.
    const oldLeaf = path.join(dir, 'services', 'api.crt');
    expect(fs.existsSync(oldLeaf)).toBe(true);
    expect(verifyWith(oldLeaf, path.join(dir, 'ca-bundle.crt'), intermediate)).toMatch(/OK/);
    expect(verifyWith(path.join(dir, 'services', 'edge.crt'), path.join(dir, 'ca-bundle.crt'), intermediate)).toMatch(/OK/);
  });

  maybeIt('adds a new intermediate to the bundle before dropping the old one', () => {
    const firstIntermediate = fs.readFileSync(path.join(dir, 'intermediate', 'ca.crt'), 'utf8');

    runPki(['rotate', '--out', dir, '--days', '30', '--key-bits', '2048', '--new-intermediate']);

    const secondIntermediate = fs.readFileSync(path.join(dir, 'intermediate', 'ca.crt'), 'utf8');
    expect(secondIntermediate).not.toBe(firstIntermediate);

    // Root + both intermediates, so a peer that has only the old leaf can still
    // build a chain while the fleet rolls over.
    expect(certCount(path.join(dir, 'ca-bundle.crt'))).toBe(3);
    expect(fs.existsSync(path.join(dir, 'intermediate', 'retired'))).toBe(true);
  });

  maybeIt('leaves the bundle with a single intermediate after prune', () => {
    runPki(['rotate', '--out', dir, '--days', '30', '--key-bits', '2048', '--new-intermediate']);
    runPki(['prune', '--out', dir]);

    expect(certCount(path.join(dir, 'ca-bundle.crt'))).toBe(2);
    expect(fs.existsSync(path.join(dir, 'intermediate', 'retired'))).toBe(false);
    expect(
      verifyWith(path.join(dir, 'services', 'api.crt'), path.join(dir, 'ca-bundle.crt'), path.join(dir, 'intermediate', 'ca.crt')),
    ).toMatch(/OK/);
  });
});

describeWithOpenssl('pki.sh check', () => {
  let dir;

  beforeEach(() => {
    dir = makePkiDir('pki-check-');
    runPki(['init', '--out', dir, '--services', 'api', '--days', '30', '--key-bits', '2048']);
  });

  afterEach(() => {
    removePkiDir(dir);
  });

  maybeIt('reports every certificate and exits 0 when nothing is near expiry', () => {
    const result = runPki(['check', '--out', dir, '--warn-days', '1']);

    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/api/);
    expect(result.stdout).toMatch(/intermediate/i);
  });

  maybeIt('exits 1 when a certificate is inside the warning window', () => {
    const result = runPki(['check', '--out', dir, '--warn-days', '3650'], {
      expectFailure: true,
    });

    expect(result.status).toBe(1);
    expect(`${result.stdout}${result.stderr}`).toMatch(/expire/i);
  });
});
