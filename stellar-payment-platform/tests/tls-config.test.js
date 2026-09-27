'use strict';

/**
 * Unit tests for the mTLS configuration loader. Everything here runs against
 * temporary files and inline PEM strings, so no real PKI is needed.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  MtlsConfigurationError,
  describeTlsStatus,
  getClientTlsOptions,
  getServerTlsOptions,
  getTlsConfig,
  isMtlsEnabled,
  loadTlsConfig,
  parseBoolean,
  parseList,
  resetTlsConfig,
} = require('../src/config/tls');

// A syntactically valid key/certificate pair is not needed for the loader: the
// loader only checks that the material looks like PEM, that a CA bundle holds
// at least one certificate, and that the flags parse.
const FAKE_CERT = [
  '-----BEGIN CERTIFICATE-----',
  'MIIBfakecontentforunittestingpurposesonly0000000000',
  '-----END CERTIFICATE-----',
  '',
].join('\n');

const FAKE_KEY = [
  '-----BEGIN PRIVATE KEY-----',
  'MIIBfakekeycontentforunittestingpurposes00000000000000',
  '-----END PRIVATE KEY-----',
  '',
].join('\n');

const MTLS_VARS = [
  'MTLS_ENABLED',
  'MTLS_CA_FILE',
  'MTLS_CA_PEM',
  'MTLS_CERT_FILE',
  'MTLS_CERT_PEM',
  'MTLS_KEY_FILE',
  'MTLS_KEY_PEM',
  'MTLS_CLIENT_CERT_FILE',
  'MTLS_CLIENT_CERT_PEM',
  'MTLS_CLIENT_KEY_FILE',
  'MTLS_CLIENT_KEY_PEM',
  'MTLS_CLIENT_AUTH',
  'MTLS_MIN_VERSION',
  'MTLS_CIPHERS',
  'MTLS_REQUIRED_SANS',
  'MTLS_INTERNAL_DOMAINS',
  'MTLS_CIPHER_POLICY',
  'MTLS_HOT_RELOAD',
  'MTLS_RELOAD_INTERVAL_MS',
  'MTLS_CERT_DIR',
];

let savedEnv = {};
let tempDir = null;

const writeFile = (name, contents) => {
  const file = path.join(tempDir, name);
  fs.writeFileSync(file, contents);
  return file;
};

beforeAll(() => {
  MTLS_VARS.forEach((key) => {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  });
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mtls-config-'));
});

afterAll(() => {
  MTLS_VARS.forEach((key) => {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  });
  resetTlsConfig();
  if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
});

beforeEach(() => {
  resetTlsConfig();
  MTLS_VARS.forEach((key) => delete process.env[key]);
});

describe('parseBoolean', () => {
  test.each(['1', 'true', 'TRUE', 'yes', 'on', 'enabled'])('treats %s as true', (value) => {
    expect(parseBoolean(value)).toBe(true);
  });

  test.each(['0', 'false', 'no', 'off', 'disabled'])('treats %s as false', (value) => {
    expect(parseBoolean(value, true)).toBe(false);
  });

  test('falls back when unset', () => {
    expect(parseBoolean(undefined, true)).toBe(true);
    expect(parseBoolean(undefined)).toBe(false);
    // An empty value means "not configured", so the fallback applies.
    expect(parseBoolean('', true)).toBe(true);
  });

  test('rejects a value that is neither', () => {
    expect(() => parseBoolean('maybe')).toThrow(MtlsConfigurationError);
  });
});

describe('parseList', () => {
  test('splits on commas and drops blanks', () => {
    expect(parseList('a, b ,,c')).toEqual(['a', 'b', 'c']);
  });

  test('returns an empty array for an unset value', () => {
    expect(parseList(undefined)).toEqual([]);
    expect(parseList('')).toEqual([]);
  });
});

describe('mTLS disabled (default)', () => {
  test('reports http and yields no TLS options', () => {
    expect(isMtlsEnabled()).toBe(false);
    expect(getServerTlsOptions()).toBeNull();
    expect(getClientTlsOptions()).toBeNull();
    expect(describeTlsStatus()).toEqual({ enabled: false, transport: 'http' });
  });

  test('never touches the filesystem even when the paths are wrong', () => {
    process.env.MTLS_CA_FILE = '/nonexistent/ca-bundle.crt';
    process.env.MTLS_CERT_FILE = '/nonexistent/api.crt';
    process.env.MTLS_KEY_FILE = '/nonexistent/api.key';

    expect(() => getTlsConfig()).not.toThrow();
    expect(getTlsConfig().ca).toBeNull();
  });
});

describe('mTLS enabled', () => {
  beforeEach(() => {
    process.env.MTLS_ENABLED = 'true';
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;
  });

  test('requires client certificates by default', () => {
    const config = getTlsConfig();

    expect(config.enabled).toBe(true);
    expect(config.enforcePeerCert).toBe(true);
    expect(config.requireClientCert).toBe(true);
    expect(config.minVersionName).toBe('TLSv1.2');
  });

  test('builds server options that demand a client certificate', () => {
    const options = getServerTlsOptions();

    expect(options.requestCert).toBe(true);
    expect(options.rejectUnauthorized).toBe(true);
    expect(options.ca).toBe(FAKE_CERT);
    expect(options.cert).toBe(FAKE_CERT);
    expect(options.key).toBe(FAKE_KEY);
    expect(options.minVersion).toBe('TLSv1.2');
    expect(options.honorCipherOrder).toBe(true);
  });

  test('client options present the service identity and trust anchor', () => {
    const options = getClientTlsOptions();

    expect(options).toMatchObject({ ca: FAKE_CERT, cert: FAKE_CERT, key: FAKE_KEY });
  });

  test('reuses the server identity as a client identity when none is given', () => {
    process.env.MTLS_CLIENT_CERT_PEM = FAKE_CERT;
    process.env.MTLS_CLIENT_KEY_PEM = FAKE_KEY;

    expect(getClientTlsOptions().cert).toBe(FAKE_CERT);
  });

  test('reads material from files when they are provided', () => {
    delete process.env.MTLS_CA_PEM;
    delete process.env.MTLS_CERT_PEM;
    delete process.env.MTLS_KEY_PEM;
    process.env.MTLS_CA_FILE = writeFile('ca-bundle.crt', FAKE_CERT);
    process.env.MTLS_CERT_FILE = writeFile('api.crt', FAKE_CERT);
    process.env.MTLS_KEY_FILE = writeFile('api.key', FAKE_KEY);

    const config = getTlsConfig();

    expect(config.ca).toBe(FAKE_CERT);
    expect(config.certDir).toBeDefined();
  });

  test('a file path wins over an inline PEM value', () => {
    process.env.MTLS_CA_FILE = writeFile('ca-bundle.crt', FAKE_CERT);

    expect(getTlsConfig().ca).toBe(FAKE_CERT);
  });

  test('describeTlsStatus advertises the enforced policy', () => {
    process.env.MTLS_REQUIRED_SANS = 'spiffe://stellar-tags/internal/edge, DNS:backend';

    expect(describeTlsStatus()).toMatchObject({
      enabled: true,
      transport: 'https',
      clientAuth: 'required',
      clientCertificateRequired: true,
      minVersion: 'TLSv1.2',
      requiredSans: ['spiffe://stellar-tags/internal/edge', 'dns:backend'],
      caCertificates: 1,
    });
  });

  test('counting a rotation bundle reports every certificate', () => {
    process.env.MTLS_CA_PEM = `${FAKE_CERT}\n${FAKE_CERT}\n${FAKE_CERT}`;

    expect(describeTlsStatus().caCertificates).toBe(3);
  });
});

describe('mTLS configuration is validated, not guessed', () => {
  beforeEach(() => {
    process.env.MTLS_ENABLED = 'true';
  });

  test('refuses to start without a trust anchor', () => {
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;

    expect(() => loadTlsConfig()).toThrow(/MTLS_CA_FILE/);
  });

  test('refuses to start without a server certificate', () => {
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;

    expect(() => loadTlsConfig()).toThrow(/MTLS_CERT_FILE/);
  });

  test('refuses to start without a server key', () => {
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_CERT_PEM = FAKE_CERT;

    expect(() => loadTlsConfig()).toThrow(/MTLS_KEY_FILE/);
  });

  test('reports an unreadable file instead of falling back to plaintext', () => {
    process.env.MTLS_CA_FILE = '/nonexistent/ca-bundle.crt';
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;

    expect(() => loadTlsConfig()).toThrow(MtlsConfigurationError);
    expect(() => loadTlsConfig()).toThrow(/Unable to read/);
  });

  test('rejects material that is not PEM', () => {
    process.env.MTLS_CA_PEM = 'not a certificate';
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;

    expect(() => loadTlsConfig()).toThrow(/does not look like PEM/);
  });

  test('rejects a CA file that holds no certificate', () => {
    process.env.MTLS_CA_PEM = '-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----';
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;

    expect(() => loadTlsConfig()).toThrow(/no certificates/);
  });

  test('rejects an unsupported TLS version', () => {
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;
    process.env.MTLS_MIN_VERSION = 'SSLv3';

    expect(() => loadTlsConfig()).toThrow(/Unsupported MTLS_MIN_VERSION/);
  });

  test('rejects an unknown client authentication mode', () => {
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;
    process.env.MTLS_CLIENT_AUTH = 'maybe';

    expect(() => loadTlsConfig()).toThrow(/Unsupported MTLS_CLIENT_AUTH/);
  });

  test('rejects a non-numeric reload interval', () => {
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;
    process.env.MTLS_RELOAD_INTERVAL_MS = 'often';

    expect(() => loadTlsConfig()).toThrow(/non-negative integer/);
  });

  test('validates the flag shapes even when mTLS is off', () => {
    process.env.MTLS_ENABLED = 'false';
    process.env.MTLS_MIN_VERSION = 'TLSv9';

    expect(() => loadTlsConfig()).toThrow(/Unsupported MTLS_MIN_VERSION/);
  });
});

describe('client authentication modes', () => {
  beforeEach(() => {
    process.env.MTLS_ENABLED = 'true';
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;
  });

  test('verify-if-given asks for a certificate but tolerates its absence', () => {
    process.env.MTLS_CLIENT_AUTH = 'verify-if-given';

    const options = getServerTlsOptions();

    expect(options.requestCert).toBe(true);
    // Node would otherwise drop the socket before the request layer can decide.
    expect(options.rejectUnauthorized).toBe(false);
    expect(getTlsConfig().enforcePeerCert).toBe(false);
  });

  test('none encrypts without authenticating the peer', () => {
    process.env.MTLS_CLIENT_AUTH = 'none';

    const options = getServerTlsOptions();

    expect(options.requestCert).toBe(false);
    expect(options.rejectUnauthorized).toBe(false);
    expect(describeTlsStatus().clientCertificateRequired).toBe(false);
  });
});

describe('cipher policy', () => {
  beforeEach(() => {
    process.env.MTLS_ENABLED = 'true';
    process.env.MTLS_CA_PEM = FAKE_CERT;
    process.env.MTLS_CERT_PEM = FAKE_CERT;
    process.env.MTLS_KEY_PEM = FAKE_KEY;
  });

  test('leaves Node defaults alone when no override is configured', () => {
    expect(getServerTlsOptions().ciphers).toBeUndefined();
  });

  test('applies an explicit cipher list', () => {
    process.env.MTLS_CIPHERS = 'ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256';

    expect(getServerTlsOptions().ciphers).toBe(
      'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
    );
  });

  test('honours a TLS 1.3 floor', () => {
    process.env.MTLS_MIN_VERSION = 'TLSv1.3';

    expect(getServerTlsOptions().minVersion).toBe('TLSv1.3');
  });
});

describe('internal host allowlist', () => {
  test('falls back to the compose service names', () => {
    expect(getTlsConfig().internalDomains).toEqual(
      expect.arrayContaining(['backend', 'fraud-worker', 'api-test', 'localhost']),
    );
  });

  test('is fully overridable', () => {
    process.env.MTLS_INTERNAL_DOMAINS = 'payments.internal, ledger.internal';

    expect(getTlsConfig().internalDomains).toEqual([
      'payments.internal',
      'ledger.internal',
    ]);
  });
});
