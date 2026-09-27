'use strict';

/**
 * Unit tests for the request-layer mTLS guard. The fake sockets here stand in
 * for real TLS connections; the handshake itself is covered end to end in
 * mtls-handshake.test.js.
 */

const {
  emptyCertificateInfo,
  getClientCertificateInfo,
  identitySatisfiesPolicy,
  isInternalCaller,
  parseSubjectAltNames,
  requireMutualTls,
  serviceIdentity,
} = require('../src/middleware/mtls');
const { resetTlsConfig } = require('../src/config/tls');
const { ApiError } = require('../src/errors');

const PEER_CERT = {
  subject: { CN: 'edge', O: 'Stellar Tags' },
  issuer: { CN: 'Stellar Tags Internal Intermediate CA' },
  subjectaltname: 'DNS:edge, DNS:localhost, IP:127.0.0.1, URI:spiffe://stellar-tags/internal/edge',
  serialNumber: '0A1B2C3D',
  fingerprint256: 'AA:BB:CC',
  valid_from: 'Jan  1 00:00:00 2026 GMT',
  valid_to: 'Jan  1 00:00:00 2027 GMT',
  raw: Buffer.from('ignored'),
};

const makeSocket = (overrides = {}) => ({
  authorized: true,
  getPeerCertificate: () => PEER_CERT,
  getCipher: () => ({ name: 'TLS_AES_256_GCM_SHA384' }),
  remoteAddress: '172.20.0.4',
  ...overrides,
});

const makeReq = (socket, extra = {}) => ({
  socket,
  headers: {},
  correlationId: 'test-correlation-id',
  ...extra,
});

const run = (middleware, req) => {
  const next = jest.fn();
  middleware(req, {}, next);
  return next;
};

const FAKE_CERT = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n';
const FAKE_KEY = '-----BEGIN PRIVATE KEY-----\nMIIBfake\n-----END PRIVATE KEY-----\n';

const MTLS_VARS = [
  'MTLS_ENABLED',
  'MTLS_CA_PEM',
  'MTLS_CERT_PEM',
  'MTLS_KEY_PEM',
  'MTLS_CLIENT_AUTH',
  'MTLS_REQUIRED_SANS',
];

let savedEnv = {};

beforeAll(() => {
  MTLS_VARS.forEach((key) => {
    savedEnv[key] = process.env[key];
  });
});

afterAll(() => {
  MTLS_VARS.forEach((key) => {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
    resetTlsConfig();
  });
});

// The middleware reads the real configuration loader, so enabling mTLS here
// needs syntactically valid material even though the sockets are faked.
const enableMtls = (vars = {}) => {
  resetTlsConfig();
  process.env.MTLS_ENABLED = 'true';
  process.env.MTLS_CA_PEM = FAKE_CERT;
  process.env.MTLS_CERT_PEM = FAKE_CERT;
  process.env.MTLS_KEY_PEM = FAKE_KEY;
  Object.keys(vars).forEach((key) => {
    if (vars[key] === null) delete process.env[key];
    else process.env[key] = vars[key];
  });
};

const disableMtls = () => {
  resetTlsConfig();
  process.env.MTLS_ENABLED = 'false';
  ['MTLS_REQUIRED_SANS', 'MTLS_CLIENT_AUTH'].forEach((key) => delete process.env[key]);
};

beforeEach(() => {
  disableMtls();
});

describe('parseSubjectAltNames', () => {
  test('splits the OpenSSL SAN string into typed entries', () => {
    expect(
      parseSubjectAltNames('DNS:backend, URI:spiffe://stellar-tags/internal/api, IP:10.0.0.1'),
    ).toEqual([
      { type: 'DNS', value: 'backend' },
      { type: 'URI', value: 'spiffe://stellar-tags/internal/api' },
      { type: 'IP', value: '10.0.0.1' },
    ]);
  });

  test('handles a missing SAN list', () => {
    expect(parseSubjectAltNames(undefined)).toEqual([]);
    expect(parseSubjectAltNames('')).toEqual([]);
  });

  test('tolerates entries with no type prefix', () => {
    expect(parseSubjectAltNames('backend')).toEqual([{ type: 'DNS', value: 'backend' }]);
  });
});

describe('getClientCertificateInfo', () => {
  test('prefers the URI SAN as the service identity', () => {
    const info = getClientCertificateInfo(makeReq(makeSocket()));

    expect(info.presented).toBe(true);
    expect(info.authorized).toBe(true);
    expect(info.identity).toBe('spiffe://stellar-tags/internal/edge');
    expect(info.fingerprint256).toBe('AA:BB:CC');
    expect(info.validTo).toBe('Jan  1 00:00:00 2027 GMT');
  });

  test('falls back to a DNS SAN, then the common name', () => {
    const dnsOnly = getClientCertificateInfo(
      makeReq(makeSocket({ getPeerCertificate: () => ({ ...PEER_CERT, subjectaltname: 'DNS:backend' }) })),
    );
    expect(dnsOnly.identity).toBe('backend');

    const cnOnly = getClientCertificateInfo(
      makeReq(makeSocket({ getPeerCertificate: () => ({ subject: { CN: 'fraud-worker' } }) })),
    );
    expect(cnOnly.identity).toBe('fraud-worker');
  });

  test('reports an empty certificate for a request with no socket', () => {
    expect(getClientCertificateInfo({})).toEqual(emptyCertificateInfo());
  });

  test('reports no certificate when getPeerCertificate returns nothing', () => {
    const info = getClientCertificateInfo(makeReq(makeSocket({ getPeerCertificate: () => ({}) })));

    expect(info.presented).toBe(false);
    expect(info.authorized).toBe(true);
  });

  test('surfaces the authorization error for an unverified peer', () => {
    const info = getClientCertificateInfo(
      makeReq(
        makeSocket({
          authorized: false,
          authorizationError: new Error('unable to verify the first certificate'),
        }),
      ),
    );

    expect(info.authorized).toBe(false);
    expect(info.authorizationError).toBe('unable to verify the first certificate');
  });
});

describe('identitySatisfiesPolicy', () => {
  const info = getClientCertificateInfo(makeReq(makeSocket()));

  test('accepts any identity when no policy is configured', () => {
    expect(identitySatisfiesPolicy(info, [])).toBe(true);
  });

  test('matches a URI SAN', () => {
    expect(
      identitySatisfiesPolicy(info, ['spiffe://stellar-tags/internal/edge']),
    ).toBe(true);
  });

  test('matches a DNS SAN', () => {
    expect(identitySatisfiesPolicy(info, ['edge', 'localhost'])).toBe(true);
  });

  test('matches case-insensitively', () => {
    expect(identitySatisfiesPolicy(info, ['EDGE'])).toBe(true);
  });

  test('rejects an identity outside the allowlist', () => {
    expect(identitySatisfiesPolicy(info, ['spiffe://stellar-tags/internal/fraud-worker'])).toBe(false);
  });

  test('an empty allowlist does not accidentally match everything else', () => {
    expect(identitySatisfiesPolicy(emptyCertificateInfo(), ['edge'])).toBe(false);
  });
});

describe('requireMutualTls with mTLS disabled', () => {
  test('passes the request through and claims no identity', () => {
    const req = makeReq(makeSocket());
    const next = run(requireMutualTls, req);

    expect(next).toHaveBeenCalledWith();
    expect(req.serviceIdentity).toBeNull();
    expect(req.clientCertificate.presented).toBe(false);
  });
});

describe('requireMutualTls with mTLS enabled', () => {
  beforeEach(() => {
    enableMtls();
  });

  test('accepts a verified peer and records its identity', () => {
    const req = makeReq(makeSocket());
    const next = run(requireMutualTls, req);

    expect(next).toHaveBeenCalledWith();
    expect(req.serviceIdentity).toBe('spiffe://stellar-tags/internal/edge');
  });

  test('rejects a request that arrives with no certificate', () => {
    const req = makeReq(makeSocket({ getPeerCertificate: () => ({}) }));
    const next = run(requireMutualTls, req);

    const error = next.mock.calls[0][0];
    expect(error).toBeInstanceOf(ApiError);
    expect(error.statusCode).toBe(401);
    expect(error.code).toBe('UNAUTHENTICATED');
  });

  test('rejects a certificate the TLS layer refused to verify', () => {
    const req = makeReq(makeSocket({ authorized: false, authorizationError: 'self-signed' }));
    const next = run(requireMutualTls, req);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });

  test('rejects a certificate that is outside MTLS_REQUIRED_SANS', () => {
    enableMtls({ MTLS_REQUIRED_SANS: 'spiffe://stellar-tags/internal/fraud-worker' });
    const next = run(requireMutualTls, makeReq(makeSocket()));

    const error = next.mock.calls[0][0];
    expect(error.statusCode).toBe(403);
    expect(error.code).toBe('FORBIDDEN');
  });

  test('accepts any internal CA identity when no SAN policy is set', () => {
    const next = run(requireMutualTls, makeReq(makeSocket()));

    expect(next).toHaveBeenCalledWith();
  });

  test('verify-if-given still rejects a presented cert outside the allowlist', () => {
    // The mode makes the certificate optional, not unverified: if one is
    // presented it still has to be authorized.
    enableMtls({
      MTLS_CLIENT_AUTH: 'verify-if-given',
      MTLS_REQUIRED_SANS: 'spiffe://stellar-tags/internal/other',
    });
    const next = run(requireMutualTls, makeReq(makeSocket()));

    expect(next.mock.calls[0][0].statusCode).toBe(403);
  });

  test('verify-if-given lets a peer with no certificate through', () => {
    enableMtls({ MTLS_CLIENT_AUTH: 'verify-if-given' });
    const req = makeReq(makeSocket({ getPeerCertificate: () => ({}) }));
    const next = run(requireMutualTls, req);

    expect(next).toHaveBeenCalledWith();
    expect(req.serviceIdentity).toBeNull();
  });

  test('none lets every peer through, since none is requested', () => {
    enableMtls({ MTLS_CLIENT_AUTH: 'none' });
    const next = run(requireMutualTls, makeReq(makeSocket({ getPeerCertificate: () => ({}) })));

    expect(next).toHaveBeenCalledWith();
  });
});

describe('serviceIdentity', () => {
  test('attaches the identity without blocking the request', () => {
    enableMtls();
    const req = makeReq(makeSocket());
    const next = run(serviceIdentity, req);

    expect(next).toHaveBeenCalledWith();
    expect(req.serviceIdentity).toBe('spiffe://stellar-tags/internal/edge');
  });

  test('leaves the identity unset for an unauthorized peer', () => {
    enableMtls();
    const req = makeReq(makeSocket({ authorized: false }));
    run(serviceIdentity, req);

    expect(req.serviceIdentity).toBeNull();
  });

  test('is a no-op over plain HTTP', () => {
    const req = makeReq(makeSocket());
    const next = run(serviceIdentity, req);

    expect(next).toHaveBeenCalledWith();
    expect(req.serviceIdentity).toBeUndefined();
  });

  test('never fails a request when extraction throws', () => {
    enableMtls();
    const req = makeReq({
      get socket() {
        throw new Error('socket went away');
      },
    });
    const next = run(serviceIdentity, req);

    expect(next).toHaveBeenCalledWith();
  });
});

describe('isInternalCaller', () => {
  test('is false over plain HTTP even with a certificate present', () => {
    const req = makeReq(makeSocket());
    run(serviceIdentity, req);

    expect(isInternalCaller(req)).toBe(false);
  });

  test('is true for a verified peer on an mTLS listener', () => {
    enableMtls();
    const req = makeReq(makeSocket());
    run(serviceIdentity, req);

    expect(isInternalCaller(req)).toBe(true);
  });

  test('is false when mTLS does not demand client certificates', () => {
    enableMtls({ MTLS_CLIENT_AUTH: 'verify-if-given' });
    const req = makeReq(makeSocket());
    run(serviceIdentity, req);

    expect(isInternalCaller(req)).toBe(false);
  });
});
