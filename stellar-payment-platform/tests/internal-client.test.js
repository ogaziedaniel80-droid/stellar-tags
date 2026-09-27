'use strict';

/**
 * Outbound client tests.
 *
 * The property under test is a security boundary: the internal client
 * certificate may only ever be presented to a host on MTLS_INTERNAL_DOMAINS.
 * Asserting that against a real listener is awkward, because a correct
 * implementation routes external hosts to plain `fetch` and therefore cannot
 * trust a test CA — so the transport is stubbed and the arguments are checked
 * directly. The real handshake on the internal path is covered end to end in
 * tests/mtls-handshake.test.js.
 */

const https = require('https');
const { EventEmitter } = require('events');

const { resetTlsConfig } = require('../src/config/tls');
const { internalFetch, resetInternalClient } = require('../src/utils/internalClient');

const ENV_KEYS = [
  'MTLS_ENABLED',
  'MTLS_CA_PEM',
  'MTLS_CERT_PEM',
  'MTLS_KEY_PEM',
  'MTLS_CLIENT_CERT_PEM',
  'MTLS_CLIENT_KEY_PEM',
  'MTLS_INTERNAL_DOMAINS',
];

const PEM_CA = '-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n';
const PEM_CERT = '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n';
const PEM_KEY = '-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n';

let savedEnv = {};

beforeEach(() => {
  ENV_KEYS.forEach((key) => {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  });

  process.env.MTLS_ENABLED = 'true';
  process.env.MTLS_CA_PEM = PEM_CA;
  process.env.MTLS_CERT_PEM = PEM_CERT;
  process.env.MTLS_KEY_PEM = PEM_KEY;
  process.env.MTLS_CLIENT_CERT_PEM = PEM_CERT;
  process.env.MTLS_CLIENT_KEY_PEM = PEM_KEY;
  process.env.MTLS_INTERNAL_DOMAINS = 'backend,fraud-worker.internal';

  resetTlsConfig();
  resetInternalClient();
});

afterEach(() => {
  jest.restoreAllMocks();
  resetInternalClient();
  resetTlsConfig();
  ENV_KEYS.forEach((key) => {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  });
});

/** Resolves the stubbed `https.request` with a minimal 200 JSON response. */
const stubHttpsRequest = () => {
  const req = new EventEmitter();
  req.write = jest.fn();
  req.end = jest.fn(() => {
    const res = new EventEmitter();
    res.statusCode = 200;
    res.statusMessage = 'OK';
    res.headers = { 'content-type': 'application/json' };
    process.nextTick(() => {
      callback(res);
      res.emit('data', Buffer.from('{"ok":true}'));
      res.emit('end');
    });
  });
  let callback;
  const spy = jest
    .spyOn(https, 'request')
    .mockImplementation((_url, _options, cb) => {
      callback = cb;
      return req;
    });
  return { spy, req };
};

const stubFetch = () =>
  jest
    .spyOn(global, 'fetch')
    .mockResolvedValue(new Response('{}', { status: 200 }));

describe('internalFetch', () => {
  it('presents the client certificate to an internal host', async () => {
    const { spy } = stubHttpsRequest();
    const fetchSpy = stubFetch();

    const res = await internalFetch('https://backend:5000/health');

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(spy).toHaveBeenCalledTimes(1);

    const [url, options] = spy.mock.calls[0];
    expect(url).toBe('https://backend:5000/health');
    expect(options.method).toBe('GET');
    expect(options.agent.options.cert).toBe(PEM_CERT);
    expect(options.agent.options.key).toBe(PEM_KEY);
    expect(options.agent.options.ca).toBe(PEM_CA);
    expect(res.ok).toBe(true);
    await expect(res.json()).resolves.toEqual({ ok: true });
  });

  it('matches an internal host on a label boundary only', async () => {
    stubHttpsRequest();
    const fetchSpy = stubFetch();

    // A subdomain of an allowlisted entry is internal...
    await internalFetch('https://fraud-worker.internal:5000/x');
    expect(fetchSpy).not.toHaveBeenCalled();

    // ...but a lookalike name is not.
    await internalFetch('https://notfraud-worker.internal.attacker.test/x');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('never offers the certificate to a host outside the allowlist', async () => {
    const { spy } = stubHttpsRequest();
    const fetchSpy = stubFetch();

    await internalFetch('https://merchant.example.com/hook');

    // External destinations stay on plain fetch: no agent, no certificate,
    // and the caller's options untouched.
    expect(spy).not.toHaveBeenCalled();
    expect(fetchSpy).toHaveBeenCalledWith('https://merchant.example.com/hook', {});
  });

  it('refuses to reach an internal host over plaintext', async () => {
    const { spy } = stubHttpsRequest();
    const fetchSpy = stubFetch();

    await expect(internalFetch('http://backend:5000/health')).rejects.toThrow(
      /Refusing to send an unauthenticated plaintext request to internal host "backend"/,
    );
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(spy).not.toHaveBeenCalled();
  });

  it('is a plain fetch when mTLS is disabled', async () => {
    process.env.MTLS_ENABLED = 'false';
    resetTlsConfig();
    resetInternalClient();

    const { spy } = stubHttpsRequest();
    const fetchSpy = stubFetch();

    // Even an internal host is left alone: nothing to authenticate with.
    await expect(internalFetch('http://backend:5000/health')).resolves.toBeDefined();

    expect(spy).not.toHaveBeenCalled();
    expect(fetchSpy).toHaveBeenCalledWith('http://backend:5000/health', {});
  });

  it('forwards method, headers and body to the internal hop', async () => {
    const { spy, req } = stubHttpsRequest();

    await internalFetch('https://backend:5000/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"id":1}',
    });

    const [, options] = spy.mock.calls[0];
    expect(options.method).toBe('POST');
    expect(options.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(req.write).toHaveBeenCalledWith('{"id":1}');
    expect(req.end).toHaveBeenCalled();
  });

  it('honours an already-aborted signal', async () => {
    const { spy, req } = stubHttpsRequest();
    const controller = new AbortController();
    controller.abort();

    await expect(
      internalFetch('https://backend:5000/health', { signal: controller.signal }),
    ).rejects.toThrow();
    expect(spy).not.toHaveBeenCalled();
    expect(req.end).not.toHaveBeenCalled();
  });

  it('rebuilds the agent when the certificate on disk changes', async () => {
    const { spy } = stubHttpsRequest();

    await internalFetch('https://backend:5000/one');
    const first = spy.mock.calls[0][1].agent;

    await internalFetch('https://backend:5000/two');
    expect(spy.mock.calls[1][1].agent).toBe(first);

    // A rotation changes the material, so the pooled agent must be replaced.
    process.env.MTLS_CLIENT_CERT_PEM = PEM_CERT.replace('cert', 'rotated');
    resetTlsConfig();
    await internalFetch('https://backend:5000/three');
    expect(spy.mock.calls[2][1].agent).not.toBe(first);
  });
});
