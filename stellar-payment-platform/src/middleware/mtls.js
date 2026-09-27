'use strict';

/**
 * src/middleware/mtls.js
 *
 * Request-layer enforcement for mutual TLS.
 *
 * The TLS handshake already refuses unauthenticated peers when
 * MTLS_CLIENT_AUTH=required, so by the time a request reaches Express the
 * socket carries an authorized certificate. This layer adds the two things
 * the handshake cannot express:
 *
 *   1. An explicit check per request, so a route mounted without the
 *      requirement cannot accidentally serve traffic on an mTLS listener.
 *   2. Service identity. The certificate SAN (DNS name or SPIFFE-style URI) is
 *      lifted onto `req.serviceIdentity` so internal callers can be authorized
 *      by who they are, and audit logs can record the peer rather than an
 *      unauthenticated IP.
 *
 * When mTLS is disabled every middleware here is a no-op, which keeps local
 * dev and the supertest suite working over plain HTTP.
 */

const { ApiError } = require('../errors');
const { logger } = require('../logger');
const { getTlsConfig } = require('../config/tls');

/**
 * SANs arrive as a single comma-separated OpenSSL string, e.g.
 * "DNS:backend, URI:spiffe://stellar-tags/prod/api". Split them into typed
 * entries so callers can match on DNS names or URIs without re-parsing.
 */
const parseSubjectAltNames = (subjectaltname) => {
  if (!subjectaltname) return [];
  return String(subjectaltname)
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const separator = entry.indexOf(':');
      if (separator === -1) return { type: 'DNS', value: entry };
      return { type: entry.slice(0, separator).trim(), value: entry.slice(separator + 1).trim() };
    });
};

const socketOf = (req) => req.socket || (req.connection && req.connection) || null;

const emptyCertificateInfo = () => ({
  presented: false,
  authorized: false,
  identity: null,
  subject: null,
  issuer: null,
  sans: [],
  serialNumber: null,
  fingerprint256: null,
  validFrom: null,
  validTo: null,
  authorizationError: null,
});

/**
 * Normalizes `socket.getPeerCertificate()` into a plain, loggable object.
 *
 * @returns {ReturnType<typeof emptyCertificateInfo>}
 */
const getClientCertificateInfo = (req) => {
  const socket = socketOf(req);
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    return emptyCertificateInfo();
  }

  const peer = socket.getPeerCertificate();
  // getPeerCertificate() returns an empty object when no certificate was
  // presented, so `authorized` is the real signal, not truthiness of `peer`.
  const presented = Boolean(peer && (peer.fingerprint256 || peer.raw));
  const sans = parseSubjectAltNames(peer && peer.subjectaltname);
  const dnsNames = sans.filter((san) => san.type === 'DNS').map((san) => san.value);
  const uriSans = sans.filter((san) => san.type === 'URI').map((san) => san.value);
  const subjectCn =
    peer && peer.subject && peer.subject.CN ? String(peer.subject.CN) : null;

  return {
    presented,
    authorized: Boolean(socket.authorized),
    identity: uriSans[0] || dnsNames[0] || subjectCn || null,
    subject: peer && peer.subject ? { ...peer.subject } : null,
    issuer: peer && peer.issuer ? { ...peer.issuer } : null,
    sans,
    serialNumber: (peer && peer.serialNumber) || null,
    fingerprint256: (peer && peer.fingerprint256) || null,
    validFrom: (peer && peer.valid_from) || null,
    validTo: (peer && peer.valid_to) || null,
    authorizationError:
      socket.authorizationError instanceof Error
        ? socket.authorizationError.message
        : socket.authorizationError || null,
  };
};

/**
 * Certificate identity check. When MTLS_REQUIRED_SANS is set, the peer must
 * present a certificate carrying at least one of those SANs, which is what
 * stops any certificate the internal CA ever issued from being good enough.
 */
const identitySatisfiesPolicy = (info, requiredSans) => {
  if (!requiredSans.length) return true;
  const presented = new Set(
    info.sans
      .filter((san) => san.type === 'DNS' || san.type === 'URI')
      .map((san) => san.value.toLowerCase()),
  );
  if (info.identity) presented.add(String(info.identity).toLowerCase());
  return requiredSans.some((expected) => presented.has(String(expected).toLowerCase()));
};

/**
 * Express middleware enforcing a verified client certificate.
 *
 * Usage: `router.use(requireMutualTls)` or `router.get('/internal', requireMutualTls, handler)`.
 */
const requireMutualTls = (req, res, next) => {
  const config = getTlsConfig();

  if (!config.enabled) {
    // Plain HTTP listener: there is no certificate to check, and pretending
    // otherwise would be a lie in the audit log.
    req.clientCertificate = emptyCertificateInfo();
    req.serviceIdentity = null;
    return next();
  }

  const info = getClientCertificateInfo(req);
  req.clientCertificate = info;

  if (!info.presented) {
    // In verify-if-given mode the transport already decided a certificate is
    // optional, so the guard must not turn that into a hard requirement.
    if (!config.enforcePeerCert) {
      req.serviceIdentity = null;
      return next();
    }
    logger.warn(
      {
        remoteAddress: req.socket && req.socket.remoteAddress,
        cipher: req.socket && req.socket.getCipher && req.socket.getCipher(),
        correlationId: req.correlationId,
      },
      '[mtls] Rejected request without a client certificate',
    );
    return next(
      new ApiError(
        'UNAUTHENTICATED',
        'A valid client certificate is required for this service',
      ),
    );
  }

  if (!info.authorized) {
    logger.warn(
      {
        identity: info.identity,
        authorizationError: info.authorizationError,
        correlationId: req.correlationId,
      },
      '[mtls] Rejected request with a client certificate that failed verification',
    );
    return next(
      new ApiError(
        'UNAUTHENTICATED',
        'A valid client certificate is required for this service',
      ),
    );
  }

  if (!identitySatisfiesPolicy(info, config.requiredSans)) {
    logger.warn(
      {
        identity: info.identity,
        requiredSans: config.requiredSans,
        correlationId: req.correlationId,
      },
      '[mtls] Rejected request from a certificate outside the allowed identities',
    );
    return next(
      new ApiError(
        'FORBIDDEN',
        'Client certificate is not authorized for this service',
      ),
    );
  }

  req.serviceIdentity = info.identity;
  return next();
};

/**
 * Attaches the peer identity to every request without blocking anything.
 * Mounted early so correlation IDs, request logs and audit trails can name the
 * calling service rather than just its address.
 */
const serviceIdentity = (req, _res, next) => {
  try {
    const config = getTlsConfig();
    if (!config.enabled) return next();
    const info = getClientCertificateInfo(req);
    req.clientCertificate = info;
    req.serviceIdentity = info.authorized ? info.identity : null;
  } catch (err) {
    // Identity extraction is observability, not access control: never let it
    // fail a request that the TLS layer already authorized.
    logger.debug({ err: err.message }, '[mtls] Could not extract peer identity');
  }
  return next();
};

/** Whether the calling process is an internal, certificate-authenticated peer. */
const isInternalCaller = (req) => {
  const config = getTlsConfig();
  if (!config.enabled || !config.enforcePeerCert) return false;
  const identity = req.serviceIdentity || (req.clientCertificate && req.clientCertificate.identity);
  return Boolean(identity);
};

module.exports = {
  emptyCertificateInfo,
  getClientCertificateInfo,
  identitySatisfiesPolicy,
  isInternalCaller,
  parseSubjectAltNames,
  requireMutualTls,
  serviceIdentity,
};
