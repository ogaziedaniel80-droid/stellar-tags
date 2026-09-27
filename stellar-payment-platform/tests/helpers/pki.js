'use strict';

/**
 * Test helper for the internal PKI.
 *
 * Every test that needs real certificates goes through here, so the
 * certificate material used by the suite is always produced by the same script
 * that ships in scripts/pki. When openssl is unavailable the tests that use
 * this helper skip rather than fail.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PKI_SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'pki', 'pki.sh');

let cachedAvailability = null;

const opensslAvailable = () => {
  if (cachedAvailability === null) {
    try {
      execFileSync('openssl', ['version'], { stdio: 'ignore' });
      cachedAvailability = true;
    } catch {
      cachedAvailability = false;
    }
  }
  return cachedAvailability;
};

/**
 * Runs a pki.sh subcommand.
 *
 * @param {string[]} args
 * @param {{ expectFailure?: boolean }} [options]
 * @returns {{ status: number, stdout: string, stderr: string }}
 */
const runPki = (args, options = {}) => {
  try {
    const stdout = execFileSync('sh', [PKI_SCRIPT, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    if (!options.expectFailure) throw err;
    return {
      status: err.status === undefined ? 1 : err.status,
      stdout: err.stdout ? String(err.stdout) : '',
      stderr: err.stderr ? String(err.stderr) : '',
    };
  }
};

/** Creates a throwaway directory for generated PKI material. */
const makePkiDir = (prefix = 'mtls-pki-') => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

const removePkiDir = (dir) => fs.rmSync(dir, { recursive: true, force: true });

/**
 * Generates a complete PKI with small keys, so a test suite that needs one
 * spends seconds rather than a minute on RSA key generation.
 *
 * @returns {{ dir: string, ca: string, services: (name: string) => {cert: string, key: string} }}
 */
const generatePki = (options = {}) => {
  const dir = makePkiDir();
  const services = options.services || 'api edge fraud-worker healthcheck';
  runPki([
    'init',
    '--out',
    dir,
    '--services',
    services,
    '--days',
    String(options.days || 30),
    '--key-bits',
    '2048',
  ]);
  return {
    dir,
    ca: path.join(dir, 'ca-bundle.crt'),
    services: (name) => ({
      cert: path.join(dir, 'services', `${name}.crt`),
      key: path.join(dir, 'services', `${name}.key`),
    }),
  };
};

module.exports = {
  PKI_SCRIPT,
  generatePki,
  makePkiDir,
  opensslAvailable,
  removePkiDir,
  runPki,
};
