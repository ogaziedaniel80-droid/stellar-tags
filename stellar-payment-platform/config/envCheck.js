'use strict';

// This module is the first thing the server loads, which means it runs before
// server.js gets to call dotenv. Loading it here is what makes the checks
// below see the same environment the rest of the process will (dotenv never
// overrides variables that are already exported, so the later call in
// server.js stays harmless).
require('dotenv').config();

const REQUIRED_ENV_VARS = ['PORT'];

for (const key of REQUIRED_ENV_VARS) {
  if (!process.env[key]) {
    if (process.env.NODE_ENV !== 'test') {
      console.error(`[env] Missing required environment variable: ${key}`);
      process.exit(1);
    }
  }
}

// #736 — When mTLS is switched on, its configuration is validated at startup so
// a missing certificate or a typo in a flag aborts the boot instead of
// quietly serving traffic in clear. Uses the same parser the server uses, so
// the two can never disagree about whether a value is valid.
const TRUTHY = new Set(['1', 'true', 'yes', 'on', 'enabled']);
const mtlsRequested =
  process.env.MTLS_ENABLED !== undefined &&
  TRUTHY.has(String(process.env.MTLS_ENABLED).trim().toLowerCase());

if (mtlsRequested) {
  try {
    const { getTlsConfig } = require('../src/config/tls');
    const config = getTlsConfig();
    console.error(
      `[env] mTLS enabled: ${config.clientAuth} client authentication, ${config.minVersionName} minimum, ` +
        `${config.requiredSans.length ? `identities restricted to ${config.requiredSans.join(', ')}` : 'any internal CA identity accepted'}.`,
    );
  } catch (err) {
    console.error(`[env] Invalid mTLS configuration: ${err.message}`);
    process.exit(1);
  }
}
