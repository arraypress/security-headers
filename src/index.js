/**
 * @arraypress/security-headers
 *
 * Security response headers for Hono on edge runtimes. Ships strict-by-default
 * Content-Security-Policy + HSTS + the usual supporting headers
 * (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
 * `Permissions-Policy`) as a single middleware.
 *
 * Zero dependencies beyond Hono itself. Defaults match a modern admin
 * SPA (Tailwind v4 + shadcn/ui): same-origin everything, `'unsafe-inline'`
 * on style only (required by Tailwind arbitrary values + Radix inline
 * positioning), `object-src 'none'` to kill legacy plugins, and
 * `upgrade-insecure-requests` to auto-rewrite any http:// refs.
 *
 * Also exports `buildCSP()` standalone for consumers that want to
 * compose the header string and apply it elsewhere (e.g. Pages config,
 * a reverse proxy).
 *
 * @module @arraypress/security-headers
 */

/**
 * Safe defaults for a modern admin SPA. Each field can be overridden
 * independently via the `csp` config. Arrays replace — they don't merge
 * — so `{ scriptSrc: ["'self'"] }` drops the CSP back to bare bones.
 */
const CSP_DEFAULTS = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'"],
  styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:', 'https:'],
  fontSrc: ["'self'"],
  connectSrc: ["'self'"],
  frameSrc: ["'self'"],
  formAction: ["'self'"],
  baseUri: ["'self'"],
  objectSrc: ["'none'"],
  frameAncestors: ["'self'"],
  upgradeInsecureRequests: true,
};

/** Map camelCase directive names → kebab-case wire format. */
const DIRECTIVE_NAMES = {
  defaultSrc: 'default-src',
  scriptSrc: 'script-src',
  styleSrc: 'style-src',
  imgSrc: 'img-src',
  fontSrc: 'font-src',
  connectSrc: 'connect-src',
  frameSrc: 'frame-src',
  formAction: 'form-action',
  baseUri: 'base-uri',
  objectSrc: 'object-src',
  frameAncestors: 'frame-ancestors',
};

const HSTS_DEFAULTS = {
  maxAge: 31536000, // 1 year
  includeSubDomains: true,
  preload: false,
};

/**
 * Build a Content-Security-Policy header string from a config object.
 *
 * Every directive has a safe default from `CSP_DEFAULTS`. Pass only the
 * fields you want to override — the rest inherit the defaults. Arrays
 * replace (they don't merge), so `scriptSrc: ["'self'", turnstile]` is
 * how you'd allow the Cloudflare Turnstile widget.
 *
 * Directives are emitted in a stable order so different call sites that
 * produce the same logical config produce the same string (makes
 * diffs + header-fingerprinting tools happy).
 *
 * @param {import('./index.d.ts').CSPConfig} [config={}]
 * @returns {string} Serialised CSP ready for a `Content-Security-Policy` header.
 *
 * @example
 * buildCSP({
 *   scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
 *   frameSrc: ["'self'", 'https://challenges.cloudflare.com'],
 * });
 * // → "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; ..."
 */
export function buildCSP(config = {}) {
  const merged = { ...CSP_DEFAULTS, ...config };
  const parts = [];

  for (const [key, wireName] of Object.entries(DIRECTIVE_NAMES)) {
    const values = merged[key];
    if (!values || values.length === 0) continue;
    parts.push(`${wireName} ${values.join(' ')}`);
  }

  // Arbitrary extra directives — rare, but e.g. `report-uri` or
  // `require-trusted-types-for` that aren't first-class here.
  if (config.custom) {
    for (const [name, values] of Object.entries(config.custom)) {
      if (values && values.length > 0) {
        parts.push(`${name} ${values.join(' ')}`);
      }
    }
  }

  if (merged.upgradeInsecureRequests) {
    parts.push('upgrade-insecure-requests');
  }

  return parts.join('; ');
}

/**
 * Build the `Strict-Transport-Security` header string.
 *
 * @param {import('./index.d.ts').HSTSConfig | true} [config=true]
 *   Pass `true` for safe defaults (1yr + includeSubDomains), or an
 *   object to customise.
 * @returns {string}
 */
export function buildHSTS(config = true) {
  const { maxAge, includeSubDomains, preload } = {
    ...HSTS_DEFAULTS,
    ...(config === true ? {} : config ?? {}),
  };
  const parts = [`max-age=${maxAge}`];
  if (includeSubDomains) parts.push('includeSubDomains');
  if (preload) parts.push('preload');
  return parts.join('; ');
}

/**
 * Create the security-headers Hono middleware.
 *
 * Runs AFTER `next()` so the headers are applied to the response on the
 * way out. Every header is independently togglable — pass `false` for
 * any field to skip that header entirely.
 *
 * @param {import('./index.d.ts').SecurityHeadersConfig} [config={}]
 * @returns {import('hono').MiddlewareHandler}
 *
 * @example
 * ```ts
 * import { securityHeaders } from '@arraypress/security-headers';
 *
 * app.use('*', securityHeaders({
 *   csp: {
 *     scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
 *     frameSrc:  ["'self'", 'https://challenges.cloudflare.com'],
 *   },
 *   // hsts / xFrameOptions / etc. use safe defaults
 * }));
 * ```
 */
export function securityHeaders(config = {}) {
  const {
    csp = {},
    hsts = true,
    xContentTypeOptions = true,
    xFrameOptions = 'SAMEORIGIN',
    referrerPolicy = 'strict-origin-when-cross-origin',
    permissionsPolicy = 'camera=(), microphone=(), geolocation=()',
  } = config;

  // Pre-compute the static header strings once so the middleware isn't
  // serializing on every request.
  const cspHeader = csp === false ? null : buildCSP(csp);
  const hstsHeader = hsts === false ? null : buildHSTS(hsts);

  return async (c, next) => {
    await next();

    if (xContentTypeOptions) {
      c.header('X-Content-Type-Options', 'nosniff');
    }
    if (xFrameOptions !== false) {
      c.header('X-Frame-Options', xFrameOptions);
    }
    if (referrerPolicy !== false) {
      c.header('Referrer-Policy', referrerPolicy);
    }
    if (permissionsPolicy !== false) {
      c.header('Permissions-Policy', permissionsPolicy);
    }
    if (cspHeader) {
      c.header('Content-Security-Policy', cspHeader);
    }
    if (hstsHeader) {
      c.header('Strict-Transport-Security', hstsHeader);
    }
  };
}
