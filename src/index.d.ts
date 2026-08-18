
// ── CSP ─────────────────────────────────────────────────

/**
 * Content-Security-Policy directive config. Every field has a safe
 * default — pass only the ones you need to override.
 *
 * Arrays **replace** the default rather than merging. If you need
 * Turnstile's CDN added to script-src, supply the full list:
 * `scriptSrc: ["'self'", 'https://challenges.cloudflare.com']`.
 *
 * Pass `csp: false` on the middleware config to skip CSP entirely.
 */
export interface CSPConfig {
  /** `default-src` — fallback for anything else. Default: `["'self'"]`. */
  defaultSrc?: string[];
  /** `script-src`. Default: `["'self'"]`. */
  scriptSrc?: string[];
  /**
   * `style-src`. Default: `["'self'", "'unsafe-inline'"]`.
   *
   * `'unsafe-inline'` is required for Tailwind v4 arbitrary-value
   * utilities and Radix/shadcn inline positioning styles. If your app
   * doesn't use either, drop it: `styleSrc: ["'self'"]`.
   */
  styleSrc?: string[];
  /** `img-src`. Default: `["'self'", 'data:', 'https:']` (allow HTTPS images + bundled data URIs). */
  imgSrc?: string[];
  /** `font-src`. Default: `["'self'"]`. */
  fontSrc?: string[];
  /** `connect-src` — XHR/fetch targets. Default: `["'self'"]`. */
  connectSrc?: string[];
  /** `frame-src` — iframe sources. Default: `["'self'"]`. Add CAPTCHA CDNs here. */
  frameSrc?: string[];
  /** `form-action`. Default: `["'self'"]`. */
  formAction?: string[];
  /** `base-uri`. Default: `["'self'"]`. */
  baseUri?: string[];
  /** `object-src`. Default: `["'none'"]` — kills legacy Flash / Java plugin vectors. Keep restrictive. */
  objectSrc?: string[];
  /**
   * `frame-ancestors` — clickjacking defence. Default: `["'self'"]`.
   *
   * Supersedes `X-Frame-Options` in modern browsers, but this library
   * sets both for defence-in-depth.
   */
  frameAncestors?: string[];
  /** Emit `upgrade-insecure-requests`. Default: `true` — auto-rewrites any http:// ref to https://. */
  upgradeInsecureRequests?: boolean;
  /**
   * Extra directives not covered above. Key is the directive name in
   * wire format (e.g. `'report-uri'`, `'require-trusted-types-for'`),
   * value is the array of sources.
   */
  custom?: Record<string, string[]>;
}

// ── HSTS ────────────────────────────────────────────────

/**
 * Strict-Transport-Security config. Pass `true` for safe defaults.
 */
export interface HSTSConfig {
  /** Max age in seconds. Default: `31536000` (1 year). */
  maxAge?: number;
  /** Include `includeSubDomains` directive. Default: `true`. */
  includeSubDomains?: boolean;
  /**
   * Include `preload` directive. Default: `false`.
   *
   * Only set to `true` if you've actually submitted the domain to
   * https://hstspreload.org — inclusion is hard to undo. Cloudflare's
   * "Always Use HTTPS" doesn't set this, for good reason.
   */
  preload?: boolean;
}

// ── Middleware ──────────────────────────────────────────

export interface SecurityHeadersConfig {
  /** Content-Security-Policy config. Pass `false` to skip the header entirely. Default: strict defaults. */
  csp?: CSPConfig | false;
  /** Strict-Transport-Security config. Pass `false` to skip, `true` for defaults. Default: `true`. */
  hsts?: HSTSConfig | boolean;
  /** Emit `X-Content-Type-Options: nosniff`. Default: `true`. */
  xContentTypeOptions?: boolean;
  /**
   * `X-Frame-Options` value. Legacy clickjacking defence, superseded by
   * `frame-ancestors` but kept for older browsers. Pass `false` to skip.
   *
   * Default: `'SAMEORIGIN'`.
   */
  xFrameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  /** `Referrer-Policy` value. Pass `false` to skip. Default: `'strict-origin-when-cross-origin'`. */
  referrerPolicy?: string | false;
  /**
   * `Permissions-Policy` value. Restricts access to browser features.
   * Pass `false` to skip.
   *
   * Default: `'camera=(), microphone=(), geolocation=()'` — a tight
   * baseline for admin surfaces. Extend if your app legitimately needs
   * these features.
   */
  permissionsPolicy?: string | false;
}

/**
 * Build a Content-Security-Policy header string.
 *
 * Pure function — no side effects. Useful for embedding CSP into
 * response shells rendered outside a request handler (e.g. a
 * static-file serve with custom headers).
 *
 * @param config Partial override of the default directive set.
 * @returns The serialised header value.
 */
export function buildCSP(config?: CSPConfig): string;

/**
 * Build a Strict-Transport-Security header string.
 *
 * @param config Passing `true` gives safe defaults (1yr + includeSubDomains).
 * @returns The serialised header value.
 */
export function buildHSTS(config?: HSTSConfig | true): string;

/**
 * Build the security headers as a plain object.
 *
 * For anywhere you need the values rather than a file: a `Response` you
 * construct yourself, or a test asserting on policy. Pass `false` for any
 * field to skip that specific header.
 *
 * @example
 * ```ts
 * return new Response(body, { headers: buildHeaders() });
 * ```
 *
 * @param config Partial override of the defaults.
 * @returns Header name → value.
 */
export function buildHeaders(config?: SecurityHeadersConfig): Record<string, string>;

export interface HeadersFileOptions { path?: string; }
export function headersFile(config?: SecurityHeadersConfig, options?: HeadersFileOptions): string;

