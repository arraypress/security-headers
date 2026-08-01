/**
 * @arraypress/security-headers — test suite.
 *
 * Split into five groups: `buildCSP` unit tests (no Hono), `buildHSTS`
 * unit tests, `securityHeaders` integration tests that fire in-memory requests
 * through a tiny Hono app and assert on the response headers, and framework-free
 * `buildHeaders` / `headersFile` unit tests for the static-host path.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Hono } from 'hono';
import { buildCSP, buildHSTS, securityHeaders, buildHeaders, headersFile } from '../src/index.js';

// ── buildCSP ───────────────────────────────────────────

describe('buildCSP defaults', () => {
  it('emits the full strict-default policy when called with no args', () => {
    const csp = buildCSP();
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /style-src 'self' 'unsafe-inline'/);
    assert.match(csp, /img-src 'self' data: https:/);
    assert.match(csp, /object-src 'none'/);
    assert.match(csp, /frame-ancestors 'self'/);
    assert.match(csp, /upgrade-insecure-requests$/);
  });

  it('separates directives with "; "', () => {
    const csp = buildCSP();
    assert.match(csp, /'self'; script-src/);
  });

  it('emits upgrade-insecure-requests last, without a value suffix', () => {
    const csp = buildCSP();
    assert.match(csp, /; upgrade-insecure-requests$/);
  });
});

describe('buildCSP overrides', () => {
  it('replaces defaults when arrays are provided', () => {
    const csp = buildCSP({
      scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
    });
    assert.match(csp, /script-src 'self' https:\/\/challenges\.cloudflare\.com/);
    // Other directives still have their defaults.
    assert.match(csp, /default-src 'self'/);
  });

  it('omits a directive when the array is empty', () => {
    const csp = buildCSP({ frameSrc: [] });
    assert.doesNotMatch(csp, /frame-src/);
  });

  it('omits upgrade-insecure-requests when disabled', () => {
    const csp = buildCSP({ upgradeInsecureRequests: false });
    assert.doesNotMatch(csp, /upgrade-insecure-requests/);
  });

  it('emits custom directives with raw names', () => {
    const csp = buildCSP({
      custom: {
        'report-uri': ['/csp-report'],
        'require-trusted-types-for': ["'script'"],
      },
    });
    assert.match(csp, /report-uri \/csp-report/);
    assert.match(csp, /require-trusted-types-for 'script'/);
  });

  it('emits directives in a stable order', () => {
    const a = buildCSP();
    const b = buildCSP();
    assert.equal(a, b);
  });
});

// ── buildHSTS ──────────────────────────────────────────

describe('buildHSTS', () => {
  it('defaults to 1 year + includeSubDomains, no preload', () => {
    assert.equal(buildHSTS(), 'max-age=31536000; includeSubDomains');
    assert.equal(buildHSTS(true), 'max-age=31536000; includeSubDomains');
  });

  it('emits preload when enabled', () => {
    const hsts = buildHSTS({ maxAge: 63072000, includeSubDomains: true, preload: true });
    assert.equal(hsts, 'max-age=63072000; includeSubDomains; preload');
  });

  it('can drop includeSubDomains', () => {
    assert.equal(buildHSTS({ includeSubDomains: false }), 'max-age=31536000');
  });

  it('accepts a custom max-age', () => {
    assert.equal(buildHSTS({ maxAge: 3600, includeSubDomains: false }), 'max-age=3600');
  });
});

// ── securityHeaders middleware ─────────────────────────

function buildApp(config) {
  const app = new Hono();
  app.use('*', securityHeaders(config));
  app.get('/', (c) => c.text('ok'));
  return app;
}

describe('securityHeaders defaults', () => {
  it('applies every default header on a GET response', async () => {
    const app = buildApp();
    const res = await app.request('/');

    assert.match(res.headers.get('content-security-policy') ?? '', /default-src 'self'/);
    assert.equal(res.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
    assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    assert.equal(res.headers.get('permissions-policy'), 'camera=(), microphone=(), geolocation=()');
  });
});

describe('securityHeaders overrides', () => {
  it('merges a CSP override into the strict defaults', async () => {
    const app = buildApp({
      csp: { scriptSrc: ["'self'", 'https://challenges.cloudflare.com'] },
    });
    const res = await app.request('/');
    const csp = res.headers.get('content-security-policy') ?? '';
    assert.match(csp, /script-src 'self' https:\/\/challenges\.cloudflare\.com/);
    assert.match(csp, /default-src 'self'/);
  });

  it('skips CSP entirely when csp: false', async () => {
    const app = buildApp({ csp: false });
    const res = await app.request('/');
    assert.equal(res.headers.get('content-security-policy'), null);
    // Other headers still applied.
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });

  it('skips HSTS when hsts: false', async () => {
    const app = buildApp({ hsts: false });
    const res = await app.request('/');
    assert.equal(res.headers.get('strict-transport-security'), null);
  });

  it('respects xFrameOptions: false', async () => {
    const app = buildApp({ xFrameOptions: false });
    const res = await app.request('/');
    assert.equal(res.headers.get('x-frame-options'), null);
  });

  it('allows DENY for xFrameOptions', async () => {
    const app = buildApp({ xFrameOptions: 'DENY' });
    const res = await app.request('/');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  });

  it('custom referrer policy replaces the default', async () => {
    const app = buildApp({ referrerPolicy: 'no-referrer' });
    const res = await app.request('/');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  });

  it('skips permissionsPolicy when false', async () => {
    const app = buildApp({ permissionsPolicy: false });
    const res = await app.request('/');
    assert.equal(res.headers.get('permissions-policy'), null);
  });

  it('skips xContentTypeOptions when false', async () => {
    const app = buildApp({ xContentTypeOptions: false });
    const res = await app.request('/');
    assert.equal(res.headers.get('x-content-type-options'), null);
  });

  it('applies to error responses too (runs after next)', async () => {
    const app = new Hono();
    app.use('*', securityHeaders());
    app.get('/boom', (c) => c.json({ error: 'x' }, 500));

    const res = await app.request('/boom');
    assert.equal(res.status, 500);
    assert.ok(res.headers.get('content-security-policy'));
    assert.ok(res.headers.get('strict-transport-security'));
  });
});

describe('securityHeaders performance', () => {
  it('pre-computes the CSP string once per middleware (not per request)', async () => {
    // Not directly observable, but we can at least confirm the same
    // middleware used across many requests emits identical headers.
    const app = buildApp({ csp: { scriptSrc: ["'self'"] } });
    const first = await app.request('/');
    const second = await app.request('/');
    assert.equal(
      first.headers.get('content-security-policy'),
      second.headers.get('content-security-policy'),
    );
  });
});

describe('buildHeaders', () => {
  it('returns the full default set', () => {
    const h = buildHeaders();
    assert.equal(h['X-Content-Type-Options'], 'nosniff');
    assert.equal(h['X-Frame-Options'], 'SAMEORIGIN');
    assert.equal(h['Referrer-Policy'], 'strict-origin-when-cross-origin');
    assert.ok(h['Content-Security-Policy'].includes("default-src 'self'"));
    assert.ok(h['Strict-Transport-Security'].includes('max-age='));
  });

  it('omits anything disabled with false', () => {
    const h = buildHeaders({ csp: false, hsts: false, xFrameOptions: false });
    assert.equal(h['Content-Security-Policy'], undefined);
    assert.equal(h['Strict-Transport-Security'], undefined);
    assert.equal(h['X-Frame-Options'], undefined);
    assert.equal(h['X-Content-Type-Options'], 'nosniff');
  });

  it('matches what the middleware sets', async () => {
    const app = new Hono();
    app.use('*', securityHeaders());
    app.get('/', (c) => c.text('ok'));
    const res = await app.request('/');
    for (const [k, v] of Object.entries(buildHeaders())) {
      assert.equal(res.headers.get(k), v, `${k} should match the middleware`);
    }
  });
});

describe('headersFile', () => {
  it('renders a _headers block with two-space indentation', () => {
    const out = headersFile();
    const lines = out.trimEnd().split('\n');
    assert.equal(lines[0], '/*');
    assert.ok(lines.slice(1).every((l) => l.startsWith('  ')));
    assert.ok(out.endsWith('\n'));
  });

  it('honours a custom path', () => {
    assert.ok(headersFile({}, { path: '/admin/*' }).startsWith('/admin/*\n'));
  });

  it('carries the same values as buildHeaders', () => {
    const out = headersFile({ csp: { scriptSrc: ["'self'"] } });
    const built = buildHeaders({ csp: { scriptSrc: ["'self'"] } });
    for (const [k, v] of Object.entries(built)) {
      assert.ok(out.includes(`  ${k}: ${v}`), `${k} should appear verbatim`);
    }
  });
});
