/**
 * @arraypress/security-headers — test suite.
 *
 * Four groups, all framework-free: `buildCSP` and `buildHSTS` unit tests, and
 * `buildHeaders` / `headersFile` tests covering the static-host path — the
 * `_headers` file a Cloudflare Pages or Netlify deploy serves at the edge.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildCSP, buildHSTS, buildHeaders, headersFile } from '../src/index.js';

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

describe('cross-origin and legacy headers', () => {
  it('sets COOP by default but not COEP or CORP', () => {
    const h = buildHeaders();
    assert.equal(h['Cross-Origin-Opener-Policy'], 'same-origin');
    assert.equal(h['Cross-Origin-Embedder-Policy'], undefined);
    assert.equal(h['Cross-Origin-Resource-Policy'], undefined);
  });
  /* COEP breaks every cross-origin resource that hasn't opted in, so it is
   * only worth turning on when crossOriginIsolated is actually needed. */
  it('enables the isolation pair on request', () => {
    const h = buildHeaders({ crossOriginEmbedderPolicy: 'require-corp', crossOriginResourcePolicy: 'same-origin' });
    assert.equal(h['Cross-Origin-Embedder-Policy'], 'require-corp');
    assert.equal(h['Cross-Origin-Resource-Policy'], 'same-origin');
  });
  it('allows relaxing COOP for OAuth popups', () => {
    assert.equal(buildHeaders({ crossOriginOpenerPolicy: 'same-origin-allow-popups' })['Cross-Origin-Opener-Policy'],
      'same-origin-allow-popups');
  });
  it('sets X-Permitted-Cross-Domain-Policies to none by default', () => {
    assert.equal(buildHeaders()['X-Permitted-Cross-Domain-Policies'], 'none');
  });
  it('omits Origin-Agent-Cluster unless asked', () => {
    assert.equal(buildHeaders()['Origin-Agent-Cluster'], undefined);
    assert.equal(buildHeaders({ originAgentCluster: true })['Origin-Agent-Cluster'], '?1');
  });
  it('skips any of them with false', () => {
    const h = buildHeaders({ crossOriginOpenerPolicy: false, permittedCrossDomainPolicies: false });
    assert.equal(h['Cross-Origin-Opener-Policy'], undefined);
    assert.equal(h['X-Permitted-Cross-Domain-Policies'], undefined);
  });
});

describe('CSP reporting', () => {
  it('sends report-only alongside the enforced policy', () => {
    const h = buildHeaders({ cspReportOnly: { defaultSrc: ["'none'"] } });
    assert.ok(h['Content-Security-Policy'], 'enforced policy still present');
    assert.ok(h['Content-Security-Policy-Report-Only'].includes("default-src 'none'"));
  });
  it('omits report-only by default', () => {
    assert.equal(buildHeaders()['Content-Security-Policy-Report-Only'], undefined);
  });
  it('renders Reporting-Endpoints in the documented format', () => {
    const h = buildHeaders({ reportingEndpoints: { csp: 'https://x.com/r', default: 'https://x.com/d' } });
    assert.equal(h['Reporting-Endpoints'], 'csp="https://x.com/r", default="https://x.com/d"');
  });
});

// ── Astro integration ──────────────────────────────────

import integration from '../src/astro.js';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * Run the integration's build:done hook against a throwaway directory,
 * optionally seeded with files (a built page, a `_headers` from public/).
 */
function runBuild(config, options, files = {}) {
  const root = mkdtempSync(join(tmpdir(), 'sh-'));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(root, name), text);
  const dir = pathToFileURL(join(root, '/'));
  const logs = [];
  const warnings = [];
  const it = integration(config, options);
  it.hooks['astro:build:done']({ dir, logger: { info: (m) => logs.push(m), warn: (m) => warnings.push(m) } });
  const name = options?.filename ?? '_headers';
  return { body: readFileSync(new URL(name, dir), 'utf8'), logs, warnings };
}

describe('astro integration', () => {
  it('writes _headers on build:done', () => {
    const { body } = runBuild();
    const lines = body.trimEnd().split('\n');
    assert.equal(lines[0], '/*');
    assert.ok(lines.some((l) => l.includes('X-Frame-Options: SAMEORIGIN')));
    assert.ok(lines.some((l) => l.includes('Strict-Transport-Security')));
  });

  /* Astro's own security.csp hashes the inline blocks Astro emits, so it beats
   * anything a static file can express without 'unsafe-inline'. The integration
   * must stay out of its way unless asked. */
  it('omits CSP by default, leaving it to Astro', () => {
    assert.ok(!runBuild().body.includes('Content-Security-Policy'));
  });

  it('emits CSP when explicitly configured', () => {
    const { body } = runBuild({ csp: { defaultSrc: ["'self'"] } });
    assert.ok(body.includes("Content-Security-Policy: default-src 'self'"));
  });

  it('honours path and filename', () => {
    const { body } = runBuild({}, { path: '/assets/*', filename: '_headers.txt' });
    assert.equal(body.trimEnd().split('\n')[0], '/assets/*');
  });

  it('reports what it wrote', () => {
    const { logs } = runBuild();
    assert.match(logs[0], /wrote _headers — \d+ headers on \/\*/);
  });

  it("csp: 'auto' hashes the built pages' inline code", () => {
    const { body, logs } = runBuild({ csp: 'auto' }, {}, { 'index.html': '<script>boot()</script><style>a{}</style>' });
    assert.match(body, /Content-Security-Policy: [^\n]*script-src 'self' 'sha256-/);
    assert.match(body, /style-src-attr 'unsafe-inline'/);
    assert.match(logs[0], /CSP from 1 pages — 1 inline script hash, 1 inline style hash, 0 third-party origins/);
  });

  it("cspReportOnly: 'auto' trials the same policy without enforcing it", () => {
    const { body } = runBuild({ cspReportOnly: 'auto' }, {}, { 'index.html': '<script>boot()</script>' });
    assert.match(body, /Content-Security-Policy-Report-Only: [^\n]*'sha256-/);
    assert.doesNotMatch(body, /Content-Security-Policy: /);
  });

  it('warns about inline handlers the policy will block', () => {
    const { warnings } = runBuild({ csp: 'auto' }, {}, { 'index.html': '<button onclick="x()">x</button>' });
    assert.match(warnings[0], /1 element\(s\) use an inline on\*= handler/);
  });

  /* Astro copies public/_headers into the build first; cache rules in it must
   * survive. */
  it('appends to a _headers already in the build', () => {
    const { body, warnings } = runBuild({}, {}, { _headers: '/_astro/*\n  Cache-Control: public, max-age=31536000, immutable\n' });
    assert.match(body, /^\/_astro\/\*\n  Cache-Control: [^\n]+\n\n\/\*\n/);
    assert.equal(warnings.length, 0);
  });

  it('warns when public/_headers sets a header it also writes', () => {
    const { warnings } = runBuild({}, {}, { _headers: '/*\n  X-Frame-Options: DENY\n' });
    assert.match(warnings[0], /already sets X-Frame-Options/);
  });

  it("warns past Cloudflare's 2,000-character line limit", () => {
    const pages = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`p${i}.html`, `<script>f${i}()</script>`]));
    const { warnings } = runBuild({ csp: 'auto' }, {}, pages);
    assert.ok(warnings.some((w) => /exceed Cloudflare's 2000-character/.test(w)));
  });

  it('names itself for the Astro integration list', () => {
    assert.equal(integration().name, '@arraypress/security-headers');
  });
});

// ── Documented escape hatches ──────────────────────────
//
// The strict defaults break two things a real site tends to need. These assert
// the fixes the README gives actually work, so the docs can't drift from them.

describe('gotcha: microphone access', () => {
  it('blocks getUserMedia by default', () => {
    assert.match(buildHeaders()['Permissions-Policy'], /microphone=\(\)/);
  });
  it('can be reopened for an app that records', () => {
    const h = buildHeaders({ permissionsPolicy: 'camera=(), microphone=(self), geolocation=()' });
    assert.match(h['Permissions-Policy'], /microphone=\(self\)/);
  });
});

describe('gotcha: Google Fonts', () => {
  it('blocks them by default', () => {
    const csp = buildCSP();
    assert.ok(!csp.includes('fonts.googleapis.com'));
    assert.ok(!csp.includes('fonts.gstatic.com'));
  });
  it('allows them when both directives are extended', () => {
    const csp = buildCSP({
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
    });
    assert.match(csp, /style-src[^;]*https:\/\/fonts\.googleapis\.com/);
    assert.match(csp, /font-src[^;]*https:\/\/fonts\.gstatic\.com/);
  });
});
