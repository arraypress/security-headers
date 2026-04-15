# @arraypress/security-headers

Strict-by-default security response headers for Hono on edge runtimes (Cloudflare Workers, Deno, Bun, Node.js). Single middleware covers:

- **Content-Security-Policy** — builder with safe defaults tuned for Tailwind v4 + shadcn/ui admin SPAs
- **Strict-Transport-Security** — HSTS with 1-year max-age + `includeSubDomains` out of the box
- **X-Frame-Options** — legacy clickjacking defence (supersets CSP `frame-ancestors`)
- **X-Content-Type-Options** — `nosniff` to block MIME-type guessing
- **Referrer-Policy** — `strict-origin-when-cross-origin` by default
- **Permissions-Policy** — restrictive browser-feature gate (camera/mic/geolocation off)

Plus standalone `buildCSP()` and `buildHSTS()` helpers when you want the header string without the middleware (e.g. static-file serves, reverse-proxy config).

Zero runtime dependencies. Peer: `hono ^4.0.0`.

---

## Why

Configuring CSP by hand is how apps end up with `'unsafe-eval'` in production or a forgotten HSTS directive. This package bakes in the pattern that's been tuned across multiple `@arraypress` apps — every header togglable, every directive overridable, but always with a sensible baseline.

## Install

```bash
npm install @arraypress/security-headers
```

## Quick start

```ts
import { Hono } from 'hono';
import { securityHeaders } from '@arraypress/security-headers';

const app = new Hono();

app.use('*', securityHeaders({
  // Add Turnstile to the CAPTCHA-using script + frame allowlists.
  csp: {
    scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
    frameSrc:  ["'self'", 'https://challenges.cloudflare.com'],
  },
  // All other headers use strict defaults.
}));
```

## Default configuration

If you pass no config at all, here's what your responses will carry:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; upgrade-insecure-requests
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Why these specific defaults

- **`'unsafe-inline'` on `style-src`** — Tailwind v4 emits inline styles for arbitrary-value utilities (`[--foo:12]`) and Radix / shadcn primitives set inline positioning styles. Without this, the admin SPA visibly breaks. If your app doesn't use either, tighten with `styleSrc: ["'self'"]`.
- **`img-src 'self' data: https:`** — `data:` allows inline SVG / embedded base64 images; `https:` allows any HTTPS image source. Tighten with a specific allowlist if you host all images yourself.
- **`object-src 'none'`** — kills Flash / Java plugin vectors. Keep this restrictive unless you have a hard requirement.
- **`frame-ancestors 'self'`** — clickjacking defence. Supersedes `X-Frame-Options` on modern browsers, but we set both for belt-and-braces.
- **`upgrade-insecure-requests`** — auto-rewrites any `http://` ref to `https://` so a stray asset URL doesn't mixed-content-warn.
- **HSTS 1yr + includeSubDomains, no preload** — `preload` is hard to undo (inclusion requires manual submission to hstspreload.org). Opt in explicitly if you actually want it.

## CSP configuration

Every directive has a safe default. Pass only the ones you want to override — **arrays replace the default, they don't merge**. This is deliberate: CSP bugs are usually "I added X but forgot to include the baseline," and explicit replacement makes the full rule visible in one place.

```ts
securityHeaders({
  csp: {
    defaultSrc:  ["'self'"],
    scriptSrc:   ["'self'", 'https://challenges.cloudflare.com'],
    styleSrc:    ["'self'", "'unsafe-inline'"],
    imgSrc:      ["'self'", 'data:', 'https:'],
    fontSrc:     ["'self'"],
    connectSrc:  ["'self'"],
    frameSrc:    ["'self'", 'https://challenges.cloudflare.com'],
    formAction:  ["'self'"],
    baseUri:     ["'self'"],
    objectSrc:   ["'none'"],
    frameAncestors: ["'self'"],
    upgradeInsecureRequests: true,

    // For directives not covered above (e.g. report-uri):
    custom: {
      'report-uri': ['https://example.report-uri.com/a/d/g'],
      'require-trusted-types-for': ["'script'"],
    },
  },
});
```

Pass `csp: false` to skip the CSP header entirely — e.g. for an API-only Worker where the browser never renders responses.

## HSTS configuration

```ts
securityHeaders({
  hsts: {
    maxAge: 63072000,        // 2 years (preload-list requirement)
    includeSubDomains: true,
    preload: true,            // only after submitting to hstspreload.org
  },
});
```

Pass `hsts: true` for the defaults (1yr, includeSubDomains, no preload), or `hsts: false` to skip HSTS entirely.

## Standalone builders

Use these when you need the header string without the middleware:

```ts
import { buildCSP, buildHSTS } from '@arraypress/security-headers';

// E.g. for a static Response with custom headers:
const csp = buildCSP({ scriptSrc: ["'self'"] });
const hsts = buildHSTS({ maxAge: 31536000 });

return new Response(html, {
  headers: {
    'Content-Type': 'text/html',
    'Content-Security-Policy': csp,
    'Strict-Transport-Security': hsts,
  },
});
```

## Toggling individual headers

Pass `false` for any field to skip it:

```ts
securityHeaders({
  csp: false,                  // no CSP at all
  hsts: false,                 // no HSTS at all
  xFrameOptions: false,        // no X-Frame-Options (rely on CSP frame-ancestors only)
  xContentTypeOptions: true,   // keep nosniff
  referrerPolicy: 'no-referrer',
  permissionsPolicy: false,    // no Permissions-Policy
});
```

## Full configuration reference

### `SecurityHeadersConfig`

| Field | Default | Description |
|---|---|---|
| `csp` | Strict defaults (see above) | CSP config, or `false` to skip. |
| `hsts` | `true` (1yr + includeSubDomains) | HSTS config, or `true` / `false`. |
| `xContentTypeOptions` | `true` | Emit `X-Content-Type-Options: nosniff`. |
| `xFrameOptions` | `'SAMEORIGIN'` | `'DENY'` / `'SAMEORIGIN'` / `false`. |
| `referrerPolicy` | `'strict-origin-when-cross-origin'` | Any valid Referrer-Policy, or `false`. |
| `permissionsPolicy` | `'camera=(), microphone=(), geolocation=()'` | Any valid Permissions-Policy, or `false`. |

### `CSPConfig`

| Directive | Default | Notes |
|---|---|---|
| `defaultSrc` | `["'self'"]` | Fallback for anything not explicitly set. |
| `scriptSrc` | `["'self'"]` | Add CDN origins for external scripts. |
| `styleSrc` | `["'self'", "'unsafe-inline'"]` | Drop `'unsafe-inline'` if your app doesn't need Tailwind v4 arbitrary values or Radix inline positioning. |
| `imgSrc` | `["'self'", 'data:', 'https:']` | Tighten with specific origins when possible. |
| `fontSrc` | `["'self'"]` | Add CDN origins for web fonts. |
| `connectSrc` | `["'self'"]` | Add API origins for `fetch` / XHR. |
| `frameSrc` | `["'self'"]` | Allowed iframe sources (CAPTCHAs, embeds). |
| `formAction` | `["'self'"]` | Allowed `<form action>` targets. |
| `baseUri` | `["'self'"]` | Allowed `<base href>` origins. |
| `objectSrc` | `["'none'"]` | Keep at `'none'` unless you really need plugins. |
| `frameAncestors` | `["'self'"]` | Who can frame you. Supersets `X-Frame-Options`. |
| `upgradeInsecureRequests` | `true` | Auto-rewrite http:// → https://. |
| `custom` | `undefined` | Map of raw directive name → values for anything not first-class. |

### `HSTSConfig`

| Field | Default | Description |
|---|---|---|
| `maxAge` | `31536000` | Seconds. `63072000` (2yr) is required for preload-list eligibility. |
| `includeSubDomains` | `true` | Apply HSTS to all subdomains. |
| `preload` | `false` | Emit `preload` directive. **Only set after submitting to hstspreload.org** — inclusion is hard to undo. |

## Patterns

### Adding Cloudflare Turnstile / reCAPTCHA

Both CAPTCHA providers need their CDN on `script-src` and `frame-src`:

```ts
securityHeaders({
  csp: {
    scriptSrc: ["'self'", 'https://challenges.cloudflare.com'],
    frameSrc:  ["'self'", 'https://challenges.cloudflare.com'],
  },
});
```

Google reCAPTCHA uses `https://www.google.com` instead.

### Allowing Stripe checkout

```ts
securityHeaders({
  csp: {
    scriptSrc: ["'self'", 'https://js.stripe.com'],
    frameSrc:  ["'self'", 'https://js.stripe.com', 'https://hooks.stripe.com'],
    connectSrc: ["'self'", 'https://api.stripe.com'],
  },
});
```

### Report-only mode

For testing a tightened policy without breaking the app, use `custom`:

```ts
// Apply the strict policy as reporting-only, keep the lenient one as enforced.
app.use('*', securityHeaders({ csp: { /* lenient live policy */ } }));
app.use('*', async (c, next) => {
  await next();
  c.header('Content-Security-Policy-Report-Only',
    buildCSP({ /* stricter trial policy */, custom: { 'report-uri': ['/csp-report'] } })
  );
});
```

### Non-admin API Worker

If your Worker serves only JSON to trusted clients, CSP + XFO don't buy you much:

```ts
app.use('*', securityHeaders({
  csp: false,
  xFrameOptions: false,
  // Keep HSTS + nosniff — always useful.
}));
```

## Security notes

- **CSP doesn't protect against CSRF** — you need a separate token or `X-Requested-With` check. See `@arraypress/admin-auth` for one.
- **HSTS only takes effect after the first TLS response** — a user's first insecure HTTP request to the domain is still vulnerable to TLS-stripping attacks. That's why `preload` exists (gets it into the browser's built-in list).
- **`frame-ancestors` is the modern clickjacking defence** — `X-Frame-Options` is legacy but both are set for older browsers.
- **`'unsafe-inline'` on `style-src` is NOT equivalent to `'unsafe-inline'` on `script-src`** — inline styles are much lower risk than inline scripts. Don't let CSP-purity arguments push you into breaking Tailwind.
- **`report-uri` has largely been replaced by `report-to`** — if you're collecting violations, check your reporting endpoint's requirements.

## License

MIT
