# @arraypress/security-headers

> Security response headers for static hosts — CSP, HSTS, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. Generates a Cloudflare/Netlify `_headers` file, with an Astro integration. Zero dependencies.

## Install

```bash
npm install @arraypress/security-headers
```

## Astro

```js
// astro.config.mjs
import { defineConfig } from 'astro/config';
import headers from '@arraypress/security-headers/astro';

export default defineConfig({
  security: { csp: true },    // Astro owns CSP — see below
  integrations: [headers()],   // everything else, written to dist/_headers
});
```

The integration writes `_headers` on `astro:build:done`, so there's no separate
build script to remember. It logs what it wrote:

```
[@arraypress/security-headers] wrote _headers — 5 headers on /*
```

### Why a file and not middleware

On Cloudflare, a static-assets deploy with no server script serves requests for
free. Adding middleware to set headers adds a script and makes every request
billable. `_headers` is applied at the edge for nothing.

### Why CSP defaults to off here

Astro has its own `security.csp`, and it can hash the inline `<script>` and
`<style>` blocks Astro itself emits — the theme flash-guard, scoped component
styles. A static `_headers` file can't hash them, so expressing the same policy
there means `'unsafe-inline'` on both directives, which is most of what CSP was
protecting you from.

So Astro owns CSP, and this owns what Astro doesn't do: HSTS,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`,
`X-Content-Type-Options`.

Opt back in — for a host where Astro's CSP isn't in play:

```js
integrations: [headers({ csp: { defaultSrc: ["'self'"] } })]
```

### Options

`headers(config?, options?)`

- `config` — a `SecurityHeadersConfig` (below). `csp` defaults to `false` here.
- `options.path` — path pattern the headers apply to. Default `'/*'`.
- `options.filename` — output name. Default `'_headers'`.

Cloudflare caps a `_headers` file at 100 rules; one path costs one rule however
many headers it carries.

## Anywhere else

The generators are plain functions with no framework attached — use them from a
build script, a Worker, or a test.

```js
import { headersFile, buildHeaders, buildCSP, buildHSTS } from '@arraypress/security-headers';

// A _headers file, as a string.
writeFileSync('dist/_headers', headersFile({ csp: { scriptSrc: ["'self'"] } }));

// The same values as a plain object — for a Response you build yourself.
return new Response(body, { headers: buildHeaders() });

// Or one header at a time.
buildCSP({ defaultSrc: ["'self'"] });
buildHSTS({ maxAge: 31536000, includeSubDomains: true });
```

`headersFile()` renders the Cloudflare/Netlify format — a path line, then each
header indented two spaces:

```
/*
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## Configuration

| Option | Default | Notes |
|---|---|---|
| `csp` | strict defaults | `CSPConfig` or `false`. Defaults to `false` in the Astro integration. |
| `hsts` | `true` | `HSTSConfig`, `true` for defaults, or `false` to skip. |
| `xContentTypeOptions` | `true` | Emits `nosniff`. |
| `xFrameOptions` | `'SAMEORIGIN'` | `'DENY'`, `'SAMEORIGIN'` or `false`. |
| `referrerPolicy` | `'strict-origin-when-cross-origin'` | Any policy string, or `false`. |
| `permissionsPolicy` | `camera=(), microphone=(), geolocation=()` | Any policy string, or `false`. |

Every header is independently togglable — pass `false` to skip it.

CSP directives are camelCase and become kebab-case on the wire:
`defaultSrc`, `scriptSrc`, `styleSrc`, `imgSrc`, `fontSrc`, `connectSrc`,
`frameSrc`, and the rest.

```js
buildHeaders({
  csp: { scriptSrc: ["'self'", 'https://challenges.cloudflare.com'] },
  xFrameOptions: 'DENY',
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  permissionsPolicy: false,
});
```

## Security notes

`X-Frame-Options` is superseded by CSP's `frame-ancestors` but is still emitted
for older browsers — they don't cost each other anything.

The `Permissions-Policy` default is a tight baseline suited to admin surfaces.
If your site legitimately uses the camera, microphone or geolocation, extend it
rather than dropping the header.

HSTS only takes effect over HTTPS, and `preload` is a one-way door — browsers
cache it for a long time, so don't enable it until you're certain every
subdomain can serve HTTPS.

## License

MIT
