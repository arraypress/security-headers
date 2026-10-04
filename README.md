# @arraypress/security-headers

> Security response headers for static hosts — CSP, HSTS, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. Generates a Cloudflare/Netlify `_headers` file, with an Astro integration that derives a strict, hash-based CSP from the finished build. Zero dependencies.

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
  integrations: [headers({ csp: 'auto' })],
});
```

The integration writes `_headers` on `astro:build:done`, so there's no separate
build script to remember. With `csp: 'auto'` it reads the finished pages first:

```
[@arraypress/security-headers] CSP from 50 pages — 5 inline script hashes, 8 inline style hashes, 1 third-party origin (https://fonts.googleapis.com)
[@arraypress/security-headers] wrote _headers — 8 headers on /*
```

### What `csp: 'auto'` does

It scans every built `.html` file and writes one site-wide policy:

- **Hashes every inline `<script>` and `<style>`**, so `script-src` needs no
  `'unsafe-inline'` — the theme flash-guard, a `define:vars` block and a
  component's inline styles all keep working. JSON-LD isn't hashed; data
  blocks don't execute.
- **Allows exactly the third-party origins the pages load from**: script and
  stylesheet URLs, font preloads, iframes, form `action`s, media. Including
  scripts an inline *loader* injects (`createElement('script')` + `.src = '…'`,
  the pattern analytics snippets use), which never appear as a tag in the HTML.
- **Adds the hosts known providers talk back to** that the page never names:
  Google Fonts' `fonts.gstatic.com`, GA4's collection hosts, Cloudflare Web
  Analytics, Simple Analytics, GoatCounter, Umami Cloud, Turnstile's frame.
  Every third-party script origin also gets `connect-src` — a script you
  already run can reach its own origin anyway — which covers any tracker
  that beacons home, self-hosted ones included.
- **Allows `style=""` attributes** (`style-src-attr 'unsafe-inline'`). Hashes
  can't cover attributes, every component-driven site has them, and an
  attribute can't run script.

So turning on an analytics provider or pointing a form at Formspree needs no
CSP edit: rebuild, and it's in the policy.

What the scan can't see, you add. Arrays you pass are the base and the scan's
findings go on top:

```js
headers({
  csp: { auto: true, connectSrc: ["'self'", 'https://api.example.com'] },
})
```

Trial it before enforcing with `cspReportOnly: 'auto'`, which sends the same
policy as `Content-Security-Policy-Report-Only`.

### Why not Astro's `security.csp`

Astro's own CSP is a per-page `<meta>` tag, and it doesn't support
`<ClientRouter />`. The router swaps pages in without a reload, so the policy
the visitor's *first* page arrived with must cover the inline code of every
page they reach after it — a per-page policy can't. `'auto'` unions the hashes
across the whole build into one header, so a soft navigation never lands on
code the policy doesn't know. It also runs as a real HTTP header, which a
`<meta>` CSP can't fully replace (`frame-ancestors` is ignored in `<meta>`).

If you're not using the router, Astro's `security.csp` is a fine choice: leave
`csp` at its default `false` here and this writes everything else.

### What a hash policy blocks

Two things no hash can allow. The build warns if it finds either, because in
the browser they fail silently:

- inline event handlers — `onclick="…"`. Move them into a script.
- `href="javascript:…"` links.

### Limits

- **Cloudflare caps each `_headers` line at 2,000 characters**, and the CSP is
  one line. Each hash costs ~54. The build warns past the limit; the usual fix
  is `build.inlineStylesheets: 'never'`, which moves component CSS out of
  inline `<style>` blocks into files.
- **Vercel doesn't read `_headers`.** Cloudflare Pages and Netlify do.
- A `_headers` already in the build (copied from `public/`) is kept and this is
  appended to it. If both set the same header, the build says so — both would
  be sent.

### Why a file and not middleware

On Cloudflare, a static-assets deploy with no server script serves requests for
free. Adding middleware to set headers adds a script and makes every request
billable. `_headers` is applied at the edge for nothing.

### Options

`headers(config?, options?)`

- `config` — a `SecurityHeadersConfig` (below), where `csp` and
  `cspReportOnly` also accept `'auto'` or `{ auto: true, … }`. `csp` defaults
  to `false` here.
- `options.path` — path pattern the headers apply to. Default `'/*'`.
- `options.filename` — output name. Default `'_headers'`.

Cloudflare caps a `_headers` file at 100 rules; one path costs one rule however
many headers it carries.

### The scanner on its own

`@arraypress/security-headers/scan` is the same machinery without Astro —
point it at any static build:

```js
import { scanDir, autoCsp } from '@arraypress/security-headers/scan';
import { headersFile } from '@arraypress/security-headers';

const csp = autoCsp(scanDir('dist'));
writeFileSync('dist/_headers', headersFile({ csp }));
```

`scanHtml(html)`, `mergeScans(scans)`, `hashSource(text)` and the `PROVIDERS`
table are exported too. Node only.

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
  Cross-Origin-Opener-Policy: same-origin
  X-Permitted-Cross-Domain-Policies: none
  Content-Security-Policy: default-src 'self'; script-src 'self'; …
  Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Under the Astro integration the CSP line is absent unless you set `csp` — `'auto'` is the usual choice.

## Configuration

| Option | Default | Notes |
|---|---|---|
| `csp` | strict defaults | `CSPConfig` or `false`. Defaults to `false` in the Astro integration. |
| `cspReportOnly` | `false` | A stricter policy sent as `…-Report-Only`, to trial before enforcing. |
| `hsts` | `true` | `HSTSConfig`, `true` for defaults, or `false` to skip. |
| `xContentTypeOptions` | `true` | Emits `nosniff`. |
| `xFrameOptions` | `'SAMEORIGIN'` | `'DENY'`, `'SAMEORIGIN'` or `false`. |
| `referrerPolicy` | `'strict-origin-when-cross-origin'` | Any policy string, or `false`. |
| `permissionsPolicy` | `camera=(), microphone=(), geolocation=()` | Any policy string, or `false`. |
| `crossOriginOpenerPolicy` | `'same-origin'` | Use `'same-origin-allow-popups'` for OAuth popups. |
| `crossOriginEmbedderPolicy` | `false` | `'require-corp'` / `'credentialless'`. See isolation below. |
| `crossOriginResourcePolicy` | `false` | `'same-origin'` / `'same-site'` / `'cross-origin'`. |
| `permittedCrossDomainPolicies` | `'none'` | Legacy Flash/Acrobat `crossdomain.xml` opt-out. |
| `originAgentCluster` | `false` | Emits `Origin-Agent-Cluster: ?1`. |
| `reportingEndpoints` | `null` | `{ csp: 'https://…' }` → `Reporting-Endpoints`. |

Every header is independently togglable — pass `false` to skip it.

### Cross-origin isolation

`Cross-Origin-Opener-Policy` is on by default: it severs `window.opener` across
origins and needs nothing from the resources you load, so it costs you nothing.
The one gotcha is OAuth popups that talk back via `window.opener` — those want
`'same-origin-allow-popups'`.

`Cross-Origin-Embedder-Policy` and `Cross-Origin-Resource-Policy` are **off** by
default, deliberately. COEP blocks every cross-origin resource that hasn't opted
in, and CORP stops other sites embedding your images and fonts. Turn them on
together, with COOP `'same-origin'`, when you actually need `crossOriginIsolated`
— that is, `SharedArrayBuffer` or wasm threads:

```js
headers({
  crossOriginOpenerPolicy: 'same-origin',
  crossOriginEmbedderPolicy: 'require-corp',
  crossOriginResourcePolicy: 'same-origin',
})
```

An app using AudioWorklets or Workers does **not** need this on its own — only
shared memory does.

### Rolling out a CSP

Send a strict policy as report-only alongside a permissive enforced one, watch
the reports, then promote it:

```js
headers({
  csp: { scriptSrc: ["'self'", "'unsafe-inline'"] },   // enforced today
  cspReportOnly: { scriptSrc: ["'self'"] },             // the goal
  reportingEndpoints: { csp: 'https://example.com/csp-report' },
})
```

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

## Gotchas

Two defaults are strict on purpose and will bite if your site is the exception.
Both fail *silently* in the browser, so they're worth knowing before you deploy.

### The microphone and camera are off

`Permissions-Policy` defaults to `camera=(), microphone=(), geolocation=()`,
which disables `getUserMedia()` outright — the call rejects, and nothing in your
own code looks wrong. Right for a marketing or directory site; wrong for an app
that records audio.

```js
// An app with a record-from-mic button:
headers({ permissionsPolicy: 'camera=(), microphone=(self), geolocation=()' })
```

### The default CSP blocks Google Fonts

`font-src` defaults to `'self'` and `style-src` to `'self' 'unsafe-inline'`, so
a `<link>` to `fonts.googleapis.com` and the files it pulls from
`fonts.gstatic.com` are both blocked:

```js
headers({
  csp: {
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
  },
})
```

The same applies to any third-party origin — analytics, embeds, a CDN. The
default assumes a site that serves everything itself; add origins as you add
dependencies rather than loosening `default-src`.

Under the Astro integration's `csp: 'auto'` this one doesn't arise — the scan
finds the stylesheet and adds `fonts.gstatic.com` itself.

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
