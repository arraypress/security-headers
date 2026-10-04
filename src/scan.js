/**
 * @arraypress/security-headers/scan
 *
 * Derive a Content-Security-Policy from a built static site instead of
 * writing one by hand.
 *
 * Two jobs:
 *
 *   1. HASH every inline `<script>` and `<style>` the build emitted, so the
 *      policy can drop `'unsafe-inline'` without breaking the theme
 *      flash-guard, the reveal bootstrap or a component's inline styles.
 *   2. FIND every third-party origin the pages load from (scripts,
 *      stylesheets, fonts, frames, form endpoints, media) and allow exactly
 *      those, plus the hosts known providers talk back to, plus any a
 *      component declares with `data-csp` for what it loads at runtime.
 *
 * Why site-wide rather than per page: the hashes are unioned across every
 * page into ONE policy. That is what lets this coexist with Astro's
 * `<ClientRouter />`, which Astro's own per-page `<meta>` CSP can't — the
 * router swaps pages in without reloading, so the policy the visitor's FIRST
 * page arrived with has to cover the inline code of every page they reach
 * after it. A union does; a per-page policy can't.
 *
 * Node-only (reads the filesystem, uses `node:crypto`). The main entry stays
 * framework- and runtime-free.
 *
 * @module @arraypress/security-headers/scan
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { cspDefaults } from './index.js';

/**
 * Hosts a provider talks to that the page itself never names.
 *
 * Keyed on an origin the scan DOES see (a stylesheet or script URL) and adding
 * the ones it can't. Only providers whose data goes somewhere OTHER than their
 * script's own origin need an entry: every third-party script origin is added
 * to `connect-src` automatically (see `autoCsp`), which already covers
 * Plausible, Fathom and any self-hosted tracker that beacons home.
 *
 * Hosts are from each provider's own CSP documentation.
 */
export const PROVIDERS = [
	/* Google Fonts: the stylesheet is on googleapis, the font files on gstatic. */
	{ match: 'https://fonts.googleapis.com', add: { fontSrc: ['https://fonts.gstatic.com'] } },
	/* GA4: gtag loads from www.googletagmanager.com and pulls more from the
	   regional subdomains, then beacons to google-analytics.com. */
	{
		match: 'https://www.googletagmanager.com',
		add: {
			scriptSrc: ['https://*.googletagmanager.com'],
			connectSrc: ['https://*.google-analytics.com', 'https://*.analytics.google.com', 'https://*.googletagmanager.com'],
		},
	},
	/* Cloudflare Web Analytics: script on static., beacon on the apex. */
	{ match: 'https://static.cloudflareinsights.com', add: { connectSrc: ['https://cloudflareinsights.com'] } },
	/* Simple Analytics: script on scripts., events on queue. */
	{ match: 'https://scripts.simpleanalyticscdn.com', add: { connectSrc: ['https://queue.simpleanalyticscdn.com'] } },
	/* GoatCounter: script on gc.zgo.at, counts go to <code>.goatcounter.com. */
	{ match: 'https://gc.zgo.at', add: { connectSrc: ['https://*.goatcounter.com'] } },
	/* Umami Cloud has collected through both hosts. */
	{ match: 'https://cloud.umami.is', add: { connectSrc: ['https://api-gateway.umami.dev'] } },
	/* Cloudflare Turnstile renders its challenge in a frame. */
	{ match: 'https://challenges.cloudflare.com', add: { frameSrc: ['https://challenges.cloudflare.com'] } },
];

/**
 * Directives a `data-csp` declaration may add to. Kebab-case on the wire,
 * camelCase in the result.
 */
const DECLARABLE = {
	'script-src': 'scriptSrc',
	'style-src': 'styleSrc',
	'font-src': 'fontSrc',
	'img-src': 'imgSrc',
	'media-src': 'mediaSrc',
	'frame-src': 'frameSrc',
	'form-action': 'formAction',
	'connect-src': 'connectSrc',
};

/** An https origin, optionally with a leading `*.` wildcard. Nothing else. */
const DECLARED_SOURCE = /^https:\/\/(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?\/?$/i;

/** Script `type`s the browser executes, and so the ones `script-src` governs. */
const EXECUTABLE = new Set(['', 'text/javascript', 'application/javascript', 'module', 'importmap', 'speculationrules']);

/**
 * The CSP hash token for a block of inline source.
 *
 * @param {string} text - The exact text between the tags.
 * @param {'sha256'|'sha384'|'sha512'} [algorithm='sha256']
 * @returns {string} e.g. `'sha256-abc…='` — quoted, ready for a directive.
 */
export function hashSource(text, algorithm = 'sha256') {
	return `'${algorithm}-${createHash(algorithm).update(text, 'utf8').digest('base64')}'`;
}

/**
 * Read one attribute from a tag's attribute string. Handles double, single and
 * UNQUOTED values — Astro's `compressHTML` emits `<script type=module>`.
 */
function attr(attrs, name) {
	const m = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i').exec(attrs);
	return m ? (m[1] ?? m[2] ?? m[3]) : undefined;
}

/** The origin of a third-party URL, or null for same-origin / non-http(s). */
function externalOrigin(url) {
	if (!url) return null;
	try {
		/* A relative URL resolves onto the sentinel and is same-origin by
		   definition; protocol-relative `//host` picks up https from it. */
		const u = new URL(url.trim(), 'https://same-origin.invalid/');
		if (u.host === 'same-origin.invalid') return null;
		return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null;
	} catch {
		return null;
	}
}

/**
 * An empty scan result, the shape `scanHtml` fills and `mergeScans` combines.
 *
 * @returns {import('./scan.d.ts').ScanResult}
 */
function emptyScan() {
	return {
		pages: 0,
		scripts: new Set(),
		styles: new Set(),
		sources: {
			scriptSrc: new Set(),
			styleSrc: new Set(),
			fontSrc: new Set(),
			imgSrc: new Set(),
			mediaSrc: new Set(),
			frameSrc: new Set(),
			formAction: new Set(),
			connectSrc: new Set(),
		},
		handlers: 0,
		jsUrls: 0,
		badDeclarations: [],
	};
}

/**
 * Scan one HTML document.
 *
 * @param {string} html - The page source.
 * @param {Object} [options]
 * @param {'sha256'|'sha384'|'sha512'} [options.algorithm='sha256']
 * @returns {import('./scan.d.ts').ScanResult}
 */
export function scanHtml(html, { algorithm = 'sha256' } = {}) {
	const out = emptyScan();
	out.pages = 1;
	const add = (directive, url) => {
		const origin = externalOrigin(url);
		if (origin) out.sources[directive].add(origin);
	};

	for (const [, attrs, body] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
		const src = attr(attrs, 'src');
		if (src !== undefined) {
			add('scriptSrc', src);
			continue;
		}
		/* JSON-LD and other data blocks never execute, so CSP doesn't apply. */
		if (!EXECUTABLE.has((attr(attrs, 'type') ?? '').toLowerCase())) continue;
		out.scripts.add(hashSource(body, algorithm));

		/* An inline LOADER — the analytics pattern — names its script only as a
		   string: `s=document.createElement('script'); s.src='https://…'`. The
		   tag it creates is never in the HTML, so read the URL out of the code.
		   Gated on createElement('script') so an `img.src` isn't mistaken for
		   a script source. */
		if (/createElement\(\s*['"`]script['"`]\s*\)/.test(body)) {
			for (const [, , url] of body.matchAll(/\.src\s*=\s*(['"`])((?:https?:)?\/\/[^'"`]+)\1/g)) add('scriptSrc', url);
		}
	}

	for (const [, , body] of html.matchAll(/<style\b([^>]*)>([\s\S]*?)<\/style\s*>/gi)) {
		out.styles.add(hashSource(body, algorithm));
	}

	for (const [tag, name, attrs] of html.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*)>/gi)) {
		const el = name.toLowerCase();
		if (el === 'link') {
			const rel = (attr(attrs, 'rel') ?? '').toLowerCase().split(/\s+/);
			const href = attr(attrs, 'href');
			if (rel.includes('stylesheet')) add('styleSrc', href);
			else if (rel.includes('modulepreload')) add('scriptSrc', href);
			else if (rel.includes('preload')) {
				const as = (attr(attrs, 'as') ?? '').toLowerCase();
				if (as === 'font') add('fontSrc', href);
				else if (as === 'style') add('styleSrc', href);
				else if (as === 'script') add('scriptSrc', href);
			}
		} else if (el === 'iframe') add('frameSrc', attr(attrs, 'src'));
		else if (el === 'form') add('formAction', attr(attrs, 'action'));
		else if (el === 'img') add('imgSrc', attr(attrs, 'src'));
		else if (el === 'video' || el === 'audio' || el === 'source' || el === 'track') {
			/* `<source srcset>` belongs to a <picture> and is an image. */
			if (attr(attrs, 'srcset') !== undefined && attr(attrs, 'src') === undefined) continue;
			add('mediaSrc', attr(attrs, 'src'));
		}

		/* A component that frames or fetches a host only at RUNTIME declares it
		   on its own element — `data-csp="frame-src https://www.youtube-nocookie.com"`
		   — because the scan can't see a URL that only exists once someone
		   clicks. Only https origins are accepted: a declaration can widen the
		   policy to a host, never to a keyword like 'unsafe-inline'. */
		const declared = attr(attrs, 'data-csp');
		if (declared) {
			for (const part of declared.split(';')) {
				const [directive, ...values] = part.trim().split(/\s+/);
				if (!directive) continue;
				const key = DECLARABLE[directive.toLowerCase()];
				if (!key || !values.length) {
					out.badDeclarations.push(part.trim());
					continue;
				}
				for (const v of values) {
					if (DECLARED_SOURCE.test(v)) out.sources[key].add(v.replace(/\/$/, ''));
					else out.badDeclarations.push(`${directive} ${v}`);
				}
			}
		}

		/* Things a hash-based policy will block and nothing can allow short of
		   'unsafe-inline' — counted so the build can say so out loud. */
		if (/\son[a-z]+\s*=/i.test(tag.slice(name.length + 1))) out.handlers++;
		if (/\shref\s*=\s*["']?\s*javascript:/i.test(attrs)) out.jsUrls++;
	}

	return out;
}

/**
 * Combine scans of several pages into one site-wide result.
 *
 * @param {import('./scan.d.ts').ScanResult[]} scans
 * @returns {import('./scan.d.ts').ScanResult}
 */
export function mergeScans(scans) {
	const out = emptyScan();
	for (const s of scans) {
		out.pages += s.pages;
		for (const h of s.scripts) out.scripts.add(h);
		for (const h of s.styles) out.styles.add(h);
		for (const [k, set] of Object.entries(s.sources)) for (const o of set) out.sources[k].add(o);
		out.handlers += s.handlers;
		out.jsUrls += s.jsUrls;
		for (const b of s.badDeclarations) if (!out.badDeclarations.includes(b)) out.badDeclarations.push(b);
	}
	return out;
}

/**
 * Scan every `.html` file under a directory — a build output folder.
 *
 * @param {string} dir - Absolute path, e.g. Astro's `dist/`.
 * @param {Object} [options] - Passed to `scanHtml`.
 * @returns {import('./scan.d.ts').ScanResult}
 */
export function scanDir(dir, options) {
	const files = [];
	const walk = (d) => {
		for (const entry of readdirSync(d, { withFileTypes: true })) {
			const p = join(d, entry.name);
			if (entry.isDirectory()) walk(p);
			else if (entry.name.endsWith('.html')) files.push(p);
		}
	};
	walk(dir);
	return mergeScans(files.map((f) => scanHtml(readFileSync(f, 'utf8'), options)));
}

/** True when a source list already admits any https origin. */
const allowsAnyHttps = (list) => list.some((v) => v === 'https:' || v === '*');

/**
 * Turn a scan into a CSP config for `buildCSP`.
 *
 * Every directive starts from YOUR array if you passed one, else the library
 * default — the same "arrays replace" rule as `buildCSP` — and the scan's
 * findings are ADDED on top. So `{ connectSrc: ["'self'", 'https://api.example.com'] }`
 * keeps your API and still picks up the analytics beacon the scan found.
 *
 * Two defaults change in auto mode, because hashes make them possible:
 *   - `style-src` drops `'unsafe-inline'` and carries the style hashes.
 *     (Browsers ignore `'unsafe-inline'` once a hash is present anyway, so
 *     leaving it in would only be misleading.)
 *   - `style-src-attr 'unsafe-inline'` is added. Hashes can't cover `style=""`
 *     ATTRIBUTES, and every component-driven site has them (custom-property
 *     plumbing, syntax highlighters). Attributes can't run script, so this is
 *     the conventional trade.
 *
 * If you put `'unsafe-inline'` in `scriptSrc` or `styleSrc` yourself, that
 * directive gets no hashes — per the CSP spec a hash would switch your
 * `'unsafe-inline'` off.
 *
 * @param {import('./scan.d.ts').ScanResult} scan
 * @param {import('./index.d.ts').CSPConfig} [config={}]
 * @returns {import('./index.d.ts').CSPConfig}
 */
export function autoCsp(scan, config = {}) {
	const { auto: _auto, ...overrides } = config;
	const base = { ...cspDefaults, styleSrc: ["'self'"], styleSrcAttr: ["'unsafe-inline'"] };
	/* A directive with no default of its own (media-src) falls back to
	   default-src in the browser, so it has to START from default-src here too —
	   otherwise naming one third-party video host would block your own files. */
	const fallback = overrides.defaultSrc ?? cspDefaults.defaultSrc;
	const pick = (key) => [...(overrides[key] ?? base[key] ?? fallback)];

	const out = { ...overrides };
	const directives = ['scriptSrc', 'styleSrc', 'fontSrc', 'imgSrc', 'mediaSrc', 'frameSrc', 'formAction', 'connectSrc'];
	const lists = Object.fromEntries(directives.map((k) => [k, pick(k)]));
	const push = (key, value) => {
		const list = lists[key];
		if (list.includes(value)) return;
		/* Don't name a host a wildcard already admits — it's noise in a header
		   with a 2,000-character line limit on Cloudflare. */
		if (/^https?:\/\//.test(value) && allowsAnyHttps(list)) return;
		list.push(value);
	};

	for (const [key, origins] of Object.entries(scan.sources)) for (const o of origins) push(key, o);

	/* A third-party script already has the run of the page; letting it also
	   CONNECT home adds no capability it didn't have. This one rule covers every
	   tracker that beacons to its own origin, self-hosted ones included. */
	for (const o of scan.sources.scriptSrc) push('connectSrc', o);

	const seen = new Set([...scan.sources.scriptSrc, ...scan.sources.styleSrc, ...scan.sources.frameSrc]);
	for (const p of PROVIDERS) {
		if (!seen.has(p.match)) continue;
		for (const [key, values] of Object.entries(p.add)) for (const v of values) push(key, v);
	}

	if (!lists.scriptSrc.includes("'unsafe-inline'")) for (const h of scan.scripts) push('scriptSrc', h);
	if (!lists.styleSrc.includes("'unsafe-inline'")) for (const h of scan.styles) push('styleSrc', h);

	for (const [key, list] of Object.entries(lists)) {
		/* Only write a fallback-derived directive when the scan added to it. */
		if (!(key in overrides) && !(key in base) && list.length === fallback.length) continue;
		out[key] = list;
	}
	if (!('styleSrcAttr' in overrides)) out.styleSrcAttr = base.styleSrcAttr;
	return out;
}
