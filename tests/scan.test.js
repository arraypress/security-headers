/**
 * @arraypress/security-headers/scan — test suite.
 *
 * The scanner reads a built site and the policy it produces is only as good as
 * what it notices, so most of these pin down a thing it must SEE (an unquoted
 * attribute, a loader's string URL) or must IGNORE (JSON-LD, a picture's
 * srcset, a same-origin path).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { autoCsp, hashSource, mergeScans, scanDir, scanHtml } from '../src/scan.js';
import { buildCSP } from '../src/index.js';

const sha = (t) => `'sha256-${createHash('sha256').update(t).digest('base64')}'`;

// ── hashing ────────────────────────────────────────────

describe('hashSource', () => {
	it('matches the CSP hash of the exact text, quoted', () => {
		assert.equal(hashSource("alert('x')"), sha("alert('x')"));
	});

	it('supports sha384', () => {
		assert.match(hashSource('x', 'sha384'), /^'sha384-/);
	});
});

// ── scanHtml: inline blocks ────────────────────────────

describe('scanHtml inline blocks', () => {
	it('hashes inline scripts, including unquoted type=module', () => {
		const s = scanHtml('<script>a()</script><script type=module>b()</script>');
		assert.deepEqual([...s.scripts], [sha('a()'), sha('b()')]);
	});

	it('ignores JSON-LD and other data blocks', () => {
		const s = scanHtml('<script type="application/ld+json">{"@type":"Thing"}</script>');
		assert.equal(s.scripts.size, 0);
	});

	it('does not hash a script with src', () => {
		const s = scanHtml('<script src="/_astro/x.js"></script>');
		assert.equal(s.scripts.size, 0);
	});

	it('hashes inline styles, preserving whitespace exactly', () => {
		const s = scanHtml('<style id="p">\n:root{--a:1}\n</style>');
		assert.deepEqual([...s.styles], [sha('\n:root{--a:1}\n')]);
	});

	it('dedupes the same block across a page', () => {
		const s = scanHtml('<script>a()</script><script>a()</script>');
		assert.equal(s.scripts.size, 1);
	});
});

// ── scanHtml: origins ──────────────────────────────────

describe('scanHtml origins', () => {
	it('records third-party origins by directive', () => {
		const s = scanHtml(`
			<script src="https://cdn.example.com/a.js"></script>
			<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
			<link rel="preload" as="font" href="https://fonts.example.com/f.woff2" crossorigin>
			<iframe src="https://www.youtube-nocookie.com/embed/x"></iframe>
			<form action="https://formspree.io/f/abc" method="post"></form>
			<video src="https://media.example.com/v.mp4"></video>
		`);
		assert.deepEqual([...s.sources.scriptSrc], ['https://cdn.example.com']);
		assert.deepEqual([...s.sources.styleSrc], ['https://fonts.googleapis.com']);
		assert.deepEqual([...s.sources.fontSrc], ['https://fonts.example.com']);
		assert.deepEqual([...s.sources.frameSrc], ['https://www.youtube-nocookie.com']);
		assert.deepEqual([...s.sources.formAction], ['https://formspree.io']);
		assert.deepEqual([...s.sources.mediaSrc], ['https://media.example.com']);
	});

	it('ignores same-origin and relative URLs', () => {
		const s = scanHtml('<script src="/_astro/a.js"></script><link rel=stylesheet href="./x.css"><form action="/api/contact"></form>');
		assert.equal(s.sources.scriptSrc.size, 0);
		assert.equal(s.sources.styleSrc.size, 0);
		assert.equal(s.sources.formAction.size, 0);
	});

	it('does not treat a preconnect hint as a source', () => {
		const s = scanHtml('<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>');
		assert.equal(s.sources.fontSrc.size, 0);
	});

	it("reads a loader's script URL out of inline code", () => {
		const s = scanHtml(`<script>if(ok){var s=document.createElement('script');s.defer=true;s.src="https://plausible.io/js/script.js";document.head.appendChild(s);}</script>`);
		assert.deepEqual([...s.sources.scriptSrc], ['https://plausible.io']);
	});

	it('resolves a protocol-relative loader URL to https', () => {
		const s = scanHtml(`<script>var s=document.createElement('script');s.src='//gc.zgo.at/count.js';</script>`);
		assert.deepEqual([...s.sources.scriptSrc], ['https://gc.zgo.at']);
	});

	it('does not mistake an image .src for a script source', () => {
		const s = scanHtml(`<script>var i=new Image();i.src='https://pixel.example.com/p.gif';</script>`);
		assert.equal(s.sources.scriptSrc.size, 0);
	});

	it("skips a <picture>'s srcset sources", () => {
		const s = scanHtml('<picture><source srcset="https://img.example.com/a.avif" type="image/avif"></picture>');
		assert.equal(s.sources.mediaSrc.size, 0);
	});

	it('counts inline handlers and javascript: links', () => {
		const s = scanHtml('<button onclick="go()">x</button><a href="javascript:void(0)">y</a><a href="/x">z</a>');
		assert.equal(s.handlers, 1);
		assert.equal(s.jsUrls, 1);
	});
});

// ── merging + directories ──────────────────────────────

describe('mergeScans / scanDir', () => {
	it('unions hashes and origins across pages', () => {
		const m = mergeScans([scanHtml('<script>a()</script>'), scanHtml('<script>b()</script><script>a()</script>')]);
		assert.equal(m.pages, 2);
		assert.equal(m.scripts.size, 2);
	});

	it('walks nested .html files and nothing else', () => {
		const dir = mkdtempSync(join(tmpdir(), 'sh-scan-'));
		mkdirSync(join(dir, 'blog'));
		writeFileSync(join(dir, 'index.html'), '<script>a()</script>');
		writeFileSync(join(dir, 'blog', 'index.html'), '<script>b()</script>');
		writeFileSync(join(dir, 'app.js'), '<script>not html</script>');
		const s = scanDir(dir);
		assert.equal(s.pages, 2);
		assert.equal(s.scripts.size, 2);
	});
});

// ── autoCsp ────────────────────────────────────────────

describe('autoCsp', () => {
	const scan = scanHtml(`
		<script>boot()</script>
		<style>:root{--a:1}</style>
		<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
		<script>var s=document.createElement('script');s.src='https://www.googletagmanager.com/gtag/js?id=G-1';</script>
	`);
	const csp = buildCSP(autoCsp(scan));

	it('puts script hashes on script-src, with no unsafe-inline', () => {
		assert.match(csp, new RegExp(`script-src 'self'[^;]*${sha('boot()').replace(/[+/=]/g, '\\$&')}`));
		assert.doesNotMatch(csp, /script-src[^;]*'unsafe-inline'/);
	});

	it("drops style-src 'unsafe-inline' for hashes and allows style attributes", () => {
		assert.doesNotMatch(csp, /style-src [^;]*'unsafe-inline'/);
		assert.match(csp, /style-src 'self' https:\/\/fonts\.googleapis\.com 'sha256-/);
		assert.match(csp, /style-src-attr 'unsafe-inline'/);
	});

	it('adds known provider companions', () => {
		assert.match(csp, /font-src 'self' https:\/\/fonts\.gstatic\.com/);
		assert.match(csp, /connect-src [^;]*https:\/\/\*\.google-analytics\.com/);
	});

	it('lets every third-party script origin connect home', () => {
		assert.match(csp, /connect-src 'self' https:\/\/www\.googletagmanager\.com/);
	});

	it("doesn't name an image host that img-src's https: already admits", () => {
		const c = buildCSP(autoCsp(scanHtml('<img src="https://img.example.com/a.png" alt="">')));
		assert.match(c, /img-src 'self' data: https:;/);
	});

	it('adds to your arrays rather than replacing them', () => {
		const c = buildCSP(autoCsp(scan, { auto: true, connectSrc: ["'self'", 'https://api.example.com'] }));
		assert.match(c, /connect-src 'self' https:\/\/api\.example\.com https:\/\/www\.googletagmanager\.com/);
		assert.doesNotMatch(c, /\bauto\b/);
	});

	it("emits no hashes on a directive you gave 'unsafe-inline'", () => {
		const c = buildCSP(autoCsp(scan, { styleSrc: ["'self'", "'unsafe-inline'"] }));
		assert.match(c, /style-src 'self' 'unsafe-inline' https:\/\/fonts\.googleapis\.com;/);
	});

	it('starts media-src from default-src, and omits it when nothing was found', () => {
		assert.doesNotMatch(csp, /media-src/);
		const c = buildCSP(autoCsp(scanHtml('<video src="https://media.example.com/v.mp4"></video>')));
		assert.match(c, /media-src 'self' https:\/\/media\.example\.com/);
	});
});
