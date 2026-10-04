/**
 * @arraypress/security-headers/astro
 *
 * An Astro integration that writes `_headers` into the build output, so a
 * static site gets its security headers without a separate build script.
 *
 * Why a file rather than middleware: on Cloudflare, a static-assets deploy with
 * no server script serves requests for free. Adding middleware to set headers
 * adds a script and makes every request billable. `_headers` is applied at the
 * edge for nothing. Netlify reads the same file.
 *
 * CSP has three modes here:
 *
 *   - `csp: 'auto'` — scan the finished build, hash every inline script and
 *     style, allow every third-party origin the pages load from, and write ONE
 *     site-wide policy. Strict (no `'unsafe-inline'` on scripts) and compatible
 *     with `<ClientRouter />`, because the union covers every page a visitor
 *     can swap to. This is the mode to use.
 *   - `csp: { … }` — a policy you write yourself. `{ auto: true, … }` combines
 *     the two: your arrays as the base, the scan's findings added on top.
 *   - `csp: false` (the default) — no CSP header. Use this when Astro's own
 *     `security.csp` owns the policy instead. That `<meta>` approach doesn't
 *     support `<ClientRouter />`; this one does.
 *
 * @module @arraypress/security-headers/astro
 *
 * @example
 * // astro.config.mjs
 * import headers from '@arraypress/security-headers/astro';
 *
 * export default defineConfig({
 *   integrations: [headers({ csp: 'auto' })],
 * });
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { headersFile } from './index.js';
import { autoCsp, scanDir } from './scan.js';

/** Cloudflare Pages rejects a `_headers` line over this many characters. */
const CF_LINE_LIMIT = 2000;

const isAuto = (v) => v === 'auto' || (v && typeof v === 'object' && v.auto === true);

/**
 * Create the integration.
 *
 * @param {Object} [config={}] - `SecurityHeadersConfig`, where `csp` and
 *   `cspReportOnly` additionally accept `'auto'` (or `{ auto: true, … }`).
 *   `csp` defaults to `false`.
 * @param {Object} [options={}] - Rendering options.
 * @param {string} [options.path='/*'] - Path pattern the headers apply to.
 *   Cloudflare caps `_headers` at 100 rules; one path is one rule however
 *   many headers it carries.
 * @param {string} [options.filename='_headers'] - Output filename. Netlify and
 *   Cloudflare both use `_headers`; change it for a host that doesn't.
 * @returns {import('astro').AstroIntegration} The integration.
 */
export default function securityHeadersIntegration(config = {}, options = {}) {
	const { path = '/*', filename = '_headers', ...rest } = options;
	return {
		name: '@arraypress/security-headers',
		hooks: {
			'astro:build:done': ({ dir, logger }) => {
				const resolved = { csp: false, ...config };

				if (isAuto(resolved.csp) || isAuto(resolved.cspReportOnly)) {
					const scan = scanDir(fileURLToPath(dir));
					for (const key of ['csp', 'cspReportOnly']) {
						if (isAuto(resolved[key])) resolved[key] = autoCsp(scan, resolved[key] === 'auto' ? {} : resolved[key]);
					}
					const origins = new Set(Object.values(scan.sources).flatMap((s) => [...s]));
					logger.info(
						`CSP from ${scan.pages} pages — ${scan.scripts.size} inline script hash${scan.scripts.size === 1 ? '' : 'es'}, ` +
							`${scan.styles.size} inline style hash${scan.styles.size === 1 ? '' : 'es'}, ` +
							`${origins.size} third-party origin${origins.size === 1 ? '' : 's'}${origins.size ? ` (${[...origins].join(', ')})` : ''}`,
					);
					/* The two things a hash policy blocks that no hash can allow. Said
					   at build time because in the browser they fail silently. */
					if (scan.handlers) logger.warn(`${scan.handlers} element(s) use an inline on*= handler — the CSP will block them. Move them into a script.`);
					if (scan.jsUrls) logger.warn(`${scan.jsUrls} link(s) use href="javascript:" — the CSP will block them.`);
					if (scan.badDeclarations.length) {
						logger.warn(`ignored data-csp value(s) — only https origins on fetch/frame/media directives are accepted: ${scan.badDeclarations.join(', ')}`);
					}
				}

				let body = headersFile(resolved, { path, ...rest });

				/* Keep what's already there. Astro copies `public/_headers` into the
				   build before this runs, and it may hold rules this doesn't write
				   (cache-control for /_astro/*, redirects-adjacent headers). Append
				   rather than clobber, and say so if the two disagree. */
				const target = new URL(filename, dir);
				if (existsSync(target)) {
					const existing = readFileSync(target, 'utf8');
					const ours = body.split('\n').slice(1).map((l) => l.split(':')[0].trim()).filter(Boolean);
					const clash = ours.filter((h) => new RegExp(`^\\s+${h}:`, 'mi').test(existing));
					if (clash.length) logger.warn(`public/${filename} already sets ${clash.join(', ')} — both will be sent. Remove them from public/${filename}.`);
					body = `${existing.replace(/\s*$/, '')}\n\n${body}`;
				}

				writeFileSync(target, body);

				const long = body.split('\n').filter((l) => l.length > CF_LINE_LIMIT);
				if (long.length) {
					logger.warn(
						`${long.length} line(s) exceed Cloudflare's ${CF_LINE_LIMIT}-character _headers limit (longest ${Math.max(...long.map((l) => l.length))}). ` +
							`Fewer inline styles shortens the CSP: build.inlineStylesheets: 'never' moves component CSS into files.`,
					);
				}

				/* Every line is one header bar the leading path and the trailing newline. */
				const count = headersFile(resolved, { path, ...rest }).trim().split('\n').length - 1;
				logger.info(`wrote ${filename} — ${count} header${count === 1 ? '' : 's'} on ${path}`);
			},
		},
	};
}

export { securityHeadersIntegration };
