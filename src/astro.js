/**
 * @arraypress/security-headers/astro
 *
 * An Astro integration that writes `_headers` into the build output, so a
 * static site gets its security headers without a separate build script.
 *
 * Why a file rather than middleware: on Cloudflare, a static-assets deploy with
 * no server script serves requests for free. Adding middleware to set headers
 * adds a script and makes every request billable. `_headers` is applied at the
 * edge for nothing.
 *
 * CSP is deliberately off by default here. Astro has its own `security.csp`
 * config, which can hash the inline scripts and styles Astro itself emits — so
 * it produces a stricter policy than a static file can, which would otherwise
 * need `'unsafe-inline'`. Let Astro own CSP and let this own the rest.
 *
 * @module @arraypress/security-headers/astro
 *
 * @example
 * // astro.config.mjs
 * import headers from '@arraypress/security-headers/astro';
 *
 * export default defineConfig({
 *   security: { csp: true },   // Astro hashes its own inline blocks
 *   integrations: [headers()],  // HSTS, X-Frame-Options, Referrer-Policy, …
 * });
 */

import { writeFileSync } from 'node:fs';
import { headersFile } from './index.js';

/**
 * Create the integration.
 *
 * @param {Object} [config={}] - `SecurityHeadersConfig`. `csp` defaults to
 *   `false` — see the module note above. Pass a CSP config to opt back in,
 *   for a host where Astro's own CSP isn't in play.
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
				const body = headersFile({ csp: false, ...config }, { path, ...rest });
				writeFileSync(new URL(filename, dir), body);
				/* Every line is one header bar the leading path and the trailing newline. */
				const count = body.trim().split('\n').length - 1;
				logger.info(`wrote ${filename} — ${count} header${count === 1 ? '' : 's'} on ${path}`);
			},
		},
	};
}

export { securityHeadersIntegration };
