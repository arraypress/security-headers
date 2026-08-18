/**
 * @arraypress/security-headers/astro — TypeScript definitions.
 */
import type { AstroIntegration } from 'astro';
import type { SecurityHeadersConfig } from './index.js';

export interface AstroHeadersOptions {
  /** Path pattern the headers apply to. Default `'/*'`. */
  path?: string;
  /** Output filename. Default `'_headers'`. */
  filename?: string;
}

/**
 * Write `_headers` into the build output on `astro:build:done`.
 *
 * `csp` defaults to `false` — Astro's own `security.csp` hashes the inline
 * blocks Astro emits, so it produces a stricter policy than a static file can.
 */
export default function securityHeadersIntegration(
  config?: SecurityHeadersConfig,
  options?: AstroHeadersOptions,
): AstroIntegration;

export { securityHeadersIntegration };
