/**
 * @arraypress/security-headers/astro — TypeScript definitions.
 */
import type { AstroIntegration } from 'astro';
import type { CSPConfig, SecurityHeadersConfig } from './index.js';

export interface AstroHeadersOptions {
  /** Path pattern the headers apply to. Default `'/*'`. */
  path?: string;
  /** Output filename. Default `'_headers'`. */
  filename?: string;
}

/**
 * `'auto'` derives the policy from the finished build: inline script and
 * style hashes plus every third-party origin found. `{ auto: true, … }` uses
 * your arrays as the base and adds the findings on top.
 */
export type AutoCSP = 'auto' | (CSPConfig & { auto: true });

export interface AstroSecurityHeadersConfig extends Omit<SecurityHeadersConfig, 'csp' | 'cspReportOnly'> {
  /** Default `false`. `'auto'` is the strict, ClientRouter-safe option. */
  csp?: CSPConfig | AutoCSP | false;
  cspReportOnly?: CSPConfig | AutoCSP | false;
}

/**
 * Write `_headers` into the build output on `astro:build:done`, appending to
 * any `_headers` copied in from `public/`.
 */
export default function securityHeadersIntegration(
  config?: AstroSecurityHeadersConfig,
  options?: AstroHeadersOptions,
): AstroIntegration;

export { securityHeadersIntegration };
