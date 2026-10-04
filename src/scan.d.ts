/**
 * @arraypress/security-headers/scan — TypeScript definitions.
 */
import type { CSPConfig } from './index.js';

type Algorithm = 'sha256' | 'sha384' | 'sha512';

/** What a scan found — one page, or a whole site after `mergeScans`. */
export interface ScanResult {
  /** Pages scanned. */
  pages: number;
  /** Hash tokens (`'sha256-…'`) of every executable inline `<script>`. */
  scripts: Set<string>;
  /** Hash tokens of every inline `<style>`. */
  styles: Set<string>;
  /** Third-party ORIGINS found, by the directive that governs them. */
  sources: {
    scriptSrc: Set<string>;
    styleSrc: Set<string>;
    fontSrc: Set<string>;
    imgSrc: Set<string>;
    mediaSrc: Set<string>;
    frameSrc: Set<string>;
    formAction: Set<string>;
    /** Only ever filled by a `data-csp` declaration — fetches aren't in HTML. */
    connectSrc: Set<string>;
  };
  /** Elements carrying an inline `on*=` handler — a hash policy blocks these. */
  handlers: number;
  /** `href="javascript:…"` links — also blocked. */
  jsUrls: number;
  /**
   * `data-csp` entries that were ignored: an unknown directive, or a value
   * that isn't a plain https origin (keywords like `'unsafe-inline'` are
   * refused on purpose).
   */
  badDeclarations: string[];
}

export interface ScanOptions {
  /** Hash algorithm. Default `'sha256'`. */
  algorithm?: Algorithm;
}

/** A known provider's extra hosts, keyed on an origin the scan can see. */
export interface ProviderRule {
  match: string;
  add: Partial<Record<keyof CSPConfig, string[]>>;
}

export const PROVIDERS: ProviderRule[];

/** The quoted CSP hash token for a block of inline source. */
export function hashSource(text: string, algorithm?: Algorithm): string;

/** Scan one HTML document. */
export function scanHtml(html: string, options?: ScanOptions): ScanResult;

/** Union several scans into one site-wide result. */
export function mergeScans(scans: ScanResult[]): ScanResult;

/** Scan every `.html` file under a directory (e.g. a build's `dist/`). */
export function scanDir(dir: string, options?: ScanOptions): ScanResult;

/**
 * Turn a scan into a `CSPConfig`: your arrays (or the defaults) plus the
 * scan's hashes, origins and known-provider hosts.
 */
export function autoCsp(scan: ScanResult, config?: CSPConfig & { auto?: boolean }): CSPConfig;
