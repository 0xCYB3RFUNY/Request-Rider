// Section A — design-system integrity.
// Only DS-2 is statically decidable, and only in its strongest form: a file that
// already consumes design tokens AND still hardcodes a raw value. That pairing is
// proof the system exists and was bypassed. DS-1/DS-3/DS-5 are taste rules;
// DS-4 (token drift) needs the token source, so the detector has no DS-4 check.
import { rawHexOnLine } from '../lib/heuristics.mjs';

const STYLE_FILES = ['.css', '.scss', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte'];

export default [
  {
    id: 'DS-2a',
    severity: 'red',
    title: 'Hardcoded value in a file that already uses design tokens',
    why: 'The token system is provably present here (var(--…)/theme()), so the raw value bypasses the DS. Fix at the token, not the instance.',
    fileTypes: STYLE_FILES,
    test(line, ctx) {
      if (!ctx.tokenAware) return null; // otherwise it is plain B-1
      const hexes = rawHexOnLine(line, ctx);
      if (hexes.length === 0) return null;
      // Inline SVG keeps the brand-logo question on B-1. One finding per line.
      if (hexes.svgExceptionCandidate) return null;
      return { excerpt: line, note: 'REQUIRES-APPROVAL — fix in the design system, not the instance' };
    },
  },
];
