// Section B — tokens and code.
import { rawHexOnLine, lineOfIndex } from '../lib/heuristics.mjs';

const STYLE_FILES = ['.css', '.scss', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte'];
const MARKUP_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte'];
const CODE_FILES = ['.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte'];

const TW_HUES =
  'slate|gray|grey|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose';
const TW_PREFIXES =
  'bg|text|border|ring|divide|from|via|to|outline|decoration|fill|stroke|accent|caret|placeholder|shadow';
const TW_PALETTE_RE = new RegExp(
  `(?:^|[\\s"'\`])(?:[\\w-]+:)*(?:${TW_PREFIXES})-(?:(?:${TW_HUES})-(?:50|100|200|300|400|500|600|700|800|900|950)|white|black)\\b`,
  'g',
);

const ARBITRARY_RE = /(?:^|[\s"'`])(?:[\w-]+:)*[a-z][\w-]*-\[[^\]\s]+\]/g;

const ICON_SET_RE =
  /from\s+['"](lucide-react|lucide-preact|react-icons(?:\/[\w-]+)?|@heroicons\/[\w-]+(?:\/[\w/]+)?|@tabler\/icons[\w-]*|phosphor-react|@phosphor-icons\/[\w-]+|feather-icons|react-feather|@mui\/icons-material(?:\/[\w-]+)?|iconoir-react|@radix-ui\/react-icons|@fortawesome\/[\w-]+)['"]/;

const INLINE_STYLE_RE = /style\s*=\s*(?:\{\{([^}]*)\}\}|"([^"]*)"|'([^']*)')/g;
const NAMED_COLORS_RE =
  /\b(red|blue|green|purple|violet|indigo|orange|teal|cyan|magenta|pink|gold|crimson|salmon|olive|navy|lime|aqua|fuchsia|maroon|gray|grey|silver|beige|ivory)\b/i;

const NON_INTERACTIVE_HANDLER_RE =
  /<(div|span|li|p|section|article|td|img)\b((?:[^>"']|"[^"]*"|'[^']*')*?)\son(?:Click|click)\s*=/g;

export default [
  {
    id: 'B-1',
    severity: 'red',
    title: 'Raw hex colour in styles',
    why: 'A raw hex freezes a colour outside the palette. Use the semantic token.',
    fileTypes: STYLE_FILES,
    test(line, ctx) {
      const hexes = rawHexOnLine(line, ctx);
      if (hexes.length === 0) return null;
      // A logo colour stays a B-1 question even when the file already uses tokens.
      if (hexes.svgExceptionCandidate) {
        return { excerpt: line, exceptionCandidate: 'brand-svg-logo' };
      }
      if (ctx.tokenAware) return null; // escalated to DS-2
      return { excerpt: line };
    },
  },
  {
    id: 'B-2',
    severity: 'red',
    title: 'Tailwind palette class instead of a token utility',
    why: 'bg-white / text-gray-500 hardwire a palette step; the theme cannot re-skin them.',
    fileTypes: [...MARKUP_FILES, '.css', '.scss', '.js', '.ts'],
    test(line, ctx) {
      const classes = ctx.classText(line);
      if (!classes) return null;
      TW_PALETTE_RE.lastIndex = 0;
      const hits = classes.match(TW_PALETTE_RE);
      if (!hits) return null;
      return { excerpt: `${hits.map((h) => h.trim()).join(' ')}  —  ${line.trim()}` };
    },
  },
  {
    id: 'B-3',
    severity: 'orange',
    title: 'Arbitrary value in a utility class',
    why: 'w-[13px] / text-[#fff] step outside the scale. Use a scale step or a token.',
    fileTypes: [...MARKUP_FILES, '.css', '.scss', '.js', '.ts'],
    test(line, ctx) {
      const classes = ctx.classText(line);
      if (!classes) return null;
      ARBITRARY_RE.lastIndex = 0;
      const hits = classes.match(ARBITRARY_RE);
      if (!hits) return null;
      return { excerpt: `${hits.map((h) => h.trim()).join(' ')}  —  ${line.trim()}` };
    },
  },
  {
    id: 'B-4',
    severity: 'orange',
    title: 'Icon imported straight from an icon set',
    why: 'Bypasses the <Icon name=…/> adapter, so icon swaps and sizing stop being systemic.',
    fileTypes: CODE_FILES,
    test(line, ctx) {
      // The adapter itself is allowed to import the set.
      if (/(^|[\\/])icons?([.-][\w-]*)?\.[a-z]+$/i.test(ctx.rel)) return null;
      if (/[\\/]icons?[\\/]/i.test(ctx.rel)) return null;
      return ICON_SET_RE.test(line) ? { excerpt: line } : null;
    },
  },
  {
    id: 'B-6a',
    severity: 'orange',
    title: 'Data-driven component with no loading / error / empty state',
    why: 'A component that fetches must render all three outcomes, not just the happy path.',
    fileTypes: ['.jsx', '.tsx', '.vue', '.svelte'],
    testFile(content, ctx) {
      const fetches =
        /\b(useQuery|useSWR|useFetch|useAsync|useLoaderData)\b/.test(content) ||
        /\bawait\s+fetch\s*\(/.test(content) ||
        /\baxios\.(get|post|put|delete)\s*\(/.test(content);
      if (!fetches) return null;
      const missing = [];
      if (!/\b(isLoading|loading|isPending|pending|Skeleton|Spinner|isFetching)\b/.test(content))
        missing.push('loading');
      if (!/\b(isError|error|hasError|catch|onError)\b/.test(content)) missing.push('error');
      if (!/(\.length\s*===?\s*0|\.length\s*(?:<|!)|isEmpty|Empty|noResults|no_results)/.test(content))
        missing.push('empty');
      if (missing.length === 0) return null;
      const m = content.match(/\b(useQuery|useSWR|useFetch|useAsync|useLoaderData|await\s+fetch|axios\.)/);
      const line = m ? lineOfIndex(content, m.index) : 1;
      return { line, excerpt: ctx.lineAt(line), note: `missing: ${missing.join(', ')}` };
    },
  },
  {
    id: 'B-7',
    severity: 'white',
    title: 'Inline style outside the allowed set',
    why: 'Inline styles may carry layout numbers (px/cqw/clamp/rgb), not colours, gradients or !important.',
    fileTypes: MARKUP_FILES,
    testFile(content, ctx) {
      const out = [];
      INLINE_STYLE_RE.lastIndex = 0;
      let m;
      while ((m = INLINE_STYLE_RE.exec(content)) !== null) {
        const body = m[1] ?? m[2] ?? m[3] ?? '';
        const offending = [];
        if (/#[0-9a-fA-F]{3,8}\b/.test(body)) offending.push('hex colour');
        if (/gradient\s*\(/i.test(body)) offending.push('gradient');
        if (/!important/i.test(body)) offending.push('!important');
        if (NAMED_COLORS_RE.test(body.replace(/['"`]/g, ' '))) offending.push('named colour');
        if (offending.length === 0) continue;
        const line = lineOfIndex(content, m.index);
        out.push({ line, excerpt: m[0], note: offending.join(', ') });
      }
      return out;
    },
  },
  {
    id: 'B-8a',
    severity: 'red',
    title: 'Non-semantic markup',
    why: 'A click handler on a <div> is not focusable, not announced, not keyboard-operable. Use <button>/<a>.',
    fileTypes: MARKUP_FILES,
    testFile(content, ctx) {
      const out = [];
      NON_INTERACTIVE_HANDLER_RE.lastIndex = 0;
      let m;
      while ((m = NON_INTERACTIVE_HANDLER_RE.exec(content)) !== null) {
        const attrs = m[2] ?? '';
        // role=button + tabindex + key handler is the documented escape hatch.
        const rescued =
          /role\s*=\s*["'{]?\s*(button|link|tab|menuitem)/i.test(attrs) &&
          /tab(?:I|i)ndex/.test(attrs) &&
          /onKey(?:Down|Press|Up)|onkey(?:down|press|up)/i.test(content);
        if (rescued) continue;
        const line = lineOfIndex(content, m.index);
        out.push({ line, excerpt: ctx.lineAt(line) });
      }

      if (ctx.ext === '.html') {
        const divs = (content.match(/<div\b/gi) || []).length;
        const landmarks = /<(main|nav|header|footer|section|article|aside)\b/i.test(content);
        if (divs >= 15 && !landmarks) {
          out.push({
            line: 1,
            excerpt: `${divs} <div> elements, zero landmark elements in this document`,
            note: 'div soup — no <main>/<nav>/<header>/<footer>',
          });
        }
      }
      return out;
    },
  },
];
