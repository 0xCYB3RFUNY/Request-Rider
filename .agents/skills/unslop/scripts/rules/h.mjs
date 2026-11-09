// Section H — copy / content.
import { textOnly } from '../lib/heuristics.mjs';

const COPY_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte', '.md'];
// H-1 skips markdown files. The limit of 3 targets interface copy; long-form
// docs use dashes for structure, and checking them gave only false positives.
const H1_FILES = COPY_FILES.filter((e) => e !== '.md');
const ALL_FILES = [...COPY_FILES, '.js', '.ts', '.css', '.scss'];

const EM_DASH_LIMIT = 3;
const PLACEHOLDER_RE =
  /(lorem\s+ipsum|dolor\s+sit\s+amet|consectetur\s+adipiscing|placeholder\s+(?:text|copy)|your\s+(?:headline|text)\s+here|TKTK|\bTBD\b\s*copy)/i;

// H-1 counts dashes in running text only. A heading (markdown or <h1>-<h6>) that
// uses a dash as a separator is not counted.
const HEADING_RE = /^\s{0,3}#{1,6}\s|^\s*<h[1-6][\s>]/i;

// H-6 skips text that talks about placeholder copy instead of shipping it:
// developer-facing notes such as a README, a checklist or a rule list.
const NAMES_THE_PATTERN_RE =
  /\b(grep|search for|scan|detect|detector|flag|look for|rule|criteri\w*|catalog|checklist|audit)\b/i;

// The same signal, stronger: the placeholder is quoted as code (`lorem ipsum`),
// which is how documentation refers to a string rather than shipping it.
const BACKTICKED_RE = /`[^`]*(lorem\s+ipsum|placeholder)[^`]*`/i;

export default [
  {
    id: 'H-1',
    severity: 'orange',
    title: 'Too many em dashes in one piece of copy',
    why: 'More than three em-dashes in one deliverable is the AI cadence tell. Cap at three. Markdown is out of scope: see H1_FILES.',
    fileTypes: H1_FILES,
    testFile(content, ctx) {
      const hits = [];
      ctx.lines.forEach((line, i) => {
        if (HEADING_RE.test(line)) return; // structure, not cadence
        const prose = textOnly(line);
        for (const _ of prose.match(/—/g) ?? []) hits.push(i + 1);
      });
      if (hits.length <= EM_DASH_LIMIT) return null;
      const line = hits[EM_DASH_LIMIT];
      return {
        line,
        excerpt: ctx.lineAt(line),
        note: `${hits.length} em-dashes in this file (limit ${EM_DASH_LIMIT})`,
      };
    },
  },
  {
    id: 'H-6',
    severity: 'white',
    title: 'Placeholder copy in a deliverable',
    why: 'Lorem ipsum in shipped UI says nobody read the page.',
    fileTypes: ALL_FILES,
    test(line) {
      if (!PLACEHOLDER_RE.test(line)) return null;
      // Documentation naming the pattern is not an instance of it.
      if (BACKTICKED_RE.test(line) || NAMES_THE_PATTERN_RE.test(line)) return null;
      return { excerpt: line };
    },
  },
];
