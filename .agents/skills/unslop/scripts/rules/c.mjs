// Section C — typography.
import { maxPxIn, decl } from '../lib/css.mjs';
import { textOnly } from '../lib/heuristics.mjs';

const MARKUP_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte'];
const STYLE_FILES = ['.css', '.scss'];

const KICKER_CLASS_RE = /\b[\w-]*(kicker|eyebrow|overline|section-label)[\w-]*\b/i;
const BIG_TW_TEXT_RE = /\btext-(3xl|4xl|5xl|6xl|7xl|8xl|9xl)\b/;
const TIGHT_TW_TRACKING_RE = /\btracking-(tight|tighter)\b/;
const CAPS_RUN_RE = /(?:\b[A-Z][A-Z'’&./-]{1,}\b[ \t]+){4,}\b[A-Z][A-Z'’&./-]{1,}\b/g;

export default [
  {
    id: 'C-4',
    severity: 'orange',
    title: 'Section-kicker label copy-pasted 3+ times',
    why: 'The tiny tracked uppercase label above every section is scaffolding, not hierarchy.',
    fileTypes: MARKUP_FILES,
    testFile(content, ctx) {
      const hits = [];
      ctx.lines.forEach((line, i) => {
        const classes = ctx.classText(line);
        const tailwindKicker = /\buppercase\b/.test(classes) && /\btracking-[\w[\]-]+/.test(classes);
        const namedKicker = KICKER_CLASS_RE.test(classes);
        if (tailwindKicker || namedKicker) hits.push({ line: i + 1, excerpt: line });
      });
      if (hits.length < 3) return null;
      const last = hits[hits.length - 1];
      return {
        line: last.line,
        excerpt: last.excerpt,
        note: `${hits.length} kicker labels in this file (lines ${hits.map((h) => h.line).join(', ')})`,
      };
    },
  },
  {
    id: 'C-6',
    severity: 'orange',
    title: 'Crushed letter-spacing on large text',
    why: 'Negative tracking at display sizes is an optical correction, not a default — it collapses the counters.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        const ls = decl(block, 'letter-spacing');
        const fs = decl(block, 'font-size');
        if (!ls || !fs) continue;
        const isNegative = /^-/.test(ls.value.trim());
        const sizePx = maxPxIn(fs.value);
        if (isNegative && sizePx != null && sizePx >= 28) {
          out.push({
            line: ls.line,
            excerpt: `${block.selector} { font-size: ${fs.value}; letter-spacing: ${ls.value} }`,
          });
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          if (BIG_TW_TEXT_RE.test(classes) && TIGHT_TW_TRACKING_RE.test(classes)) {
            out.push({ line: i + 1, excerpt: line });
          }
        });
      }
      return out;
    },
  },
  {
    id: 'C-9',
    severity: 'white',
    title: 'Uppercase used for a whole paragraph',
    why: 'Caps kill word shape. Use them for short labels, never for a sentence.',
    fileTypes: [...MARKUP_FILES, '.md', ...STYLE_FILES],
    testFile(content, ctx) {
      const out = [];

      if (ctx.isStyleFile) {
        for (const block of ctx.blocks()) {
          const tt = decl(block, 'text-transform');
          if (!tt || !/uppercase/i.test(tt.value)) continue;
          if (/(^|[\s,>])(body|p|\.prose|\.body|\.text|article)\b/i.test(block.selector)) {
            out.push({ line: tt.line, excerpt: `${block.selector} { text-transform: uppercase }` });
          }
        }
        return out;
      }

      ctx.lines.forEach((line, i) => {
        if (/[_=]|(?:import|export|const|require)\b/.test(line)) return; // identifiers, not prose
        const prose = textOnly(line);
        CAPS_RUN_RE.lastIndex = 0;
        let m;
        while ((m = CAPS_RUN_RE.exec(prose)) !== null) {
          if (m[0].trim().length >= 40) out.push({ line: i + 1, excerpt: m[0].trim() });
        }
      });
      return out;
    },
  },
];
