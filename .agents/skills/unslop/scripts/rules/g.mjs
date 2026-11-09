// Section G: motion. Thresholds credited in CREDITS.md.
import { declsMatching, durationsMs } from '../lib/css.mjs';

const STYLE_FILES = ['.css', '.scss', '.html', '.vue', '.svelte'];
const MARKUP_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte'];
const CODE_FILES = ['.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte'];
const ALL_FILES = [...STYLE_FILES, ...MARKUP_FILES, '.js', '.ts'];

const MOTION_LIB_RE = /(framer-motion|motion\/react|motion\/dom|gsap|animejs|@react-spring|popmotion)/;
const LAYOUT_PROPS_RE =
  /\b(width|height|top|left|right|bottom|margin|margin-[a-z]+|padding|padding-[a-z]+|font-size|line-height|inset)\b/;
const OVERLAY_SELECTOR_RE = /(dropdown|menu|popover|tooltip|modal|dialog|toast|sheet|flyout|combobox|select)/i;

export default [
  {
    id: 'G-1',
    severity: 'red',
    title: '`ease-in` on UI motion',
    why: 'ease-in starts slowly, so the visible part of the motion feels sluggish. Prefer an ease-out curve.',
    fileTypes: ALL_FILES,
    test(line, ctx) {
      if (/^\s*(\/\/|\/\*|\*)/.test(line)) return null; // comment
      // cubic-bezier(.42, 0, 1, 1) is the literal definition of ease-in
      if (/cubic-bezier\(\s*0?\.\d+\s*,\s*0\s*,\s*1\s*,\s*1\s*\)/.test(line)) return { excerpt: line };
      if (ctx.isStyleFile) return /\bease-in\b(?!-out)/.test(line) ? { excerpt: line } : null;
      const classes = ctx.classText(line);
      if (classes && /\bease-in\b(?!-out)/.test(classes)) return { excerpt: line };
      if (/\beaseIn\b(?!Out)/.test(line) && MOTION_LIB_RE.test(ctx.content)) return { excerpt: line };
      return null;
    },
  },
  {
    id: 'G-2',
    severity: 'red',
    title: '`scale(0)` — appearing out of nothing',
    why: 'Nothing in the physical world grows from zero. Start at 0.9–0.97 with opacity.',
    fileTypes: ALL_FILES,
    test(line) {
      if (/\bscale3?d?\(\s*0\s*(?:[,)]|\s*,\s*0\s*\))/.test(line)) return { excerpt: line };
      if (/\bscale\s*:\s*0\s*(?:[,}\]]|$)/.test(line)) return { excerpt: line };
      return null;
    },
  },
  {
    id: 'G-4',
    severity: 'red',
    title: 'Transition applied to every property',
    why: 'Transitioning everything animates properties you never meant to, including layout. List them.',
    fileTypes: ALL_FILES,
    test(line, ctx) {
      if (/transition(?:-property)?\s*:\s*(?:[^;{}]*\s)?all\b/.test(line)) return { excerpt: line };
      const classes = ctx.classText(line);
      if (classes && /\btransition-all\b/.test(classes)) return { excerpt: line };
      return null;
    },
  },
  {
    id: 'G-5',
    severity: 'orange',
    title: 'UI duration longer than 300ms',
    why: 'Buttons 100–160ms, dropdowns 150–250ms, modals 200–500ms. Past that the UI feels sluggish.',
    fileTypes: ALL_FILES,
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        for (const d of declsMatching(block, /^(transition|transition-duration|animation|animation-duration)$/)) {
          if (/infinite/i.test(d.value)) continue; // loaders/ambient loops are not UI response
          const worst = Math.max(0, ...durationsMs(d.value));
          if (worst > 300) {
            out.push({ line: d.line, excerpt: `${block.selector} { ${d.prop}: ${d.value} }` });
          }
        }
      }

      if (ctx.isMarkupFile || ctx.ext === '.html') {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          const m = classes.match(/\bduration-(\d{3,4})\b/);
          if (m && Number(m[1]) > 300) out.push({ line: i + 1, excerpt: line });
        });
      }

      if (MOTION_LIB_RE.test(content)) {
        ctx.lines.forEach((line, i) => {
          const m = line.match(/\bduration\s*:\s*(\d*\.?\d+)/);
          if (!m) return;
          const value = Number(m[1]);
          const ms = value <= 10 ? value * 1000 : value; // motion libs count in seconds
          if (ms > 300 && !/repeat\s*:\s*Infinity/.test(line)) out.push({ line: i + 1, excerpt: line });
        });
      }
      return out;
    },
  },
  {
    id: 'G-6',
    severity: 'orange',
    title: 'Motion that animates width, height or position',
    why: 'width/height/padding animations run on the main thread and cause layout thrash. Use transform/opacity.',
    fileTypes: ALL_FILES,
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        for (const d of declsMatching(block, /^(transition|transition-property)$/)) {
          const props = d.value.split(',').map((p) => p.trim().split(/\s+/)[0]);
          const bad = props.filter((p) => LAYOUT_PROPS_RE.test(p));
          if (bad.length) {
            out.push({
              line: d.line,
              excerpt: `${block.selector} { ${d.prop}: ${d.value} }`,
              note: `layout properties: ${bad.join(', ')}`,
            });
          }
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          const m = classes.match(/\btransition-\[([^\]]+)\]/);
          if (m && LAYOUT_PROPS_RE.test(m[1])) out.push({ line: i + 1, excerpt: line });
        });
      }
      return out;
    },
  },
  {
    id: 'G-9',
    severity: 'orange',
    title: 'No `prefers-reduced-motion` anywhere in the project',
    why: 'Motion sensitivity is not optional. Every animating project needs one reduced-motion block.',
    fileTypes: ALL_FILES,
    testProject(contexts) {
      const animating = contexts.filter(
        (c) =>
          /@keyframes\b/.test(c.content) ||
          /\btransition\s*:/.test(c.content) ||
          /\banimation\s*:/.test(c.content) ||
          MOTION_LIB_RE.test(c.content),
      );
      if (animating.length === 0) return null;
      const honoured = contexts.some((c) => /prefers-reduced-motion/.test(c.content));
      if (honoured) return null;
      const first = animating[0];
      return {
        file: first.rel,
        absPath: first.file,
        line: 1,
        excerpt: `${animating.length} animating file(s), no prefers-reduced-motion query in the scanned tree`,
      };
    },
  },
  {
    id: 'G-10',
    severity: 'white',
    title: 'Scaling overlay without `transform-origin`',
    why: 'A menu that scales from its centre detaches from its trigger. Anchor the origin to the point of appearance.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const out = [];
      for (const block of ctx.blocks()) {
        if (!OVERLAY_SELECTOR_RE.test(block.selector)) continue;
        const transforms = declsMatching(block, /^(transform|scale|animation|transition)$/);
        const scales = transforms.filter((d) => /scale\b/.test(d.value));
        if (scales.length === 0) continue;
        if (block.decls.some((d) => d.prop === 'transform-origin')) continue;
        out.push({ line: scales[0].line, excerpt: `${block.selector} { ${scales[0].prop}: ${scales[0].value} }` });
      }
      return out;
    },
  },
];
