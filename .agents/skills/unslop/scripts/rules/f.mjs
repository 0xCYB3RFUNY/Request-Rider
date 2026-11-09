// Section F — layout and space.
// Only F-6 survives static scanning, and only where the measure is expressed in
// `ch`. F-7 (overflow) and F-8 (clipped positioned child) need layout, so the
// detector has no check for them.
import { declsMatching } from '../lib/css.mjs';

const STYLE_FILES = ['.css', '.scss'];
const MARKUP_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte'];
const CH_RE = /(\d+(?:\.\d+)?)ch\b/g;

export default [
  {
    id: 'F-6',
    severity: 'orange',
    title: 'Measure wider than 75ch',
    why: 'Past ~75 characters the eye loses the line return. Cap the measure at 65–75ch.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        for (const d of declsMatching(block, /^(max-)?width$/)) {
          CH_RE.lastIndex = 0;
          let m;
          while ((m = CH_RE.exec(d.value)) !== null) {
            if (Number(m[1]) > 75) {
              out.push({ line: d.line, excerpt: `${block.selector} { ${d.prop}: ${d.value} }` });
            }
          }
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          const m = classes.match(/\bmax-w-\[(\d+(?:\.\d+)?)ch\]/);
          if (m && Number(m[1]) > 75) out.push({ line: i + 1, excerpt: line });
        });
      }
      return out;
    },
  },
];
