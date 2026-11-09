// Section D — colour and contrast.
import { decl, declsMatching, isChromaticColor, isGreyish } from '../lib/css.mjs';

const STYLE_FILES = ['.css', '.scss'];
const MARKUP_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte'];

const TW_GREY_TEXT_RE = /\btext-(?:slate|gray|grey|zinc|neutral|stone)-(?:300|400|500|600)\b/;
const TW_CHROMATIC_BG_RE =
  /\bbg-(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-(?:400|500|600|700|800|900)\b/;

export default [
  {
    id: 'D-3',
    severity: 'orange',
    title: 'Text filled with a gradient',
    why: 'background-clip:text + transparent fill destroys contrast control and scannability.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        const clip = declsMatching(block, /^(-webkit-)?background-clip$/);
        const clipsText = clip.some((d) => /\btext\b/.test(d.value));
        if (!clipsText) continue;
        const transparent =
          declsMatching(block, /^(-webkit-)?text-fill-color$/).some((d) => /transparent/i.test(d.value)) ||
          (decl(block, 'color') && /transparent/i.test(decl(block, 'color').value));
        if (!transparent) continue;
        out.push({ line: clip[0].line, excerpt: `${block.selector} { background-clip: text; … transparent }` });
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          if (/\bbg-clip-text\b/.test(classes) && /\btext-transparent\b/.test(classes)) {
            out.push({ line: i + 1, excerpt: line });
          }
        });
      }
      return out;
    },
  },
  {
    id: 'D-4',
    severity: 'orange',
    title: 'Grey text on a coloured background',
    why: 'Grey on colour reads as dirt. Use a darker shade of the background itself, or white.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        const color = decl(block, 'color');
        const bg = decl(block, 'background-color') ?? decl(block, 'background');
        if (!color || !bg) continue;
        if (isGreyish(color.value) && isChromaticColor(bg.value)) {
          out.push({
            line: color.line,
            excerpt: `${block.selector} { color: ${color.value}; background: ${bg.value} }`,
          });
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          if (TW_GREY_TEXT_RE.test(classes) && TW_CHROMATIC_BG_RE.test(classes)) {
            out.push({ line: i + 1, excerpt: line });
          }
        });
      }
      return out;
    },
  },
];
