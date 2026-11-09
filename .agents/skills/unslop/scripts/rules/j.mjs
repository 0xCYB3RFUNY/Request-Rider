// Section J: readability and accessibility.
// Contrast (J-1) and touch-target size (J-2) need computed style, so the detector has no check for them.
import { decl, declsMatching, toPx, maxPxIn } from '../lib/css.mjs';
import { headingLevels, isDisplaySelector, isSmallPrintSelector, isContainerSelector } from '../lib/heuristics.mjs';

// Block rules also read stylesheets embedded in <style> tags (see lib/scan.mjs).
const STYLE_FILES = ['.css', '.scss', '.html', '.vue', '.svelte'];
const MARKUP_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte'];

const PAGE_SELECTOR_RE = /(^|[\s,>])(body|main|\.container|\.wrapper|\.page|\.content|\.prose)\b/i;
const PADDING_PROP_RE = /^padding(-(top|right|bottom|left|inline|block|inline-start|inline-end))?$/;

/** Line-height as a ratio, if it can be resolved from this block alone. */
function lineHeightRatio(block) {
  const lh = decl(block, 'line-height');
  if (!lh) return null;
  const value = lh.value.trim();
  if (/var\(|calc\(/.test(value)) return null;
  if (/^\d*\.?\d+$/.test(value)) return { ratio: Number(value), line: lh.line, raw: value };
  if (/%$/.test(value)) return { ratio: parseFloat(value) / 100, line: lh.line, raw: value };
  const lhPx = toPx(value);
  const fs = decl(block, 'font-size');
  const fsPx = fs ? toPx(fs.value) : null;
  if (lhPx != null && fsPx) return { ratio: lhPx / fsPx, line: lh.line, raw: value };
  return null;
}

export default [
  {
    id: 'J-3a',
    severity: 'orange',
    title: 'Padding too tight inside a control or container',
    why: 'Under 8px inside a control or container the content touches the edge. 12–16px is the working range.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const out = [];
      for (const block of ctx.blocks()) {
        for (const d of declsMatching(block, PADDING_PROP_RE)) {
          if (/var\(|calc\(/.test(d.value)) continue;
          const parts = d.value.split(/\s+/).filter(Boolean);
          const pxValues = parts.map((p) => toPx(p)).filter((p) => p != null);
          if (pxValues.length === 0) continue;
          const smallestNonZero = Math.min(...pxValues.filter((p) => p > 0), Infinity);

          if (isContainerSelector(block.selector) && smallestNonZero < 8) {
            out.push({
              line: d.line,
              excerpt: `${block.selector} { ${d.prop}: ${d.value} }`,
              note: 'control/container padding under 8px',
            });
            continue;
          }
          const horizontal =
            d.prop === 'padding' || /(left|right|inline)/.test(d.prop)
              ? smallestNonZero
              : Infinity;
          if (PAGE_SELECTOR_RE.test(block.selector) && horizontal > 0 && horizontal < 16) {
            out.push({
              line: d.line,
              excerpt: `${block.selector} { ${d.prop}: ${d.value} }`,
              note: 'body text under 16px from the viewport edge',
            });
          }
        }
      }
      return out;
    },
  },
  {
    id: 'J-4',
    severity: 'orange',
    title: 'Line-height below 1.3 on body text',
    why: 'Tight leading on running text destroys the return sweep. 1.5–1.7 for body.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const out = [];
      for (const block of ctx.blocks()) {
        if (isDisplaySelector(block.selector) || isSmallPrintSelector(block.selector)) continue;
        const lh = lineHeightRatio(block);
        if (!lh || lh.ratio <= 0) continue;
        const fs = decl(block, 'font-size');
        const fsPx = fs ? maxPxIn(fs.value) : null;
        if (fsPx != null && fsPx >= 28) continue; // display size, tight leading is correct
        if (lh.ratio < 1.3) {
          out.push({ line: lh.line, excerpt: `${block.selector} { line-height: ${lh.raw} }` });
        }
      }
      return out;
    },
  },
  {
    id: 'J-5',
    severity: 'orange',
    title: 'Body text below 14px',
    why: 'Under 14px body copy stops being readable on a phone. 16px is the target.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const out = [];
      for (const block of ctx.blocks()) {
        if (isSmallPrintSelector(block.selector)) continue;
        const fs = decl(block, 'font-size');
        if (!fs || /var\(|calc\(|clamp\(/.test(fs.value)) continue;
        const px = toPx(fs.value);
        if (px != null && px > 0 && px < 14) {
          out.push({ line: fs.line, excerpt: `${block.selector} { font-size: ${fs.value} }` });
        }
      }
      return out;
    },
  },
  {
    id: 'J-6',
    severity: 'orange',
    title: 'Heading levels jump (for example h2 to h4)',
    why: 'h1 → h3 breaks the document outline screen readers navigate by.',
    fileTypes: [...MARKUP_FILES, '.md'],
    testFile(content, ctx) {
      const headings = headingLevels(ctx);
      const out = [];
      let previous = null;
      for (const h of headings) {
        if (previous != null && h.level > previous + 1) {
          out.push({ line: h.line, excerpt: ctx.lineAt(h.line), note: `h${previous} → h${h.level}` });
        }
        previous = h.level;
      }
      return out;
    },
  },
  {
    id: 'J-7',
    severity: 'white',
    title: 'Letter-spacing above 0.05em on body text',
    why: 'Loose tracking on running text breaks words into loose letters.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const out = [];
      for (const block of ctx.blocks()) {
        if (isDisplaySelector(block.selector) || isSmallPrintSelector(block.selector)) continue;
        const tt = decl(block, 'text-transform');
        if (tt && /uppercase/i.test(tt.value)) continue; // caps need tracking
        const ls = decl(block, 'letter-spacing');
        if (!ls) continue;
        const em = ls.value.match(/^(\d*\.?\d+)em$/);
        const px = toPx(ls.value);
        const ratio = em ? Number(em[1]) : px != null ? px / 16 : null;
        if (ratio != null && ratio > 0.05) {
          out.push({ line: ls.line, excerpt: `${block.selector} { letter-spacing: ${ls.value} }` });
        }
      }
      return out;
    },
  },
  {
    id: 'J-8',
    severity: 'white',
    title: 'Justified text with hyphenation off',
    why: 'Justify without hyphens opens rivers of whitespace through the paragraph.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const out = [];
      for (const block of ctx.blocks()) {
        const align = decl(block, 'text-align');
        if (!align || !/justify/i.test(align.value)) continue;
        const hyphens = declsMatching(block, /^(-\w+-)?hyphens$/);
        if (hyphens.some((h) => /auto/i.test(h.value))) continue;
        out.push({ line: align.line, excerpt: `${block.selector} { text-align: justify }` });
      }
      return out;
    },
  },
  {
    id: 'J-9',
    severity: 'orange',
    title: 'Focus ring removed with no replacement',
    why: 'outline:none without a :focus-visible style leaves keyboard users with no cursor.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const killed = [];
      for (const block of ctx.blocks()) {
        for (const d of declsMatching(block, /^outline$/)) {
          if (/^(none|0)\b/i.test(d.value.trim())) killed.push({ block, d });
        }
      }
      if (killed.length === 0) return null;
      const replaced = /:focus-visible[^{]*\{[^}]*(outline|box-shadow|border)\s*:/s.test(content);
      if (replaced) return null;
      return killed.map(({ block, d }) => ({
        line: d.line,
        excerpt: `${block.selector} { outline: ${d.value} }`,
        note: 'no :focus-visible replacement in this file',
      }));
    },
  },
  {
    id: 'J-10',
    severity: 'orange',
    title: 'No type scale — font sizes picked per block',
    why: 'A dozen unique literal font sizes in one stylesheet is not a scale, it is guessing.',
    fileTypes: STYLE_FILES,
    testFile(content, ctx) {
      const sizes = new Map();
      for (const block of ctx.blocks()) {
        const fs = decl(block, 'font-size');
        if (!fs || /var\(|inherit/.test(fs.value)) continue;
        const key = fs.value.trim();
        if (!sizes.has(key)) sizes.set(key, fs.line);
      }
      if (sizes.size <= 12) return null;
      const [firstValue, firstLine] = [...sizes.entries()][0];
      return {
        line: firstLine,
        excerpt: `${sizes.size} distinct literal font-size values in this file (first: ${firstValue})`,
        note: [...sizes.keys()].join(', '),
      };
    },
  },
];
