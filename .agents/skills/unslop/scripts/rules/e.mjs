// Section E — visual details / surfaces.
import { decl, declsMatching, maxPxIn, toPx, isChromaticColor } from '../lib/css.mjs';

const STYLE_FILES = ['.css', '.scss'];
const MARKUP_FILES = ['.html', '.jsx', '.tsx', '.vue', '.svelte'];

const TW_ROUNDED_BIG_RE = /\brounded-(xl|2xl|3xl)\b/;
const TW_BORDER_THICK_RE = /\bborder-(2|4|8)\b/;
const TW_BORDER_COLOR_RE =
  /\bborder-(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}\b/;
const TW_SHADOW_WIDE_RE = /\bshadow-(lg|xl|2xl)\b/;

/** Widest blur radius in a box-shadow value, in px. */
function shadowBlurPx(value) {
  const layers = String(value).split(/,(?![^()]*\))/);
  let max = null;
  for (const layer of layers) {
    // colour functions carry numbers that are not lengths
    const cleaned = layer.replace(/(?:rgba?|hsla?|hwb|lab|lch|oklch|color|var)\([^)]*\)/gi, ' ');
    const lengths = cleaned.match(/-?\d*\.?\d+(?:px|rem|em)?\b/g);
    if (!lengths || lengths.length < 3) continue;
    const third = lengths[2];
    const blur = toPx(/[a-z]/i.test(third) ? third : `${third}px`);
    if (blur != null && (max == null || blur > max)) max = blur;
  }
  return max;
}

function borderWidthPx(block) {
  const explicit = decl(block, 'border-width');
  if (explicit) return toPx(explicit.value.split(/\s+/)[0]);
  const shorthand = declsMatching(block, /^border(-(top|right|bottom|left))?$/)[0];
  if (!shorthand) return null;
  const m = shorthand.value.match(/(-?\d*\.?\d+)(px|rem|em)\b/);
  return m ? toPx(m[0]) : null;
}

function borderColorValue(block) {
  const explicit = decl(block, 'border-color');
  if (explicit) return explicit.value;
  const shorthand = declsMatching(block, /^border(-(top|right|bottom|left))?$/)[0];
  return shorthand ? shorthand.value : null;
}

export default [
  {
    id: 'E-3',
    severity: 'orange',
    title: 'Hairline border and a wide diffuse shadow on the same surface',
    why: 'Edge OR elevation — both at once reads as an unresolved surface system.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        const shadow = decl(block, 'box-shadow');
        if (!shadow || /^\s*none/i.test(shadow.value)) continue;
        const blur = shadowBlurPx(shadow.value);
        const width = borderWidthPx(block);
        if (blur != null && blur >= 16 && width != null && width > 0 && width <= 1) {
          out.push({
            line: shadow.line,
            excerpt: `${block.selector} { border: ${width}px …; box-shadow: ${shadow.value} }`,
          });
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          const hairline = /(?:^|\s)border(?:\s|$)/.test(classes) && !TW_BORDER_THICK_RE.test(classes);
          if (hairline && TW_SHADOW_WIDE_RE.test(classes)) out.push({ line: i + 1, excerpt: line });
        });
      }
      return out;
    },
  },
  {
    id: 'E-4',
    severity: 'orange',
    title: 'Rounded card with a thick coloured border',
    why: 'Big radius plus a heavy chromatic edge is a sticker, not a surface. Pick one.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        const radius = decl(block, 'border-radius');
        if (!radius) continue;
        const radiusPx = maxPxIn(radius.value);
        const width = borderWidthPx(block);
        const color = borderColorValue(block);
        if (radiusPx != null && radiusPx >= 12 && width != null && width >= 2 && color && isChromaticColor(color)) {
          out.push({
            line: radius.line,
            excerpt: `${block.selector} { border-radius: ${radius.value}; border: ${width}px … ${color} }`,
          });
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          if (TW_ROUNDED_BIG_RE.test(classes) && TW_BORDER_THICK_RE.test(classes) && TW_BORDER_COLOR_RE.test(classes)) {
            out.push({ line: i + 1, excerpt: line });
          }
        });
      }
      return out;
    },
  },
  {
    id: 'E-5',
    severity: 'white',
    title: 'Extreme border-radius on a card',
    why: '24px+ on a card is a bubble. Full-pill belongs to tags and buttons only.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      for (const block of ctx.blocks()) {
        for (const d of declsMatching(block, /^border(-[a-z]+)?-radius$/)) {
          if (/9999|50%|100%|9rem|999px/.test(d.value)) continue; // deliberate pill
          const px = maxPxIn(d.value);
          if (px != null && px >= 24) {
            out.push({ line: d.line, excerpt: `${block.selector} { border-radius: ${d.value} }` });
          }
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          const arbitrary = classes.match(/\brounded(?:-[a-z]+)?-\[(\d+)px\]/);
          if (/\brounded-3xl\b/.test(classes) || (arbitrary && Number(arbitrary[1]) >= 24)) {
            out.push({ line: i + 1, excerpt: line });
          }
        });
      }
      return out;
    },
  },
  {
    id: 'E-8',
    severity: 'orange',
    title: 'Ad-hoc shadow outside the surface system',
    why: 'A hand-written box-shadow forks the elevation scale. Use the surface/elevation token.',
    fileTypes: [...STYLE_FILES, ...MARKUP_FILES],
    testFile(content, ctx) {
      const out = [];

      if (!ctx.isTokenFile) {
        for (const block of ctx.blocks()) {
          if (/:focus/i.test(block.selector)) continue; // focus rings are box-shadow by design
          const shadow = decl(block, 'box-shadow');
          if (!shadow) continue;
          const value = shadow.value.trim();
          if (/^none$/i.test(value)) continue;
          if (/var\(\s*--|theme\(|\$[\w-]+|@[\w-]+/.test(value)) continue; // token-driven
          out.push({ line: shadow.line, excerpt: `${block.selector} { box-shadow: ${value} }` });
        }
      }

      if (ctx.isMarkupFile) {
        ctx.lines.forEach((line, i) => {
          const classes = ctx.classText(line);
          if (!classes) return;
          if (/\bshadow-\[[^\]]+\]/.test(classes)) out.push({ line: i + 1, excerpt: line });
        });
      }
      return out;
    },
  },
];
