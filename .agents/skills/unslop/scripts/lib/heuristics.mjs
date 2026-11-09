// heuristics.mjs — shared context guards used by more than one rule module.

/** CSS properties whose value carries a colour. */
const COLOR_PROP_RE =
  /\b(color|background|background-color|background-image|border|border-[a-z]+|outline|outline-color|box-shadow|text-shadow|fill|stroke|caret-color|text-decoration-color|accent-color|stop-color)\s*:/i;

/** Style-carrying contexts inside a JS/markup file. */
const STYLE_HOST_RE =
  /(style\s*=|styled[.(`]|css`|createGlobalStyle|makeStyles|sx\s*=|StyleSheet\.create|:root|@media|keyframes)/i;

const CUSTOM_PROP_DEF_RE = /^\s*(--[\w-]+|\$[\w-]+|@[\w-]+)\s*:/;

export const HEX_RE = /#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b/g;

const PAINT_ATTR_RE = /\b(?:fill|stroke)\s*=\s*(?:\{\s*)?["']([^"']*)["']/g;

/** Hex values written as fill/stroke attributes, including JSX `fill={"#…"}`. */
function paintAttributeHexes(line) {
  const out = [];
  PAINT_ATTR_RE.lastIndex = 0;
  let match;
  while ((match = PAINT_ATTR_RE.exec(line)) !== null) {
    HEX_RE.lastIndex = 0;
    const hits = match[1].match(HEX_RE);
    if (hits) out.push(...hits);
  }
  return out;
}

/**
 * Raw hex colours on this line that sit in a style context.
 * A custom-property definition is silent only in a token file, and only
 * that declaration: `--a: #123; color: #123` still reports the usage.
 * Outside a token file, `--card-accent: #ff3b00` is a B-1 hit.
 * An inline SVG does not go quiet: a hit inside `<svg>` is tagged
 * `svgExceptionCandidate` for B-1.
 */
export function rawHexOnLine(line, ctx) {
  const hexes = [];
  for (const chunk of line.split(';')) {
    if (ctx.isTokenFile && CUSTOM_PROP_DEF_RE.test(chunk)) continue;
    const isStyleChunk =
      ctx.isStyleFile || COLOR_PROP_RE.test(chunk) || STYLE_HOST_RE.test(chunk) || CUSTOM_PROP_DEF_RE.test(chunk);
    const found = isStyleChunk ? (chunk.match(HEX_RE) ?? []) : paintAttributeHexes(chunk);
    hexes.push(...found);
  }
  if (hexes.length === 0) return hexes;
  if (ctx.svgLines?.has(ctx.lineNo)) hexes.svgExceptionCandidate = true;
  return hexes;
}

/** 1-based line number of a character offset inside content. */
export function lineOfIndex(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === '\n') line++;
  return line;
}

/** Heading levels in document order, as {level, line}. */
export function headingLevels(ctx) {
  const out = [];
  if (ctx.ext === '.md') {
    let inFence = false;
    ctx.lines.forEach((line, i) => {
      if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
      if (inFence) return;
      const m = line.match(/^(#{1,6})\s+\S/);
      if (m) out.push({ level: m[1].length, line: i + 1 });
    });
    return out;
  }
  ctx.lines.forEach((line, i) => {
    const re = /<h([1-6])\b/gi;
    let m;
    while ((m = re.exec(line)) !== null) out.push({ level: Number(m[1]), line: i + 1 });
  });
  return out;
}

/** Selector looks like display type, where tight tracking / small line-height is intentional. */
export function isDisplaySelector(selector = '') {
  return /(^|[\s.,#:>])(h[1-4]\b|\.?(display|hero|headline|heading|title|kicker|eyebrow|overline)[\w-]*)/i.test(
    selector,
  );
}

/** Selector looks like small-print UI, where <14px / tight padding is intentional. */
export function isSmallPrintSelector(selector = '') {
  return /(caption|label|badge|chip|tag|pill|meta|footnote|small|tooltip|legend|kbd|code|sup|sub|breadcrumb|counter|helper|hint|overline|eyebrow|kicker)/i.test(
    selector,
  );
}

/** Selector looks like a container or control — the place J-3 padding matters. */
export function isContainerSelector(selector = '') {
  return /(button|btn|card|panel|modal|dialog|sheet|popover|dropdown|menu|input|field|select|textarea|nav|header|footer|section|container|wrapper|toolbar|tab|row|cell|list-item|item)/i.test(
    selector,
  );
}

/** Strip tags and code so copy rules see prose, not markup. */
export function textOnly(line) {
  return line
    .replace(/<[^>]*>/g, ' ')
    .replace(/`[^`]*`/g, ' ')
    .replace(/https?:\/\/\S+/g, ' ');
}
