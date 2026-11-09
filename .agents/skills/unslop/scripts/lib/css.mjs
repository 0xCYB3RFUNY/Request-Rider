// css.mjs — a tiny, forgiving CSS/SCSS block reader plus value helpers.
// It is deliberately not a spec-compliant parser: it only needs to give rules
// a (selector, declarations, line) view precise enough to reason about pairs of
// properties inside the same rule.

/**
 * @returns {Array<{selector:string,startLine:number,endLine:number,depth:number,
 *                  decls:Array<{prop:string,value:string,line:number}>}>}
 */
export function parseBlocks(content) {
  const blocks = [];
  const stack = [];
  let buf = '';
  let bufStartLine = 1;
  let line = 1;
  let i = 0;
  let inString = null;
  let inComment = null;
  const n = content.length;

  const pushChar = (ch) => {
    if (buf.trim() === '') bufStartLine = line;
    buf += ch;
  };

  while (i < n) {
    const ch = content[i];
    const nx = content[i + 1];

    if (inComment) {
      if (ch === '\n') line++;
      if (inComment === 'block' && ch === '*' && nx === '/') {
        inComment = null;
        i += 2;
        continue;
      }
      if (inComment === 'line' && ch === '\n') inComment = null;
      i++;
      continue;
    }

    if (inString) {
      if (ch === '\n') line++;
      if (ch === '\\') {
        buf += content.slice(i, i + 2);
        i += 2;
        continue;
      }
      if (ch === inString) inString = null;
      buf += ch;
      i++;
      continue;
    }

    if (ch === '/' && nx === '*') {
      inComment = 'block';
      i += 2;
      continue;
    }
    if (ch === '/' && nx === '/') {
      inComment = 'line';
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = ch;
      pushChar(ch);
      i++;
      continue;
    }
    if (ch === '\n') {
      line++;
      pushChar(' ');
      i++;
      continue;
    }
    if (ch === '{') {
      const selector = buf.trim().replace(/\s+/g, ' ');
      const block = {
        selector,
        startLine: buf.trim() ? bufStartLine : line,
        endLine: line,
        depth: stack.length,
        decls: [],
      };
      blocks.push(block);
      stack.push(block);
      buf = '';
      i++;
      continue;
    }
    if (ch === '}') {
      const block = stack.pop();
      if (block) block.endLine = line;
      buf = '';
      i++;
      continue;
    }
    if (ch === ';') {
      const decl = buf.trim();
      const block = stack[stack.length - 1];
      const idx = decl.indexOf(':');
      if (block && idx > 0) {
        block.decls.push({
          prop: decl.slice(0, idx).trim().toLowerCase(),
          value: decl.slice(idx + 1).trim(),
          line: bufStartLine,
        });
      }
      buf = '';
      i++;
      continue;
    }
    pushChar(ch);
    i++;
  }

  // A trailing declaration without a semicolon before the closing brace.
  return blocks;
}

/** All declarations of a block, including the last one if it lacked a `;`. */
export function decl(block, prop) {
  return block.decls.find((d) => d.prop === prop);
}

export function declsMatching(block, re) {
  return block.decls.filter((d) => re.test(d.prop));
}

/** Convert a CSS length to px. Returns null when it cannot be resolved. */
export function toPx(value, rootPx = 16) {
  if (value == null) return null;
  const m = String(value).trim().match(/^(-?\d*\.?\d+)(px|rem|em|pt)?$/);
  if (!m) return null;
  const num = parseFloat(m[1]);
  switch (m[2]) {
    case undefined:
      return num === 0 ? 0 : null; // bare numbers are only meaningful as 0
    case 'px':
      return num;
    case 'rem':
    case 'em':
      return num * rootPx;
    case 'pt':
      return (num * 96) / 72;
    default:
      return null;
  }
}

/** Largest px length found anywhere in a value (e.g. `clamp(2rem, 5vw, 4rem)`). */
export function maxPxIn(value, rootPx = 16) {
  let max = null;
  const re = /(-?\d*\.?\d+)(px|rem|em|pt)\b/g;
  let m;
  while ((m = re.exec(String(value))) !== null) {
    const px = toPx(m[1] + m[2], rootPx);
    if (px != null && (max == null || px > max)) max = px;
  }
  return max;
}

/** All durations in a value, in milliseconds. */
export function durationsMs(value) {
  const out = [];
  const re = /(-?\d*\.?\d+)(ms|s)\b/g;
  let m;
  while ((m = re.exec(String(value))) !== null) {
    const num = parseFloat(m[1]);
    out.push(m[2] === 's' ? num * 1000 : num);
  }
  return out;
}

const NEUTRAL_HEX = /^#(?:([0-9a-f])\1\1(?:\1)?|([0-9a-f]{2})\2\2(?:\2)?)$/i;

/** true for #fff, #222, #1a1a1a … — greys, black, white. */
export function isNeutralHex(hex) {
  return NEUTRAL_HEX.test(hex.trim());
}

/** Rough "is this a chromatic colour" test for hex values. */
export function isChromaticColor(value) {
  const v = String(value).trim().toLowerCase();
  const hex = v.match(/#[0-9a-f]{3,8}\b/);
  if (hex) return !isNeutralHex(hex[0].slice(0, hex[0].length > 7 ? 7 : hex[0].length));
  if (/\b(transparent|currentcolor|inherit|none|white|black)\b/.test(v)) return false;
  if (/rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/.test(v)) {
    const [, r, g, b] = v.match(/rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/);
    const nums = [+r, +g, +b];
    return Math.max(...nums) - Math.min(...nums) > 12;
  }
  return /\b(red|blue|green|purple|violet|indigo|orange|teal|cyan|magenta|pink|gold|crimson|salmon|olive|navy|lime|aqua|fuchsia|maroon)\b/.test(
    v,
  );
}

/** Rough "is this a grey" test — used by D-4. */
export function isGreyish(value) {
  const v = String(value).trim().toLowerCase();
  if (/\b(gray|grey|silver|darkgray|darkgrey|lightgray|lightgrey|dimgray|dimgrey)\b/.test(v)) return true;
  const hex = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/);
  if (!hex) return false;
  let r;
  let g;
  let b;
  if (hex[1].length === 3) {
    [r, g, b] = hex[1].split('').map((c) => parseInt(c + c, 16));
  } else {
    r = parseInt(hex[1].slice(0, 2), 16);
    g = parseInt(hex[1].slice(2, 4), 16);
    b = parseInt(hex[1].slice(4, 6), 16);
  }
  const spread = Math.max(r, g, b) - Math.min(r, g, b);
  const mid = (r + g + b) / 3;
  return spread <= 24 && mid > 60 && mid < 200; // grey, not black/white
}
