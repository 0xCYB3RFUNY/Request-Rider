// scan.mjs — builds the per-file context every rule sees, and runs rules over it.
import fs from 'node:fs';
import path from 'node:path';
import { parseBlocks } from './css.mjs';

/**
 * A token file is named like one, or sits on an explicit path relative to the
 * project root. The root folder's own name is not that path: a checkout in
 * `tokens/` or `design-tokens/` does not silence every stylesheet, and neither
 * does a generic `tokens/` directory (`src/tokens/colors.css`).
 * Names: `tokens.*`, `*.tokens.*`, an SCSS partial `_tokens.scss` (`_tokens.*`),
 * `design-tokens.*`. Explicit relative paths: `design-tokens/` and `theme/tokens/`.
 * `globals.css`, `root`, `system`, `ds`, `vars`, `palette` and a bare `theme/`
 * directory are ordinary CSS.
 */
const TOKEN_BASENAME_RE =
  /^(?:_tokens|tokens|design-tokens)(?:[./_-]|$)|[.]tokens(?:[./_-]|$)/i;
const TOKEN_EXPLICIT_REL_RE =
  /(?:^|\/)design-tokens(?:\/|$)|(?:^|\/)theme\/tokens(?:\/|$)/i;

const STYLE_EXT = new Set(['.css', '.scss']);
const MARKUP_EXT = new Set(['.html', '.jsx', '.tsx', '.vue', '.svelte']);
/** Markup formats that can carry a real stylesheet inside <style> tags. */
const EMBEDDED_STYLE_EXT = new Set(['.html', '.vue', '.svelte']);

/**
 * A token/definition file is where a design system keeps source values.
 * E-8 still skips the whole file. B-1 does not: a custom-property
 * definition is silent only inside a token file, and only that declaration.
 */
function looksLikeTokenFile(relPath, rootDir) {
  let normalized = String(relPath ?? '').replace(/\\/g, '/').replace(/^\.\//, '');
  if (rootDir && path.isAbsolute(normalized)) {
    const rel = path.relative(rootDir, normalized);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return false;
    normalized = rel.replace(/\\/g, '/');
  }
  const base = normalized.split('/').pop() ?? '';
  return TOKEN_BASENAME_RE.test(base) || TOKEN_EXPLICIT_REL_RE.test(normalized);
}

/** Lines inside an inline <svg>…</svg>. B-1 reports them as a logo-colour candidate. */
function svgLineSet(lines) {
  const set = new Set();
  let depth = 0;
  lines.forEach((line, idx) => {
    const opens = (line.match(/<svg\b/gi) || []).length;
    const closes = (line.match(/<\/svg>/gi) || []).length;
    if (depth > 0 || opens > 0) set.add(idx + 1);
    depth += opens - closes;
    if (depth < 0) depth = 0;
  });
  return set;
}

const STYLE_TAG_RE = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;

/**
 * A copy of the document where everything outside <style>…</style> is blanked
 * out. Line numbers stay true, so CSS rules can read inline stylesheets in
 * .html/.vue/.svelte exactly as they read a .css file.
 */
function styleProjection(content) {
  const chars = new Array(content.length);
  for (let i = 0; i < content.length; i++) chars[i] = content[i] === '\n' ? '\n' : ' ';
  let found = false;
  let m;
  STYLE_TAG_RE.lastIndex = 0;
  while ((m = STYLE_TAG_RE.exec(content)) !== null) {
    const start = m.index + m[0].indexOf('>') + 1;
    for (let k = 0; k < m[1].length; k++) chars[start + k] = m[1][k];
    found = true;
  }
  return found ? chars.join('') : null;
}

const CLASS_ATTR_RE =
  /(?:class|className|class:list|:class)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{`([^`]*)`\}|`([^`]*)`|\{"([^"]*)"\}|\{'([^']*)'\})/g;
const UTIL_CALL_RE = /\b(?:cn|clsx|classnames|classNames|cva|tw|twMerge|twJoin)\s*\(/;

/**
 * Text on this line that is plausibly a class list. Keeps utility-class rules
 * (B-2, B-3, G-1 …) from firing on prose, imports or unrelated strings.
 */
export function classText(line, ext) {
  if (ext === '.md') return '';
  const parts = [];
  let m;
  CLASS_ATTR_RE.lastIndex = 0;
  while ((m = CLASS_ATTR_RE.exec(line)) !== null) {
    parts.push(m[1] ?? m[2] ?? m[3] ?? m[4] ?? m[5] ?? m[6] ?? '');
  }
  if (/@apply\b/.test(line)) parts.push(line);
  if (UTIL_CALL_RE.test(line)) parts.push(line);
  return parts.join(' ');
}

export function buildContext(file, rootDir) {
  const content = fs.readFileSync(file, 'utf8');
  const lines = content.split(/\r?\n/);
  const ext = path.extname(file).toLowerCase();
  const rel = path.relative(rootDir, file) || path.basename(file);
  const ctx = {
    file,
    rel,
    ext,
    content,
    lines,
    lineNo: 0,
    isStyleFile: STYLE_EXT.has(ext),
    isMarkupFile: MARKUP_EXT.has(ext),
    isTokenFile: looksLikeTokenFile(rel, rootDir),
    // A file that already consumes design tokens proves the system exists —
    // a raw value here is DS-2 (bypassing the DS), not merely B-1.
    tokenAware:
      /var\(\s*--/.test(content) ||
      /\btheme\(\s*['"]/.test(content) ||
      /from\s+['"][^'"]*(design-system|tokens)['"]/.test(content),
    svgLines: svgLineSet(lines),
    _blocks: null,
  };
  ctx.blocks = () => {
    if (ctx._blocks == null) {
      if (ctx.isStyleFile) {
        ctx._blocks = parseBlocks(content);
      } else if (EMBEDDED_STYLE_EXT.has(ext)) {
        const projection = styleProjection(content);
        ctx._blocks = projection ? parseBlocks(projection) : [];
      } else {
        ctx._blocks = [];
      }
    }
    return ctx._blocks;
  };
  ctx.classText = (line) => classText(line, ext);
  ctx.lineAt = (n) => lines[n - 1] ?? '';
  return ctx;
}

function excerptOf(text) {
  const t = String(text ?? '').trim().replace(/\s+/g, ' ');
  return t.length > 120 ? `${t.slice(0, 117)}…` : t;
}

function normalize(result, rule, ctx, fallbackLine) {
  if (!result) return [];
  const list = Array.isArray(result) ? result : [result];
  return list
    .filter(Boolean)
    .map((f) => {
      const item = f === true ? {} : f;
      const line = item.line ?? fallbackLine ?? 1;
      return {
        rule: rule.id,
        severity: rule.severity,
        title: rule.title,
        why: rule.why,
        file: ctx.rel,
        absPath: ctx.file,
        line,
        excerpt: excerptOf(item.excerpt ?? ctx.lineAt(line)),
        note: item.note,
        ...(item.exceptionCandidate ? { exceptionCandidate: item.exceptionCandidate } : {}),
      };
    });
}

function ruleAppliesTo(rule, ctx) {
  if (!rule.fileTypes || rule.fileTypes.length === 0) return true;
  return rule.fileTypes.includes(ctx.ext);
}

/** Run one file through the given rules. */
export function runFile(ctx, rules) {
  const findings = [];
  for (const rule of rules) {
    if (!ruleAppliesTo(rule, ctx)) continue;
    if (typeof rule.testFile === 'function') {
      findings.push(...normalize(rule.testFile(ctx.content, ctx), rule, ctx, 1));
      continue;
    }
    if (typeof rule.test === 'function') {
      for (let i = 0; i < ctx.lines.length; i++) {
        ctx.lineNo = i + 1;
        findings.push(...normalize(rule.test(ctx.lines[i], ctx), rule, ctx, i + 1));
      }
    }
  }
  return findings;
}

/** Rules that can only answer once they have seen the whole project. */
export function runProject(contexts, rules) {
  const findings = [];
  for (const rule of rules) {
    if (typeof rule.testProject !== 'function') continue;
    const scoped = contexts.filter((c) => ruleAppliesTo(rule, c));
    const result = rule.testProject(scoped);
    if (!result) continue;
    for (const item of Array.isArray(result) ? result : [result]) {
      if (!item) continue;
      findings.push({
        rule: rule.id,
        severity: rule.severity,
        title: rule.title,
        why: rule.why,
        file: item.file ?? '(project)',
        absPath: item.absPath ?? null,
        line: item.line ?? 1,
        excerpt: excerptOf(item.excerpt ?? rule.title),
        note: item.note,
      });
    }
  }
  return findings;
}
