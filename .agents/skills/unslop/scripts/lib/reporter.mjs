// reporter.mjs — human table + JSON output for detector findings.

export const SEVERITY_ORDER = { red: 0, orange: 1, white: 2 };
const SEVERITY_LABEL = { red: 'RED', orange: 'ORANGE', white: 'WHITE' };
const SEVERITY_COLOR = { red: '[31m', orange: '[33m', white: '[37m' };
const RESET = '[0m';
const DIM = '[2m';
const BOLD = '[1m';

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.rule.localeCompare(b.rule) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
}

export function countBySeverity(findings) {
  const counts = { red: 0, orange: 0, white: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

function pad(text, width) {
  const t = String(text);
  return t.length >= width ? t : t + ' '.repeat(width - t.length);
}

function truncate(text, width) {
  const t = String(text);
  return t.length <= width ? t : `${t.slice(0, width - 1)}…`;
}

export function toJson(findings) {
  return JSON.stringify(
    findings.map((f) => ({
      rule: f.rule,
      severity: f.severity,
      title: f.title,
      why: f.why,
      file: f.file,
      line: f.line,
      excerpt: f.excerpt,
      ...(f.note ? { note: f.note } : {}),
      ...(f.exceptionCandidate ? { exceptionCandidate: f.exceptionCandidate } : {}),
    })),
    null,
    2,
  );
}

export function toTable(findings, { color = false, truncated = 0, scanned = 0, rulesRun = 0 } = {}) {
  const c = (code, s) => (color ? `${code}${s}${RESET}` : s);
  if (findings.length === 0) {
    return `${c(BOLD, 'unslop')} — no deterministic slop found in ${scanned} file(s), ${rulesRun} rule(s) run.`;
  }

  const rows = findings.map((f) => ({
    rule: f.rule,
    sev: SEVERITY_LABEL[f.severity] ?? f.severity,
    where: `${f.file}:${f.line}`,
    excerpt: truncate(f.excerpt, 64),
    severity: f.severity,
  }));

  const wRule = Math.max(4, ...rows.map((r) => r.rule.length));
  const wSev = Math.max(3, ...rows.map((r) => r.sev.length));
  const wWhere = Math.min(60, Math.max(5, ...rows.map((r) => r.where.length)));

  const lines = [];
  lines.push(
    c(BOLD, `${pad('RULE', wRule)}  ${pad('SEV', wSev)}  ${pad('FILE:LINE', wWhere)}  EXCERPT`),
  );
  lines.push(c(DIM, '-'.repeat(wRule + wSev + wWhere + 6 + 20)));
  for (const r of rows) {
    lines.push(
      `${pad(r.rule, wRule)}  ${c(SEVERITY_COLOR[r.severity] ?? '', pad(r.sev, wSev))}  ${pad(
        truncate(r.where, wWhere),
        wWhere,
      )}  ${r.excerpt}`,
    );
  }

  const counts = countBySeverity(findings);
  lines.push('');
  lines.push(
    `${findings.length} finding(s) in ${scanned} file(s) — ` +
      `${c(SEVERITY_COLOR.red, `${counts.red} red`)}, ` +
      `${c(SEVERITY_COLOR.orange, `${counts.orange} orange`)}, ` +
      `${counts.white} white.`,
  );
  if (truncated > 0) lines.push(c(DIM, `(${truncated} more suppressed by --max-findings)`));

  const seen = new Map();
  for (const f of findings) if (!seen.has(f.rule)) seen.set(f.rule, f);
  lines.push('');
  lines.push(c(BOLD, 'Rules triggered:'));
  for (const [id, f] of [...seen.entries()].sort()) {
    lines.push(`  ${pad(id, wRule)}  ${f.title}`);
  }
  return lines.join('\n');
}
