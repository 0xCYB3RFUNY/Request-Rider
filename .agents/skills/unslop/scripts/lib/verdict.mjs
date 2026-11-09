import { evidenceKey, matchingFact } from './project-context.mjs';

/** One status per finding. Absent verdictKind stays legacy and gets no status. */

export const FINDING_STATUSES = Object.freeze([
  'violation',
  'exception',
  'needs-decision',
  'warning',
  'not-applicable',
]);

const REPLACED_GLOSS = {
  'DS-2a': 'a literal value used although a matching token is available',
  'DS-2b': 'a local re-implementation of something the library provides',
};

export const EXAMPLE_RULES = {
  'B-1': {
    id: 'B-1',
    statement: 'Component styles hardcode a hex colour instead of using a token.',
    source: 'UNKNOWN',
    strength: 'hard',
    mode: 'judgement',
    verdictKind: 'unconditional-bad',
    exceptions: [
      { id: 'brand-svg-logo', text: 'The colour belongs to an SVG brand logo', predicate: 'finding.isBrandColorInSvgLogo' },
      { id: 'token-color-definition', text: 'The line defines a token colour inside a token file', predicate: 'finding.isTokenColorDefinitionLine' },
    ],
  },
  'B-2': {
    id: 'B-2',
    statement: 'Markup uses a fixed Tailwind palette step where a token utility belongs.',
    source: 'UNKNOWN',
    strength: 'hard',
    mode: 'judgement',
    verdictKind: 'unconditional-bad',
    exceptions: [],
  },
  'DS-2': {
    id: 'DS-2',
    statement: 'Retired combined rule. Use DS-2a and DS-2b instead.',
    source: 'UNKNOWN',
    strength: 'soft',
    mode: 'judgement',
    verdictKind: 'deprecated',
    replacedBy: ['DS-2a', 'DS-2b'],
  },
  'DS-4': {
    id: 'DS-4',
    statement: 'Values in code no longer match the declared token source.',
    source: 'UNKNOWN',
    strength: 'soft',
    mode: 'judgement',
    verdictKind: 'conditional',
    defaultVerdict: 'ok-unless',
    conditions: {
      join: 'or',
      groups: [
        {
          join: 'and',
          items: [
            { id: 'source-declared', text: 'The project names its token source file', predicate: 'project.tokenSourceDeclared' },
            { id: 'value-drift', text: 'The value in code differs from that source', predicate: 'finding.differsFromTokenSource' },
          ],
        },
        {
          join: 'and',
          items: [
            { id: 'claims-parity', text: 'The block itself claims to match the source', predicate: 'finding.claimsSourceParity' },
            { id: 'parity-missing', text: 'It does not match', predicate: 'finding.parityMissing' },
          ],
        },
      ],
    },
    exceptions: [],
  },
};

function childrenOf(node) {
  if (Array.isArray(node?.groups)) return node.groups;
  if (Array.isArray(node?.items)) return node.items;
  if (Array.isArray(node?.children)) return node.children;
  return null;
}

function leafValue(predicate, facts) {
  if (!facts || !Object.hasOwn(facts, predicate)) return 'unknown';
  if (facts[predicate] === true) return 'true';
  if (facts[predicate] === false) return 'false';
  return 'unknown';
}

export function evaluateCondition(node, facts = {}) {
  const children = childrenOf(node);
  if (!children) return leafValue(node?.predicate, facts);
  const values = children.map(child => evaluateCondition(child, facts));
  if (node.join === 'or') {
    if (values.includes('true')) return 'true';
    if (values.every(value => value === 'false')) return 'false';
    return 'unknown';
  }
  if (values.includes('false')) return 'false';
  if (values.every(value => value === 'true')) return 'true';
  return 'unknown';
}

/** Unknown leaves that can still change this node. A true `or` child drops the rest. */
export function relevantUnknowns(node, facts = {}) {
  const children = childrenOf(node);
  if (!children) return leafValue(node?.predicate, facts) === 'unknown' ? [node] : [];
  const values = children.map(child => evaluateCondition(child, facts));
  if (node.join === 'or') {
    if (values.includes('true')) return [];
    return children.flatMap((child, index) => (values[index] === 'false' ? [] : relevantUnknowns(child, facts)));
  }
  if (values.includes('false')) return [];
  return children.flatMap((child, index) => (values[index] === 'true' ? [] : relevantUnknowns(child, facts)));
}

function questionFrom(leaf) {
  if (!leaf) return null;
  return { id: leaf.id, text: leaf.text, predicate: leaf.predicate };
}

function conditionLeaves(node, out = []) {
  const children = childrenOf(node);
  if (!node || !children) {
    if (node?.id && node?.predicate) out.push(node);
    return out;
  }
  for (const child of children) conditionLeaves(child, out);
  return out;
}

function ruleLeaves(rule) {
  return [...(rule?.exceptions ?? []), ...conditionLeaves(rule?.conditions)];
}

function resolvedFacts(rule, finding, facts, options = {}) {
  const resolved = { ...facts };
  for (const item of rule.exceptions ?? []) {
    if (Object.hasOwn(resolved, item.predicate)) continue;
    if (item.predicate === 'finding.isTokenColorDefinitionLine' || item.id === 'token-color-definition') {
      resolved[item.predicate] = finding?.isTokenColorDefinitionLine === true;
    } else if (item.predicate === 'finding.isBrandColorInSvgLogo' || item.id === 'brand-svg-logo') {
      if (finding?.exceptionCandidate !== 'brand-svg-logo') resolved[item.predicate] = false;
    }
  }
  let applied = null;
  const evidence = evidenceKey(options.evidenceRoot ?? '', finding);
  if (!evidence || typeof finding?.evidenceLine !== 'string') return { resolved, applied };
  for (const item of ruleLeaves(rule)) {
    if (Object.hasOwn(facts, item.predicate)) continue;
    if (item.predicate === 'finding.isTokenColorDefinitionLine' || item.id === 'token-color-definition') continue;
    if ((item.predicate === 'finding.isBrandColorInSvgLogo' || item.id === 'brand-svg-logo')
      && finding?.exceptionCandidate !== 'brand-svg-logo') continue;
    const fact = matchingFact(options.projectFacts, {
      ruleId: rule.id,
      conditionId: item.id,
      evidence,
      questionText: item.text,
      lineText: finding.evidenceLine,
    });
    if (!fact) continue;
    resolved[item.predicate] = fact.value;
    applied = fact;
  }
  return { resolved, applied };
}

function classifyExceptions(rule, facts) {
  const items = (rule.exceptions ?? []).map(item => ({ item, value: leafValue(item.predicate, facts) }));
  const hit = items.find(entry => entry.value === 'true');
  if (hit) return { status: 'exception', question: null };
  const unknown = items.find(entry => entry.value === 'unknown');
  if (unknown) return { status: 'needs-decision', question: questionFrom(unknown.item) };
  return { status: 'violation', question: null };
}

function classifyConditional(rule, facts) {
  const unknownException = (rule.exceptions ?? [])
    .map(item => ({ item, value: leafValue(item.predicate, facts) }))
    .find(entry => entry.value === 'unknown');
  const trueException = (rule.exceptions ?? []).some(item => leafValue(item.predicate, facts) === 'true');
  if (trueException) return { status: 'exception', question: null };
  const tree = evaluateCondition(rule.conditions, facts);
  const pending = relevantUnknowns(rule.conditions, facts);
  if (rule.defaultVerdict === 'ok-unless') {
    if (tree === 'true') return { status: 'violation', question: null };
    if (tree === 'false') return { status: 'not-applicable', question: null };
    return { status: 'needs-decision', question: questionFrom(pending[0] ?? unknownException?.item) };
  }
  if (tree === 'true') return { status: 'exception', question: null };
  if (tree === 'false') {
    if (unknownException) return { status: 'needs-decision', question: questionFrom(unknownException.item) };
    return { status: 'violation', question: null };
  }
  return { status: 'needs-decision', question: questionFrom(pending[0] ?? unknownException?.item) };
}

/**
 * @returns {{ rule: string, status: string, question: object|null, replacedBy?: string[] } | null}
 * null — legacy rule, or unconditional-bad with no candidate line.
 */
export function classifyVerdict(rule, { facts = {}, finding = null, projectFacts = [], evidenceRoot = '' } = {}) {
  if (!rule?.verdictKind) return null;
  if (rule.verdictKind === 'deprecated') {
    return {
      rule: rule.id,
      status: 'warning',
      question: null,
      replacedBy: [...(rule.replacedBy ?? [])],
    };
  }
  const { resolved, applied } = resolvedFacts(rule, finding, facts, { projectFacts, evidenceRoot });
  const answered = applied
    ? { answeredValue: applied.value, answerRevised: applied.revised === true }
    : {};
  if (rule.verdictKind === 'unconditional-bad') {
    if (!finding) return null;
    const result = classifyExceptions(rule, resolved);
    return { rule: rule.id, ...result, ...answered };
  }
  if (rule.verdictKind === 'conditional') {
    const result = classifyConditional(rule, resolved);
    return { rule: rule.id, ...result, ...answered };
  }
  return null;
}

export function applyVerdicts(rules, detectorFindings, facts = {}, evidenceByRule = {}, options = {}) {
  const byId = new Map(rules.map(rule => [rule.id, rule]));
  const out = [];
  const seen = new Set();
  for (const finding of detectorFindings) {
    const classified = classifyVerdict(byId.get(finding.rule), {
      facts,
      finding,
      projectFacts: options.projectFacts,
      evidenceRoot: options.evidenceRoot,
    });
    if (!classified) {
      out.push(finding);
      continue;
    }
    seen.add(finding.rule);
    if (classified.status === 'not-applicable') continue;
    if (silencedTokenDefinition(byId.get(finding.rule), finding)) continue;
    out.push(attachStatus(finding, classified));
  }
  for (const rule of rules) {
    if (!rule.verdictKind || seen.has(rule.id) || rule.verdictKind === 'unconditional-bad') continue;
    const classified = classifyVerdict(rule, {
      facts,
      projectFacts: options.projectFacts,
      evidenceRoot: options.evidenceRoot,
    });
    if (!classified || classified.status === 'not-applicable' || classified.status === 'exception') continue;
    const evidence = evidenceByRule[rule.id];
    out.push(attachStatus({
      rule: rule.id,
      ...(evidence?.file ? { file: evidence.file } : {}),
      ...(Number.isInteger(evidence?.line) ? { line: evidence.line } : {}),
    }, classified));
  }
  return out;
}

/** A true token-definition line is not a finding. The predicate has no unknown. */
function silencedTokenDefinition(rule, finding) {
  if (finding?.isTokenColorDefinitionLine !== true) return false;
  return (rule?.exceptions ?? []).some(item => item.id === 'token-color-definition');
}

function attachStatus(finding, classified) {
  const next = { ...finding, status: classified.status };
  if (classified.question) next.question = classified.question;
  else delete next.question;
  if (classified.replacedBy?.length) next.replacedBy = classified.replacedBy;
  if (classified.answeredValue === true || classified.answeredValue === false) {
    next.answeredValue = classified.answeredValue;
    if (classified.answerRevised) next.answerRevised = true;
  }
  return next;
}

/** Run status. A needs-decision finding is never a clean machine pass. */
export function auditRunStatus({ findings = [], coverage = [], scanned = 0, stale = false } = {}) {
  if (findings.some(finding => finding.status === 'needs-decision')) return 'findings';
  if (findings.length) return 'findings';
  if (coverage.some(rule => rule.coverage !== 'detector') || !scanned || stale) return 'needs-review';
  return 'machine-checks-clear';
}

export function headerMark({ operatorPass = false, findings = [] } = {}) {
  const decisionCount = findings.filter(finding => finding.status === 'needs-decision').length;
  const violationCount = findings.filter(finding => finding.status === 'violation').length;
  return {
    decisionCount,
    violationCount,
    hasViolation: violationCount > 0,
    showCheck: Boolean(operatorPass) && decisionCount === 0 && violationCount === 0,
  };
}

function evidenceLabel(file, line) {
  if (file && Number.isInteger(line)) return `${file}:${line}`;
  return file || '';
}

function firstHex(excerpt) {
  return String(excerpt ?? '').match(/#(?:[0-9a-fA-F]{3,8})\b/)?.[0] ?? '';
}

function quotedPalette(excerpt) {
  const head = String(excerpt ?? '').split('—')[0];
  return head.match(/\b(?:bg|text|border|ring|divide|from|via|to|outline|fill|stroke)-[\w-]+/)?.[0] ?? '';
}

const GLOBALS_ADVICE = 'Move the colours into tokens.css and import it.';

function isGlobalsCss(file) {
  return /(?:^|\/)globals\.css$/i.test(String(file ?? '').replace(/\\/g, '/'));
}

function replacementSentence(ids) {
  const parts = ids.map(id => (REPLACED_GLOSS[id] ? `${id} (${REPLACED_GLOSS[id]})` : id));
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return parts.join(', ');
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Card copy. A violation whose `or` is already true has no yes/no.
 * not-applicable is silence: no card.
 */
function yesNoQuestion(text) {
  const sentence = String(text ?? 'the condition is still unknown').trim().replace(/[.?!]+$/u, '');
  const lowered = sentence.charAt(0).toLocaleLowerCase('en') + sentence.slice(1);
  return `Question: ${lowered}? Yes / No.`;
}

export function shellToken(value) {
  const text = String(value);
  return /[\s"']/.test(text) ? `'${text.replaceAll("'", "'\\''")}'` : text;
}


function quotedPaint(excerpt) {
  const match = String(excerpt ?? '').match(/\b(?:fill|stroke)\s*=\s*(?:\{\s*)?["'][^"']*["']/);
  if (!match || !/#[0-9a-fA-F]{3,8}\b/.test(match[0])) return '';
  return match[0];
}

export function cardModel(rule, classified, { file, line, excerpt, finding, facts, storePath, reportPath } = {}) {
  if (!classified || classified.status === 'not-applicable') return null;
  const where = evidenceLabel(file, line);
  const asks = Boolean(classified.question);
  const declinedLogo = finding?.exceptionCandidate === 'brand-svg-logo'
    && (finding?.answeredValue === false || facts?.['finding.isBrandColorInSvgLogo'] === false);
  if (rule.id === 'B-1' && classified.status === 'exception' && finding?.exceptionCandidate === 'brand-svg-logo') {
    const revised = finding?.answerRevised === true;
    return {
      ruleId: 'B-1',
      status: 'exception',
      asks: false,
      heading: 'B-1 · exception',
      paragraphs: [
        revised
          ? 'Answer changed: yes, this is the brand logo → exception.'
          : 'You answered: yes, this is the brand logo → exception.',
        'The violation is lifted; this is not an acceptance check mark.',
        ...(where ? [`Evidence: ${where}.`] : []),
      ],
    };
  }
  if (rule.id === 'B-1' && classified.status === 'violation') {
    const colour = firstHex(excerpt);
    const paragraphs = [
      colour
        ? `Hardcoded colour ${colour} in component styles: violation.`
        : 'Hardcoded colour in component styles: violation.',
      declinedLogo
        ? (finding?.answerRevised
          ? 'Answer changed: not a logo → violation'
          : 'You answered: not a logo → violation')
        : 'The question "Is this colour part of an SVG brand logo?" does not apply: this is not SVG.',
    ];
    if (isGlobalsCss(file)) paragraphs.push(GLOBALS_ADVICE);
    if (where) paragraphs.push(`Evidence: ${where}.`);
    paragraphs.push('Status: violation. No check mark.');
    return {
      ruleId: 'B-1',
      status: 'violation',
      asks: false,
      heading: 'B-1 · always a violation',
      paragraphs,
    };
  }
  if (rule.id === 'B-1' && classified.question?.id === 'brand-svg-logo') {
    const paint = quotedPaint(excerpt);
    const paragraphs = [
      paint
        ? `Possible exception, not yet confirmed: an SVG brand logo colour. On the line: ${paint}.`
        : 'Possible exception, not yet confirmed: an SVG brand logo colour.',
    ];
    if (where) paragraphs.push(`Evidence: ${where}.`);
    paragraphs.push('Question: "Is this colour part of an SVG brand logo?" Yes / No.');
    paragraphs.push('Yes: brand logo, exception. No: violation.');
    if (where) paragraphs.push(`To answer, record the fact for ${where} in project-context.json and run the audit again.`);
    paragraphs.push('Until answered: no ✓.');
    return {
      ruleId: 'B-1',
      status: 'needs-decision',
      asks: true,
      heading: 'B-1 · always a violation · logo question only',
      paragraphs,
    };
  }
  if (rule.id === 'B-2') {
    const palette = quotedPalette(excerpt);
    return {
      ruleId: 'B-2',
      status: 'violation',
      asks: false,
      heading: 'B-2 · always a violation',
      paragraphs: [
        palette
          ? `Class ${palette}: violation. No exception applies.`
          : 'Tailwind palette class: violation. No exception applies.',
        ...(where ? [`Evidence: ${where}.`] : []),
        'No yes/no question.',
      ],
    };
  }
  if (rule.id === 'DS-2' && classified.status === 'warning') {
    return {
      ruleId: 'DS-2',
      status: 'warning',
      asks: false,
      heading: 'DS-2 · retired',
      paragraphs: [
        `This rule is no longer checked. Replaced by ${replacementSentence(classified.replacedBy ?? [])}.`,
        'This is a warning, not a violation and not a check mark.',
      ],
    };
  }
  if (rule.id === 'DS-4' && classified.status === 'needs-decision') {
    const prompt = classified.question?.id === 'source-declared'
      ? 'Question: does this project declare a token source? Yes / No.'
      : yesNoQuestion(classified.question?.text);
    const paragraphs = [prompt];
    if (classified.question?.id === 'source-declared') {
      paragraphs.push('Audit hint: DS-4 cannot be closed without a path to the token source (the detector has no DS-4 check, scripts/rules/ds.mjs:5).');
    }
    if (where) paragraphs.push(`Candidate evidence: ${where}.`);
    paragraphs.push('Status: no ✓.');
    return {
      ruleId: 'DS-4',
      status: 'needs-decision',
      asks: true,
      heading: 'DS-4 · needs a decision',
      paragraphs,
    };
  }
  if (rule.id === 'DS-2a' && classified.status === 'violation') {
    const colour = firstHex(excerpt);
    const paragraphs = [
      colour
        ? `This file already uses tokens, but this colour is hardcoded: ${colour}.`
        : 'This file already uses tokens, but this colour is hardcoded.',
    ];
    if (isGlobalsCss(file)) paragraphs.push(GLOBALS_ADVICE);
    if (where) paragraphs.push(`Evidence: ${where}.`);
    paragraphs.push('Status: violation. No check mark.');
    return {
      ruleId: 'DS-2a',
      status: 'violation',
      asks: false,
      heading: 'DS-2a · always a violation',
      paragraphs,
    };
  }
  if (classified.status === 'violation') {
    return {
      ruleId: rule.id,
      status: 'violation',
      asks: false,
      heading: `${rule.id} · violation`,
      paragraphs: [
        excerpt
          ? `The violation condition is already met (${excerpt}). No yes/no question.`
          : 'The violation condition is already met. No yes/no question.',
        where ? `Evidence: ${where}.` : '',
        'Status: violation. No check mark.',
      ].filter(Boolean),
    };
  }
  if (classified.status === 'exception') {
    return {
      ruleId: rule.id,
      status: 'exception',
      asks: false,
      heading: `${rule.id} · exception`,
      paragraphs: [
        'Exception confirmed. The violation is lifted; this is not an acceptance check mark.',
        where ? `Evidence: ${where}.` : '',
      ].filter(Boolean),
    };
  }
  return {
    ruleId: rule.id,
    status: classified.status,
    asks,
    heading: `${rule.id} · ${classified.status}`,
    paragraphs: where ? [`Evidence: ${where}.`] : [],
  };
}

export function showcaseCards() {
  const b1Css = classifyVerdict(EXAMPLE_RULES['B-1'], {
    finding: { file: 'card.css', line: 12, excerpt: 'color: #123456' },
  });
  const b1Svg = classifyVerdict(EXAMPLE_RULES['B-1'], {
    finding: { file: 'logo.svg', line: 4, excerpt: 'fill="#123456"', exceptionCandidate: 'brand-svg-logo' },
  });
  const b2 = classifyVerdict(EXAMPLE_RULES['B-2'], {
    finding: { file: 'card.tsx', line: 4, excerpt: 'text-gray-500' },
  });
  const ds2 = classifyVerdict(EXAMPLE_RULES['DS-2'], {});
  const ds4 = classifyVerdict(EXAMPLE_RULES['DS-4'], {});
  return [
    cardModel(EXAMPLE_RULES['B-1'], b1Css, { file: 'card.css', line: 12, excerpt: 'color: #123456' }),
    cardModel(EXAMPLE_RULES['B-1'], b1Svg, { file: 'logo.svg', line: 4, excerpt: 'fill="#123456"' }),
    cardModel(EXAMPLE_RULES['B-2'], b2, { file: 'card.tsx', line: 4, excerpt: 'text-gray-500' }),
    cardModel(EXAMPLE_RULES['DS-2'], ds2),
    cardModel(EXAMPLE_RULES['DS-4'], ds4, { file: 'tokens.css', line: 40 }),
  ];
}

/** Header and cards are projections of one findings array. */
export function presentVerdict({ operatorPass = false, findings = [], rules = [], facts = {}, storePath = '', reportPath = '' } = {}) {
  const header = headerMark({ operatorPass, findings });
  const byId = new Map(rules.map(rule => [rule.id, rule]));
  const cards = findings.map(finding => {
    if (!FINDING_STATUSES.includes(finding?.status)) return null;
    const rule = byId.get(finding.rule) ?? { id: finding.rule };
    return cardModel(rule, {
      status: finding.status,
      question: finding.question ?? null,
      replacedBy: finding.replacedBy,
    }, {
      file: finding.file,
      line: finding.line,
      excerpt: finding.excerpt,
      finding,
      facts,
      storePath,
      reportPath,
    });
  }).filter(Boolean);
  return { ...header, cards };
}

export function renderCardHtml(card) {
  if (!card) return '';
  const body = card.paragraphs.map(paragraph => (
    `<p>${escapeHtml(paragraph)}</p>`
  )).join('');
  return `<article class="finding-card" data-rule="${escapeHtml(card.ruleId)}" data-status="${escapeHtml(card.status)}" data-asks="${card.asks ? 'yes' : 'no'}">
  <h3>${escapeHtml(card.heading)}</h3>
  ${body}
</article>`;
}

export function renderVerdictHeaderHtml({ operatorPass = false, findings = [], cards = null } = {}) {
  const header = headerMark({ operatorPass, findings: findings.length ? findings : (cards ?? []).map(card => ({ status: card.status })) });
  const mark = header.showCheck ? '✓' : (operatorPass ? '' : '✗');
  const selfCheck = operatorPass
    ? 'Loop consistent (self-check).'
    : 'Loop not consistent (self-check).';
  const blocked = operatorPass && !header.showCheck
    ? ' No ✓ while a violation is open or a question is unanswered.'
    : '';
  return `<div class="verdict" role="status">
  <div class="mark" data-pass-mark="${header.showCheck ? 'yes' : 'no'}" aria-hidden="true">${mark}</div>
  <div>
    <p class="verdict-lead">Open violations: <strong>${header.violationCount}</strong></p>
    <p class="verdict-lead decision-count">Needs a decision: <strong>${header.decisionCount}</strong></p>
    <p class="self-check">${escapeHtml(selfCheck)}${escapeHtml(blocked)} A self-check does not replace an independent review and never draws a check mark over a violation.</p>
  </div>
</div>`;
}

export function buildVerdictShowcaseHtml({ operatorPass = true, cards = showcaseCards() } = {}) {
  const findings = cards.filter(Boolean).map(card => ({ rule: card.ruleId, status: card.status }));
  const header = renderVerdictHeaderHtml({ operatorPass, findings });
  const list = cards.filter(Boolean).map(renderCardHtml).join('\n');
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>UNSLOP report cards</title>
  <style>
    :root { color-scheme: light; --bg: #fafafa; --card: #fff; --border: #e4e4e7; --text: #18181b; --muted: #52525b; --ok: #15803d; --bad: #b91c1c; }
    * { box-sizing: border-box; }
    body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 0; padding: 1.25rem; line-height: 1.55; color: var(--text); background: var(--bg); }
    .wrap { max-width: 44rem; margin: 0 auto; }
    h1 { font-size: 1.5rem; margin: 0 0 0.35rem; font-weight: 650; }
    .lede { color: var(--muted); margin: 0 0 1rem; }
    .verdict { display: flex; gap: 0.75rem; align-items: flex-start; padding: 1rem 1.1rem; border-radius: 12px; border: 1px solid var(--border); background: var(--card); margin: 0 0 1.25rem; }
    .verdict .mark { font-size: 2rem; line-height: 1; font-weight: 700; min-width: 1.5rem; color: var(--bad); }
    .verdict .mark[data-pass-mark="yes"] { color: var(--ok); }
    .verdict-lead { margin: 0; font-size: 1.15rem; font-weight: 650; }
    .verdict-lead + .verdict-lead { margin-top: 0.15rem; }
    .self-check { margin: 0.45rem 0 0; color: var(--muted); font-size: 0.8rem; font-weight: 400; }
    .finding-cards { display: grid; gap: 0.75rem; }
    .finding-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.1rem; }
    .finding-card h3 { margin: 0 0 0.5rem; font-size: 1.05rem; }
    .finding-card p { margin: 0 0 0.55rem; }
    .finding-card p:last-child { margin-bottom: 0; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>UNSLOP report</h1>
    <p class="lede">Example cards. This page stores nothing: questions cannot be answered here; it is a preview only.</p>
    ${header}
    <div class="finding-cards">
      ${list}
    </div>
  </div>
</body>
</html>`;
}
