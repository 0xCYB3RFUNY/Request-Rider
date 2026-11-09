import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

/** Sibling of canon snapshots. Not a rule payload and not a public projection. */
export const PROJECT_CONTEXT_FILENAME = 'project-context.json';

export class AnswerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AnswerError';
    this.code = 'ANSWER_USAGE';
  }
}

export function evidenceLineHash(lineText) {
  return createHash('sha256').update(String(lineText), 'utf8').digest('hex');
}

export function emptyProjectContext() {
  return { schemaVersion: 1, facts: [] };
}

export function parseEvidenceAt(at) {
  const match = /^(.*):([1-9]\d*)$/.exec(String(at ?? ''));
  if (!match?.[1]) {
    throw new AnswerError(`--at needs evidence as file:line. Got "${at ?? ''}". The fact was not recorded.`);
  }
  return { file: match[1], line: Number(match[2]), evidence: `${match[1]}:${match[2]}` };
}

export async function readEvidenceLine(filePath, line) {
  const text = await readFile(filePath, 'utf8');
  return text.split('\n')[line - 1] ?? '';
}

export async function readProjectContext(directory) {
  const file = path.join(directory, PROJECT_CONTEXT_FILENAME);
  let raw;
  try {
    raw = await readFile(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return emptyProjectContext();
    throw error;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AnswerError('project-context.json cannot be parsed. The fact was not recorded.');
  }
  if (!parsed || parsed.schemaVersion !== 1 || !Array.isArray(parsed.facts)) {
    throw new AnswerError('project-context.json must have schemaVersion 1 and a facts list. The fact was not recorded.');
  }
  return parsed;
}

/**
 * A stored answer applies only when the evidence line and the question wording
 * are still the ones the owner answered. A canon checksum is not a gate.
 */
export function matchingFact(facts, { ruleId, conditionId, evidence, questionText, lineText }) {
  const hash = evidenceLineHash(lineText ?? '');
  return (facts ?? []).find(fact => fact
    && fact.setBy === 'owner'
    && fact.ruleId === ruleId
    && fact.conditionId === conditionId
    && fact.evidence === evidence
    && fact.questionText === questionText
    && fact.evidenceHash === hash
    && (fact.value === true || fact.value === false)) ?? null;
}

export function evidenceKey(evidenceRoot, finding) {
  if (!finding?.file || !Number.isInteger(finding.line)) return '';
  const file = evidenceRoot ? `${evidenceRoot}/${finding.file}` : finding.file;
  return `${file}:${finding.line}`;
}

export async function recordProjectAnswer(directory, { card, value }) {
  const current = await readProjectContext(directory);
  const facts = current.facts.map(fact => ({ ...fact }));
  const index = facts.findIndex(fact => fact?.ruleId === card.ruleId
    && fact?.conditionId === card.conditionId
    && fact?.evidence === card.evidence);
  const next = {
    predicate: card.predicate,
    value,
    evidence: card.evidence,
    evidenceHash: card.evidenceHash,
    questionText: card.questionText,
    setBy: 'owner',
    ruleId: card.ruleId,
    conditionId: card.conditionId,
  };
  const revised = index >= 0;
  if (revised) next.revised = true;
  if (index >= 0) facts[index] = next;
  else facts.push(next);
  const document = { schemaVersion: 1, facts };
  await mkdir(directory, { recursive: true });
  await writeFile(
    path.join(directory, PROJECT_CONTEXT_FILENAME),
    `${JSON.stringify(document, null, 2)}\n`,
    'utf8',
  );
  return { document, revised };
}
