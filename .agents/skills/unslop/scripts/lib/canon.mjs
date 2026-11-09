import { sha256Hex } from './sha256.mjs';

export class CanonError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CanonError';
    this.code = code;
  }
}

const reject = (code, message) => { throw new CanonError(code, message); };
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const VERDICT_KINDS = new Set(['unconditional-bad', 'deprecated', 'conditional']);
const DEFAULT_VERDICTS = new Set(['bad-unless', 'ok-unless']);
const MAX_CONDITION_DEPTH = 32;

function rejectPolarity(rule) {
  if (Object.hasOwn(rule, 'bad-when') || Object.hasOwn(rule, 'ok-when') ||
      rule.verdictKind === 'bad-when' || rule.verdictKind === 'ok-when' ||
      rule.defaultVerdict === 'bad-when' || rule.defaultVerdict === 'ok-when') {
    reject('SCHEMA', 'bad-when/ok-when are not a verdict polarity');
  }
}

function validateConditionLeaf(leaf, ids) {
  if (!leaf || !nonempty(leaf.id) || !nonempty(leaf.text) || !nonempty(leaf.predicate)) {
    reject('SCHEMA', 'Invalid condition leaf');
  }
  if (Object.hasOwn(leaf, 'value')) reject('SCHEMA', 'Condition leaf must not store a value');
  if (ids.has(leaf.id)) reject('SCHEMA', 'Duplicate condition leaf id');
  ids.add(leaf.id);
}

function validateConditionNode(node, { root = false, depth = 1, ids } = {}) {
  if (depth > MAX_CONDITION_DEPTH) reject('SCHEMA', 'Condition tree exceeds depth 32');
  if (!node || typeof node !== 'object' || Array.isArray(node)) reject('SCHEMA', 'Invalid condition tree');
  if (!Object.hasOwn(node, 'join')) {
    if (root) reject('SCHEMA', 'Condition tree must be and/or');
    validateConditionLeaf(node, ids);
    return;
  }
  if (node.join !== 'and' && node.join !== 'or') reject('SCHEMA', 'Condition join must be and or or');
  const listKeys = ['groups', 'items', 'children'].filter(key => Object.hasOwn(node, key));
  if (listKeys.length !== 1) reject('SCHEMA', 'Condition tree is empty');
  const children = node[listKeys[0]];
  if (!Array.isArray(children) || children.length === 0) reject('SCHEMA', 'Condition tree is empty');
  for (const child of children) validateConditionNode(child, { depth: depth + 1, ids });
}

function validateExceptions(rule) {
  if (!Object.hasOwn(rule, 'exceptions')) return;
  if (!Array.isArray(rule.exceptions)) reject('SCHEMA', 'Invalid exceptions');
  const ids = new Set();
  for (const item of rule.exceptions) {
    if (!item || !nonempty(item.id) || ids.has(item.id) || !nonempty(item.text) || !nonempty(item.predicate)) {
      reject('SCHEMA', 'Invalid exception');
    }
    ids.add(item.id);
  }
}

function validateVerdict(rule) {
  rejectPolarity(rule);
  if (!Object.hasOwn(rule, 'verdictKind')) {
    if (Object.hasOwn(rule, 'defaultVerdict') || Object.hasOwn(rule, 'conditions')) {
      reject('SCHEMA', 'defaultVerdict and conditions require verdictKind');
    }
    return;
  }
  if (!VERDICT_KINDS.has(rule.verdictKind)) reject('SCHEMA', 'Invalid verdictKind');
  validateExceptions(rule);
  if (rule.verdictKind === 'conditional') {
    if (!DEFAULT_VERDICTS.has(rule.defaultVerdict)) reject('SCHEMA', 'conditional requires defaultVerdict');
    const leafIds = new Set();
    validateConditionNode(rule.conditions, { root: true, ids: leafIds });
    for (const item of rule.exceptions ?? []) {
      if (leafIds.has(item.id)) reject('SCHEMA', 'Condition leaf id collides with an exception id');
    }
    return;
  }
  if (Object.hasOwn(rule, 'defaultVerdict') || Object.hasOwn(rule, 'conditions')) {
    reject('SCHEMA', 'defaultVerdict and conditions require verdictKind conditional');
  }
  if (rule.verdictKind === 'deprecated') {
    if (!Array.isArray(rule.replacedBy) || !rule.replacedBy.length || !rule.replacedBy.every(nonempty)) {
      reject('SCHEMA', 'deprecated requires replacedBy');
    }
    if (rule.replacedBy.includes(rule.id)) reject('SCHEMA', 'deprecated cannot be replaced by itself');
  }
}
const canonical = value => JSON.stringify(value, (_, item) =>
  item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]]))
    : item);

/** Hash the complete payload; a checksum proves integrity, not publisher identity. */
export function canonChecksum(payload) {
  return sha256Hex(canonical(payload));
}

function freeze(value) {
  for (const child of Object.values(value)) {
    if (child && typeof child === 'object') freeze(child);
  }
  return Object.freeze(value);
}

/** Transport-independent wire contract. Never evaluates code supplied by a canon. */
export function validateCanon(envelope, expectedVersion) {
  const { payload, checksum } = envelope ?? {};
  if (!payload || payload.schemaVersion !== 1) reject('SCHEMA', 'Unsupported canon schema');
  if (!nonempty(payload.version) || payload.version === 'latest') reject('SCHEMA', 'Missing immutable version');
  if (expectedVersion && payload.version !== expectedVersion) reject('REVISION', 'Requested revision was not returned');
  if (!nonempty(payload.publishedAt) || !Number.isFinite(Date.parse(payload.publishedAt)) ||
      !nonempty(payload.source) || !nonempty(payload.license) || !nonempty(payload.content) ||
      !Array.isArray(payload.rules) || !payload.rules.length) reject('SCHEMA', 'Incomplete canon provenance or content');
  const ids = new Set();
  for (const rule of payload.rules) {
    if (!rule || !nonempty(rule.id) || ids.has(rule.id) || !nonempty(rule.source) ||
        !['hard', 'soft'].includes(rule.strength) || !['detector', 'judgement'].includes(rule.mode)) {
      reject('SCHEMA', 'Invalid or duplicate rule');
    }
    validateVerdict(rule);
    ids.add(rule.id);
  }
  if (!/^[a-f0-9]{64}$/.test(checksum ?? '') || checksum !== canonChecksum(payload)) {
    reject('CHECKSUM', 'Canon checksum mismatch');
  }
  return freeze(structuredClone(envelope));
}

/** One instance is one run. Concurrent calls also resolve latest only once. */
export function createCanonRun({ endpoint, read, version, cache = new Map(), timeoutMs = 5000 }) {
  if (!nonempty(endpoint) || typeof read !== 'function' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    reject('CONFIG', 'Endpoint, reader and positive timeout are required');
  }
  if (version !== undefined && (!nonempty(version) || version === 'latest')) {
    reject('CONFIG', 'Omit version for latest, or provide an immutable revision');
  }
  let resolution;
  async function resolve() {
    const controller = new AbortController();
    let timer;
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => read({ endpoint, version, signal: controller.signal })),
        new Promise((_, rejectTimeout) => {
          timer = setTimeout(() => {
            controller.abort();
            rejectTimeout(new CanonError('TIMEOUT', 'Canon request timed out'));
          }, timeoutMs);
        }),
      ]);
      const snapshot = validateCanon(result, version);
      const key = JSON.stringify([endpoint, snapshot.payload.version]);
      const existing = cache.get(key);
      if (existing && validateCanon(existing, snapshot.payload.version).checksum !== snapshot.checksum) {
        reject('REVISION_CHANGED', 'Immutable revision changed; refusing replacement');
      }
      cache.set(key, snapshot);
      return freeze({ snapshot, endpoint, origin: 'remote', stale: false });
    } catch (error) {
      // Integrity and protocol failures never fall back to apparently successful data.
      const transportFailure = !(error instanceof CanonError) || ['TIMEOUT', 'OFFLINE'].includes(error.code);
      if (transportFailure && version) {
        const cached = cache.get(JSON.stringify([endpoint, version]));
        if (cached) return freeze({ snapshot: validateCanon(cached, version), endpoint, origin: 'cache', stale: true });
      }
      throw error instanceof CanonError ? error : new CanonError('OFFLINE', 'Canon source unavailable');
    } finally {
      clearTimeout(timer);
    }
  }
  return Object.freeze({ load: () => (resolution ??= resolve()) });
}

/** Missing machine coverage is explicit; an unknown ID can never become a pass. */
export function ruleCoverage(snapshot, ruleId, detectorIds = []) {
  const rule = snapshot.payload.rules.find(item => item.id === ruleId);
  if (!rule) reject('UNKNOWN_RULE', `Rule ${ruleId} is not present in the pinned canon`);
  return Object.freeze({
    ruleId, version: snapshot.payload.version, checksum: snapshot.checksum,
    source: rule.source, strength: rule.strength,
    coverage: rule.mode === 'judgement' ? 'judgement' : detectorIds.includes(ruleId) ? 'detector' : 'unsupported',
  });
}
