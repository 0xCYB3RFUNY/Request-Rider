// Pure routed canon core (no node: imports; Worker-safe). Routed canon: generated index + one file per topic. The agent reads the
// index once, then only the topics its project needs. Never "everything at once".
import { CanonError, canonChecksum } from './canon.mjs';

export const ROUTED_INDEX_LATEST_URI = 'unslop://canon-index/latest';
export const ROUTED_INDEX_TEMPLATE = 'unslop://canon-index/{version}';
export const ROUTED_TOPIC_TEMPLATE = 'unslop://canon-topic/{version}/{topic}';
const INDEX_PREFIX = 'unslop://canon-index/';
const TOPIC_PREFIX = 'unslop://canon-topic/';
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
// Own words only: at least 3 chars, so catalog section letters (B, DS) cannot be topics.
const TOPIC_RE = /^[a-z][a-z0-9-]{2,63}$/;
export const MAX_FILE_BYTES = 1024 * 1024;
const MAX_GLOB_LENGTH = 200;
const MAX_GLOBSTARS = 4;
const MAX_WILDCARDS = 8;
const RULE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const MAX_TITLE = 80;
// A title must not leak the rule text: not equal to, nor a prefix of, the statement
// (compared on letters and digits only, case-insensitive).
const normalized = value => String(value).toLowerCase().normalize('NFKC').replace(/[^\p{L}\p{N}]+/gu, '');
const titleLeaks = (title, statement) => normalized(statement).startsWith(normalized(title));
const titleOk = value => nonempty(value) && value.length <= MAX_TITLE && !/[\r\n]/.test(value);
export const MAX_INSTRUCTIONS_BYTES = 8 * 1024;
// Rule classes (optional): what kind of problem a rule names. Defined once per release, each with a definition.
const CLASS_ID_RE = /^[a-z][a-z-]{2,31}$/;
const MAX_CLASS_DEFINITION = 600;
// Credits (optional): third-party work a rule is adapted from, [{ name, work, url? }]. Rights attribution stays in `attribution`.
const MAX_CREDITS = 5;
const MAX_CREDIT_TEXT = 160;
const creditText = value => nonempty(value) && value.length <= MAX_CREDIT_TEXT && !/[\r\n]/.test(value);
function creditsOk(credits) {
  return Array.isArray(credits) && credits.length > 0 && credits.length <= MAX_CREDITS && credits.every(credit =>
    credit && typeof credit === 'object' && !Array.isArray(credit) && creditText(credit.name) && creditText(credit.work) &&
    (!Object.hasOwn(credit, 'url') || httpsUrl(credit.url)) &&
    Object.keys(credit).every(key => ['name', 'work', 'url'].includes(key)));
}

const encoder = new TextEncoder();
export const utf8Bytes = text => encoder.encode(String(text)).length;
const fail = (code, message) => { throw new CanonError(code, message); };
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const httpsUrl = value => { try { return new URL(value).protocol === 'https:'; } catch { return false; } };
const isDate = value => nonempty(value) && Number.isFinite(Date.parse(value));

/** Deterministic bytes: sorted keys, 2-space indent, trailing newline. */
export function stableStringify(value) {
  const sort = item => Array.isArray(item) ? item.map(sort)
    : item && typeof item === 'object'
      ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sort(item[key])]))
      : item;
  return JSON.stringify(sort(value), null, 2) + '\n';
}

export function checkVersion(version) {
  if (version === 'latest') fail('LATEST_FORBIDDEN', 'latest is not an immutable version');
  if (typeof version !== 'string' || !VERSION_RE.test(version)) fail('BAD_URI', 'Invalid version');
  return version;
}
export function checkTopic(topic) {
  if (typeof topic !== 'string' || !TOPIC_RE.test(topic)) fail('BAD_URI', 'Invalid topic name');
  return topic;
}

export function indexUri(version) {
  return version === undefined ? ROUTED_INDEX_LATEST_URI : INDEX_PREFIX + checkVersion(version);
}
export function topicUri(version, topic) {
  return `${TOPIC_PREFIX}${checkVersion(version)}/${checkTopic(topic)}`;
}

/** Parses a routed URI or returns null when it is not a routed URI at all. */
export function parseRoutedUri(uri) {
  if (uri.startsWith(INDEX_PREFIX)) {
    const rest = uri.slice(INDEX_PREFIX.length);
    if (rest === 'latest') return { kind: 'index', version: undefined };
    if (rest.includes('/')) fail('BAD_URI', 'Invalid index URI');
    return { kind: 'index', version: checkVersion(rest) };
  }
  if (uri.startsWith(TOPIC_PREFIX)) {
    const parts = uri.slice(TOPIC_PREFIX.length).split('/');
    if (parts.length !== 2) fail('BAD_URI', 'Topic URI needs exactly version/topic');
    return { kind: 'topic', version: checkVersion(parts[0]), topic: checkTopic(parts[1]) };
  }
  return null;
}

/**
 * Minimal glob: `**` / `*` / `?` / `{a,b}`; paths use forward slashes.
 * No RegExp: matching is a dynamic program over (token, position), O(tokens x path length),
 * so no pattern can backtrack exponentially or polynomially (ReDoS). Length, `**` count and
 * wildcard count are capped as well, and adjacent wildcards collapse into one.
 */
export function compileGlob(glob) {
  if (typeof glob !== 'string' || !glob.length || glob.length > MAX_GLOB_LENGTH) fail('SCHEMA', 'Glob is empty or too long');
  if ((glob.match(/\*\*/g) ?? []).length > MAX_GLOBSTARS) fail('SCHEMA', 'Too many ** in glob');
  if ((glob.match(/\*+/g) ?? []).length > MAX_WILDCARDS) fail('SCHEMA', 'Too many wildcards in glob');
  // Tokens: {t:'lit', v} | {t:'one'} | {t:'seg'} (* within a segment) | {t:'any'} (**) | {t:'dir'} (**/) | {t:'alt', v:[...]}
  const tokens = [];
  const STARS = new Set(['seg', 'any', 'dir']);
  const push = token => {
    const last = tokens[tokens.length - 1];
    if (STARS.has(token.t) && STARS.has(last?.t)) {
      // dir+dir = dir; seg+seg = seg; any other adjacent pair is equivalent to `any`.
      if (last.t !== token.t) tokens[tokens.length - 1] = { t: 'any' };
    } else tokens.push(token);
  };
  for (let i = 0; i < glob.length; i++) {
    const char = glob[i];
    if (char === '*') {
      let run = 1;
      while (glob[i + run] === '*') run++;
      if (run === 1) push({ t: 'seg' });
      else if (glob[i + run] === '/') { push({ t: 'dir' }); i += run; continue; }
      else push({ t: 'any' });
      i += run - 1;
    } else if (char === '?') push({ t: 'one' });
    else if (char === '{') {
      const end = glob.indexOf('}', i);
      if (end < 0) fail('SCHEMA', 'Unclosed brace in glob');
      const parts = glob.slice(i + 1, end).split(',');
      if (parts.some(part => /[*?{}]/.test(part))) fail('SCHEMA', 'Wildcards inside braces are not supported');
      push({ t: 'alt', v: parts });
      i = end;
    } else if (char === '}') fail('SCHEMA', 'Unbalanced brace in glob');
    else push({ t: 'lit', v: char });
  }
  return Object.freeze({ glob, test(file) {
    const n = file.length;
    // reach[j] = token prefix matched exactly file[0..j)
    let reach = new Uint8Array(n + 1); reach[0] = 1;
    for (const token of tokens) {
      const next = new Uint8Array(n + 1);
      if (token.t === 'any') {
        let on = 0;
        for (let j = 0; j <= n; j++) { on ||= reach[j]; next[j] = on; }
      } else if (token.t === 'seg') {
        let on = 0;
        for (let j = 0; j <= n; j++) { on = reach[j] || (on && file[j - 1] !== '/') ? 1 : 0; next[j] = on; }
      } else if (token.t === 'dir') {
        let on = 0;
        for (let j = 0; j <= n; j++) {
          if (reach[j]) { next[j] = 1; on = 1; }
          if (on && j < n && file[j] === '/') next[j + 1] = 1;
        }
      } else {
        for (let j = 0; j < n; j++) {
          if (!reach[j]) continue;
          if (token.t === 'lit') { if (file[j] === token.v) next[j + 1] = 1; }
          else if (token.t === 'one') { if (file[j] !== '/') next[j + 1] = 1; }
          else for (const part of token.v) if (file.startsWith(part, j)) next[j + part.length] = 1;
        }
        if (token.t === 'alt' && reach[n] && token.v.includes('')) next[n] = 1;
      }
      reach = next;
    }
    return reach[n] === 1;
  } });
}

/** Validates release/index class definitions: { id: { title, definition } }. */
function checkClasses(classes, where) {
  if (!classes || typeof classes !== 'object' || Array.isArray(classes) || !Object.keys(classes).length) {
    fail('SCHEMA', `${where}: classes must be a non-empty object`);
  }
  for (const [id, entry] of Object.entries(classes)) {
    if (!CLASS_ID_RE.test(id)) fail('SCHEMA', `${where}: invalid class id ${id}`);
    if (!titleOk(entry?.title) || !nonempty(entry?.definition) || entry.definition.length > MAX_CLASS_DEFINITION ||
        Object.keys(entry).some(key => key !== 'title' && key !== 'definition')) {
      fail('SCHEMA', `${where}: class ${id} needs a one-line title and a definition`);
    }
  }
  return classes;
}

// classes: the release's class map; null skips the membership check (rule hashing).
function ruleRecord(record, topics, classes = null) {
  if (!record || !RULE_ID_RE.test(record.id ?? '')) fail('SCHEMA', 'Rule record needs a valid id');
  if (!Object.hasOwn(topics, record.topic)) fail('SCHEMA', `Rule ${record.id} names an unknown topic`);
  if (![record.statement, record.source, record.license].every(nonempty)) fail('SCHEMA', `Rule ${record.id} is incomplete`);
  if (!titleOk(record.title)) fail('SCHEMA', `Rule ${record.id} needs a one-line title of at most ${MAX_TITLE} chars`);
  if (titleLeaks(record.title, record.statement)) fail('SCHEMA', `Rule ${record.id} title repeats the start of its statement`);
  if (!['detector', 'judgement'].includes(record.mode)) fail('SCHEMA', `Rule ${record.id} has an invalid mode`);
  if (!['hard', 'soft'].includes(record.strength)) fail('SCHEMA', `Rule ${record.id} has an invalid strength`);
  if (Object.hasOwn(record, 'attribution') && !nonempty(record.attribution)) fail('SCHEMA', `Rule ${record.id} has an empty attribution`);
  if (Object.hasOwn(record, 'licenseUrl') && !httpsUrl(record.licenseUrl)) fail('SCHEMA', `Rule ${record.id} has an invalid licenseUrl`);
  if (Object.hasOwn(record, 'class')) {
    if (!CLASS_ID_RE.test(record.class ?? '')) fail('SCHEMA', `Rule ${record.id} has an invalid class`);
    if (classes !== null && !Object.hasOwn(classes ?? {}, record.class)) fail('SCHEMA', `Rule ${record.id} names an undefined class`);
  }
  if (Object.hasOwn(record, 'credits') && !creditsOk(record.credits)) fail('SCHEMA', `Rule ${record.id} has invalid credits`);
  const { id, topic, title, statement, mode, strength, source, license } = record;
  // attribution, class and credits are optional; records without them hash exactly as before.
  return { id, topic, title, statement, mode, strength, source, license,
    ...(Object.hasOwn(record, 'class') ? { class: record.class } : {}),
    ...(Object.hasOwn(record, 'credits') ? { credits: record.credits.map(credit => ({ ...credit })) } : {}),
    ...(Object.hasOwn(record, 'attribution') ? { attribution: record.attribution } : {}),
    ...(Object.hasOwn(record, 'licenseUrl') ? { licenseUrl: record.licenseUrl } : {}) };
}

/** Hash of one rule record; a binding carries forward only while this is unchanged. */
export const ruleHash = rule => canonChecksum(ruleRecord(rule, { [rule?.topic]: true }));

/** Pure generator: same input, same bytes. publishedAt comes from input, never the clock. */
export function buildRoutedCanon(input) {
  if (input?.schemaVersion !== 1) fail('SCHEMA', 'Unsupported rule-records schema');
  const { release, topics, records } = input;
  if (!release || !isDate(release.publishedAt) || !nonempty(release.source) || !nonempty(release.license)) {
    fail('SCHEMA', 'Release needs version, publishedAt, source and license');
  }
  if (Object.hasOwn(release, 'licenseUrl') && !httpsUrl(release.licenseUrl)) fail('SCHEMA', 'Release licenseUrl must be https');
  checkVersion(release.version);
  const classes = Object.hasOwn(release, 'classes') ? checkClasses(release.classes, 'Release') : undefined;
  if (!topics || typeof topics !== 'object' || !Object.keys(topics).length) fail('SCHEMA', 'At least one topic is required');
  for (const [name, topic] of Object.entries(topics)) {
    checkTopic(name);
    // `always: true` = requested for every project (e.g. process rules that govern any audit); no globs then.
    if (Object.hasOwn(topic ?? {}, 'always')) {
      if (topic.always !== true || Object.hasOwn(topic, 'globs')) fail('SCHEMA', `Topic ${name}: always must be true and has no globs`);
      continue;
    }
    if (!Array.isArray(topic?.globs) || !topic.globs.length || !topic.globs.every(nonempty)) fail('SCHEMA', `Topic ${name} needs globs`);
    topic.globs.forEach(compileGlob);
  }
  if (!Array.isArray(records) || !records.length) fail('SCHEMA', 'Rule records are required');
  const seen = new Set();
  const byTopic = new Map(Object.keys(topics).map(name => [name, []]));
  for (const raw of records) {
    const rule = ruleRecord(raw, topics, classes ?? {});
    if (seen.has(rule.id)) fail('SCHEMA', `Duplicate rule id ${rule.id}`);
    seen.add(rule.id);
    byTopic.get(rule.topic).push(rule);
  }
  const files = new Map();
  const index = { schemaVersion: 1, kind: 'unslop-canon-index', version: release.version,
    publishedAt: release.publishedAt, source: release.source, license: release.license,
    ...(Object.hasOwn(release, 'licenseUrl') ? { licenseUrl: release.licenseUrl } : {}),
    ...(classes ? { classes: structuredClone(classes) } : {}), topics: {} };
  for (const name of [...byTopic.keys()].sort()) {
    const rules = byTopic.get(name).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    if (!rules.length) fail('SCHEMA', `Topic ${name} has no rules`);
    const payload = { schemaVersion: 1, kind: 'unslop-canon-topic', version: release.version, topic: name, rules };
    const text = stableStringify({ payload, checksum: canonChecksum(payload) });
    if (utf8Bytes(text) > MAX_FILE_BYTES) fail('TOO_LARGE', `Topic ${name} exceeds ${MAX_FILE_BYTES} bytes`);
    files.set(`topics/${name}.json`, text);
    index.topics[name] = { ...(topics[name].always ? { always: true, globs: [] } : { globs: [...topics[name].globs] }),
      ruleIds: rules.map(rule => rule.id),
      titles: Object.fromEntries(rules.map(rule => [rule.id, rule.title])),
      checksum: canonChecksum(payload), bytes: utf8Bytes(text) };
  }
  const indexText = stableStringify({ payload: index, checksum: canonChecksum(index) });
  if (utf8Bytes(indexText) > MAX_FILE_BYTES) fail('TOO_LARGE', 'Index exceeds the size cap');
  files.set('index.json', indexText);
  return { version: release.version, files: new Map([...files].sort(([a], [b]) => a < b ? -1 : 1)) };
}

/** Index validator. The index checksum covers every topic checksum and byte count. */
export function validateRoutedIndex(envelope, expectedVersion) {
  const { payload, checksum } = envelope ?? {};
  if (!payload || payload.schemaVersion !== 1 || payload.kind !== 'unslop-canon-index') fail('SCHEMA', 'Not a routed canon index');
  checkVersion(payload.version);
  if (expectedVersion !== undefined && payload.version !== expectedVersion) fail('VERSION_MISMATCH', 'Requested version was not returned');
  if (!isDate(payload.publishedAt) || !nonempty(payload.source) || !nonempty(payload.license)) fail('SCHEMA', 'Incomplete index provenance');
  if (Object.hasOwn(payload, 'licenseUrl') && !httpsUrl(payload.licenseUrl)) fail('SCHEMA', 'Index licenseUrl must be https');
  if (Object.hasOwn(payload, 'classes')) checkClasses(payload.classes, 'Index');
  const names = Object.keys(payload.topics ?? {});
  if (!names.length) fail('SCHEMA', 'Index has no topics');
  const ids = new Set();
  for (const name of names) {
    checkTopic(name);
    const entry = payload.topics[name];
    const always = entry?.always === true;
    if (Object.hasOwn(entry ?? {}, 'always') && !always) fail('SCHEMA', `Invalid always flag for topic ${name}`);
    if (!Array.isArray(entry?.globs) || (always ? entry.globs.length !== 0 : !entry.globs.length) || !entry.globs.every(nonempty) ||
        !Array.isArray(entry.ruleIds) || !entry.ruleIds.length || !HEX64.test(entry.checksum ?? '') ||
        !Number.isInteger(entry.bytes) || entry.bytes <= 0) fail('SCHEMA', `Invalid route for topic ${name}`);
    if (entry.bytes > MAX_FILE_BYTES) fail('TOO_LARGE', `Topic ${name} exceeds the size cap`);
    entry.globs.forEach(compileGlob);
    if (!entry.titles || Object.keys(entry.titles).sort().join('\n') !== [...entry.ruleIds].sort().join('\n')) {
      fail('SCHEMA', `Titles do not match rule ids in topic ${name}`);
    }
    for (const id of entry.ruleIds) {
      if (!titleOk(entry.titles[id])) fail('SCHEMA', `Invalid title for ${id}`);
      if (!RULE_ID_RE.test(id) || ids.has(id)) fail('SCHEMA', 'Rule id is invalid or routed twice');
      ids.add(id);
    }
  }
  if (!HEX64.test(checksum ?? '') || checksum !== canonChecksum(payload)) fail('CHECKSUM', 'Index checksum mismatch');
  return envelope;
}

/** Topic validator (separate from validateCanon): binds a topic file to one index entry. */
export function validateRoutedTopic(envelope, index, topic, text) {
  const entry = index.payload.topics[topic];
  if (!entry) fail('UNKNOWN_TOPIC', `Topic ${topic} is not routed in version ${index.payload.version}`);
  const { payload, checksum } = envelope ?? {};
  if (!payload || payload.schemaVersion !== 1 || payload.kind !== 'unslop-canon-topic') fail('SCHEMA', 'Not a routed canon topic');
  if (payload.version !== index.payload.version) fail('VERSION_MISMATCH', 'Topic belongs to another version');
  if (payload.topic !== topic) fail('SCHEMA', 'Topic name does not match the request');
  if (!HEX64.test(checksum ?? '') || checksum !== canonChecksum(payload) || checksum !== entry.checksum) {
    fail('CHECKSUM', 'Topic checksum mismatch');
  }
  if (text !== undefined && utf8Bytes(text) > MAX_FILE_BYTES) fail('TOO_LARGE', 'Topic exceeds the size cap');
  if (text !== undefined && utf8Bytes(text) !== entry.bytes) fail('CHECKSUM', 'Topic byte count mismatch');
  if (!Array.isArray(payload.rules) || payload.rules.map(rule => rule.id).join('\n') !== entry.ruleIds.join('\n')) {
    fail('SCHEMA', 'Topic rules do not match the index route');
  }
  for (const rule of payload.rules) {
    if (rule.topic !== topic || rule.title !== entry.titles[rule.id] || !nonempty(rule.statement) ||
        titleLeaks(rule.title, rule.statement) || !nonempty(rule.source) || !nonempty(rule.license) ||
        (Object.hasOwn(rule, 'attribution') && !nonempty(rule.attribution)) ||
        (Object.hasOwn(rule, 'licenseUrl') && !httpsUrl(rule.licenseUrl)) ||
        (Object.hasOwn(rule, 'class') && !Object.hasOwn(index.payload.classes ?? {}, rule.class)) ||
        (Object.hasOwn(rule, 'credits') && !creditsOk(rule.credits)) ||
        !['detector', 'judgement'].includes(rule.mode) || !['hard', 'soft'].includes(rule.strength)) {
      fail('SCHEMA', `Invalid rule ${rule.id} in topic ${topic}`);
    }
  }
  return envelope;
}

/** Topics whose globs match at least one project file. Mapping lives only in the index. */
export function routeTopics(index, relativeFiles) {
  const matched = [];
  for (const [name, entry] of Object.entries(index.payload.topics)) {
    if (entry.always === true) { matched.push(name); continue; }
    const patterns = entry.globs.map(compileGlob);
    if (relativeFiles.some(file => patterns.some(pattern => pattern.test(file)))) matched.push(name);
  }
  return matched.sort();
}

/**
 * One run: latest index resolved once, topics only by the explicit version from it.
 * If a topic read says UNKNOWN_VERSION (the served version changed mid-run, e.g. during a
 * deploy or rollback) and the run was not pinned to an explicit version, the index is
 * re-read ONCE and the topic retried with its version; `indexChanged` records it. A second
 * failure is thrown as is: never a silent fallback.
 */
export function createRoutedRun({ endpoint, reader, version }) {
  if (!nonempty(endpoint) || typeof reader?.readIndex !== 'function' || typeof reader?.readTopic !== 'function') {
    fail('CONFIG', 'Endpoint and routed reader are required');
  }
  if (version !== undefined) checkVersion(version);
  let indexPromise;
  let refreshed = false;
  let indexChanged = null;
  const topics = new Map();
  const readIndex = async () => {
    const { envelope, text } = await reader.readIndex(version);
    return { envelope: validateRoutedIndex(envelope, version), bytes: utf8Bytes(text) };
  };
  const loadIndex = () => (indexPromise ??= readIndex());
  async function readTopicOnce(topic) {
    const { envelope: index } = await loadIndex();
    checkTopic(topic);
    if (!index.payload.topics[topic]) fail('UNKNOWN_TOPIC', `Topic ${topic} is not routed in ${index.payload.version}`);
    if (!topics.has(topic)) {
      const pending = (async () => {
        const { envelope, text } = await reader.readTopic(index.payload.version, topic);
        return { envelope: validateRoutedTopic(envelope, index, topic, text), bytes: utf8Bytes(text) };
      })();
      topics.set(topic, pending);
      pending.catch(() => { if (topics.get(topic) === pending) topics.delete(topic); });
    }
    return topics.get(topic);
  }
  async function loadTopic(topic) {
    try { return await readTopicOnce(topic); }
    catch (error) {
      if (error?.code !== 'UNKNOWN_VERSION' || version !== undefined || refreshed) throw error;
      refreshed = true;
      const before = (await loadIndex()).envelope;
      indexPromise = readIndex();
      const after = (await indexPromise).envelope;
      topics.clear();
      indexChanged = { from: before.payload.version, to: after.payload.version,
        fromChecksum: before.checksum, toChecksum: after.checksum };
      return readTopicOnce(topic);
    }
  }
  return Object.freeze({ endpoint, loadIndex, loadTopic, get indexChanged() { return indexChanged; } });
}

/** What an agent can use through this MCP, one line each. Order is fixed. */
export const ROUTED_SURFACE = Object.freeze([
  ['resource', ROUTED_INDEX_LATEST_URI, 'entry point: routed index; read first, once per run, then use its explicit version'],
  ['resource', 'unslop://canon/latest', `legacy full canon; for routed runs read ${ROUTED_INDEX_LATEST_URI} first`],
  ['template', ROUTED_INDEX_TEMPLATE, 'index of an explicit immutable version (rollback reads)'],
  ['template', ROUTED_TOPIC_TEMPLATE, 'full rule texts of one topic; version from the index, never latest'],
]);

function surfaceLines({ legacy = true } = {}) {
  const surface = ROUTED_SURFACE.filter(([, uri]) => legacy || uri !== 'unslop://canon/latest');
  return [
    'resources:', ...surface.filter(([kind]) => kind === 'resource').map(([, uri, text]) => `- ${uri} : ${text}`),
    'resource templates:', ...surface.filter(([kind]) => kind === 'template').map(([, uri, text]) => `- ${uri} : ${text}`),
    'tools: none',
  ];
}

/**
 * Compact index sent in MCP `instructions` at initialize, without any request.
 * Ids and short titles only; full statements stay behind topic requests. Deterministic,
 * capped: topics that do not fit are listed by name only.
 */
export function routedInstructions(index, { capBytes = MAX_INSTRUCTIONS_BYTES, legacy = true } = {}) {
  const head = [
    'unslop canon MCP. This index arrives without a request; full rule texts only via a topic resource.',
    `canon ${index.payload.version} checksum ${index.checksum} published ${index.payload.publishedAt}`,
    'Pick topics whose globs match the project files, plus every topic marked always; request only those.',
  ];
  const tail = surfaceLines({ legacy });
  const size = lines => utf8Bytes(lines.join('\n'));
  const names = Object.keys(index.payload.topics).sort();
  const full = [];
  let i = 0;
  for (; i < names.length; i++) {
    const entry = index.payload.topics[names[i]];
    const route = entry.always === true ? 'always: every project' : entry.globs.join(', ');
    const block = [`- ${names[i]} [${route}]`, ...entry.ruleIds.map(id => `  ${id}: ${entry.titles[id]}`)];
    const rest = names.slice(i + 1);
    const restLine = rest.length ? [`topics listed by name only (cap ${capBytes} bytes): ${rest.join(', ')}`] : [];
    if (size([...head, 'topics:', ...full, ...block, ...restLine, ...tail]) > capBytes) break;
    full.push(...block);
  }
  let rest = names.slice(i);
  const build = more => [...head, 'topics:', ...full,
    ...(rest.length ? [`topics listed by name only (cap ${capBytes} bytes): ${rest.join(', ')}${more ? ` +${more} more` : ''}`] : []),
    ...tail].join('\n');
  let more = 0;
  while (utf8Bytes(build(more)) > capBytes && rest.length) { rest = rest.slice(0, -1); more++; }
  return build(more);
}

/** Instructions for a store; an unavailable store is said explicitly, never an empty index. */
export async function storeInstructions(store, options) {
  try {
    const { envelope } = await store.readIndex();
    return routedInstructions(envelope, options);
  } catch (error) {
    return [
      'unslop canon MCP. CANON UNAVAILABLE at connect: no routed index could be loaded'
        + ` (code ${error.code ?? 'UNAVAILABLE'}).`,
      'Do not audit against a canon and do not report a pass; reconnect after the operator publishes and promotes.',
      ...surfaceLines({ legacy: options?.legacy ?? true }),
    ].join('\n');
  }
}

/**
 * In-memory routed store with the same contract and error codes as the file store, for a
 * bundled canon (Worker). `bundle` = { latest: { version, checksum }, versions: { V: { 'index.json': text,
 * 'topics/T.json': text } } }. Every read is re-validated.
 */
export function createBundledRoutedStore(bundle) {
  const parse = text => { try { return JSON.parse(text); } catch { fail('SCHEMA', 'Invalid JSON in bundle'); } };
  const files = version => Object.hasOwn(bundle?.versions ?? {}, version) ? bundle.versions[version] : null;
  async function readIndex(version) {
    const selected = version ?? bundle?.latest?.version;
    if (selected === undefined) fail('UNKNOWN_VERSION', 'No routed canon is bundled');
    checkVersion(selected);
    const text = files(selected)?.['index.json'];
    if (typeof text !== 'string') fail('UNKNOWN_VERSION', 'Not found');
    if (utf8Bytes(text) > MAX_FILE_BYTES) fail('TOO_LARGE', 'Index exceeds the size cap');
    const envelope = validateRoutedIndex(parse(text), selected);
    if (version === undefined && bundle.latest.checksum !== envelope.checksum) fail('CHECKSUM', 'Latest pointer checksum mismatch');
    return { envelope, text };
  }
  async function readTopic(version, topic) {
    checkVersion(version);
    checkTopic(topic);
    const { envelope: index } = await readIndex(version);
    if (!index.payload.topics[topic]) fail('UNKNOWN_TOPIC', `Topic ${topic} is not routed in ${version}`);
    const text = files(version)[`topics/${topic}.json`];
    if (typeof text !== 'string') fail('MISSING_TOPIC', 'Not found');
    return { envelope: validateRoutedTopic(parse(text), index, topic, text), text };
  }
  return Object.freeze({ readIndex, readTopic });
}
