// Node side of the routed canon: generator output on disk, operator store, publish/promote,
// detector bindings and the per-initialize instructions source. Pure parts live in canon-routed-core.mjs.
import { mkdir, readFile, readdir, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { CanonError, canonChecksum } from './canon.mjs';
import { DETECTOR_VERSION } from './detector-version.mjs';
import { checkVersion, checkTopic, validateRoutedIndex, validateRoutedTopic, stableStringify, ruleHash,
  storeInstructions, MAX_FILE_BYTES } from './canon-routed-core.mjs';
export * from './canon-routed-core.mjs';

const fail = (code, message) => { throw new CanonError(code, message); };
const HEX64 = /^[a-f0-9]{64}$/;

async function readCapped(file) {
  if ((await stat(file)).size > MAX_FILE_BYTES) fail('TOO_LARGE', 'File exceeds the size cap');
  return readFile(file, 'utf8');
}

async function readGenerated(directory) {
  const indexText = await readCapped(path.join(directory, 'index.json'));
  const json = text => { try { return JSON.parse(text); } catch { fail('SCHEMA', 'Invalid JSON in canon file'); } };
  const index = validateRoutedIndex(json(indexText));
  const files = new Map([['index.json', indexText]]);
  for (const name of Object.keys(index.payload.topics)) {
    let text;
    try { text = await readCapped(path.join(directory, 'topics', `${name}.json`)); }
    catch (error) { if (error.code === 'ENOENT') fail('MISSING_TOPIC', `Topic file ${name} is missing`); throw error; }
    validateRoutedTopic(json(text), index, name, text);
    files.set(`topics/${name}.json`, text);
  }
  return { index, files };
}

async function listFiles(directory, prefix = '') {
  const out = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const rel = prefix + entry.name;
    if (entry.isDirectory()) out.push(...await listFiles(path.join(directory, entry.name), rel + '/'));
    else out.push(rel);
  }
  return out.sort();
}

async function sameTree(directory, files) {
  const existing = await listFiles(directory);
  if (existing.join('\n') !== [...files.keys()].sort().join('\n')) return false;
  for (const [rel, text] of files) if (await readFile(path.join(directory, rel), 'utf8') !== text) return false;
  return true;
}

/** Stages a tree, then renames it into place. An existing different version is never replaced. */
async function placeImmutable(parent, version, files) {
  const destination = path.join(parent, version);
  await mkdir(parent, { recursive: true });
  if (existsSync(destination)) {
    if (await sameTree(destination, files)) return 'unchanged';
    fail('REVISION_CHANGED', `Version ${version} already exists with different content`);
  }
  const stage = path.join(parent, `.stage-${randomUUID()}`);
  try {
    for (const [rel, text] of files) {
      await mkdir(path.dirname(path.join(stage, rel)), { recursive: true });
      await writeFile(path.join(stage, rel), text, { flag: 'wx' });
    }
    try { await rename(stage, destination); }
    catch (error) {
      if (!['EEXIST', 'ENOTEMPTY'].includes(error.code)) throw error;
      if (await sameTree(destination, files)) return 'unchanged';
      fail('REVISION_CHANGED', `Version ${version} already exists with different content`);
    }
  } finally { await rm(stage, { recursive: true, force: true }); }
  return 'written';
}

/** Generator output: OUT/VERSION/index.json + OUT/VERSION/topics/*.json. */
export async function writeGenerated(outDir, built) {
  return placeImmutable(outDir, built.version, built.files);
}

/** Operator-only: copy a validated generated version into STORE/routed/VERSION. */
export async function publishRouted(storeDir, generatedVersionDir, { promote = false } = {}) {
  const { index, files } = await readGenerated(generatedVersionDir);
  const result = await placeImmutable(path.join(storeDir, 'routed'), index.payload.version, files);
  if (promote) await promoteRouted(storeDir, index.payload.version);
  return { version: index.payload.version, checksum: index.checksum, result };
}

const bindingsFile = (storeDir, checksum) => {
  if (!HEX64.test(checksum ?? '')) fail('SCHEMA', 'Invalid checksum for bindings');
  return path.join(storeDir, 'bindings', `${checksum}.json`);
};

function parseBindings(text) {
  let list;
  try { list = JSON.parse(text); } catch { fail('BINDINGS_INVALID', 'Bindings file is not valid JSON'); }
  if (!Array.isArray(list) || !list.every(item => item && typeof item.ruleId === 'string')) {
    fail('BINDINGS_INVALID', 'Bindings file must be an array of bindings');
  }
  return list;
}

/** Detector bindings for exactly one index checksum; other checksums' files are ignored. */
export async function readStoreBindings(storeDir, checksum) {
  const file = bindingsFile(storeDir, checksum);
  let text;
  try { text = await readCapped(file); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  return parseBindings(text).filter(item => item.canonChecksum === checksum);
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const LOCK_STALE_MS = 30000;

/** Exclusive lock file per bindings file; a crashed holder's lock expires after 30 s. */
async function withLock(file, action) {
  const lock = `${file}.lock`;
  for (let attempt = 0; ; attempt++) {
    try { await writeFile(lock, String(process.pid), { flag: 'wx' }); break; }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try { if (Date.now() - (await stat(lock)).mtimeMs > LOCK_STALE_MS) await rm(lock, { force: true }); }
      catch (statError) { if (statError.code !== 'ENOENT') throw statError; }
      if (attempt >= 500) fail('BINDINGS_LOCKED', 'Bindings file is locked by another writer');
      await sleep(5 + Math.floor(Math.random() * 10));
    }
  }
  try { return await action(); } finally { await rm(lock, { force: true }); }
}

/** Merges bindings for one index checksum under a lock; written via temp file + rename. */
export async function writeStoreBindings(storeDir, checksum, bindings) {
  const file = bindingsFile(storeDir, checksum);
  await mkdir(path.dirname(file), { recursive: true });
  return withLock(file, async () => {
    const merged = new Map();
    let text = null;
    try { text = await readCapped(file); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (text !== null) for (const item of parseBindings(text)) merged.set(item.ruleId, item);
    for (const item of bindings) merged.set(item.ruleId, { ...item, canonChecksum: checksum });
    const temporary = `${file}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, stableStringify([...merged.values()].sort((x, y) => x.ruleId < y.ruleId ? -1 : 1)), { flag: 'wx' });
      await rename(temporary, file);
    } finally { await rm(temporary, { force: true }); }
    return [...merged.values()];
  });
}

async function rulesOf(directory, index) {
  const rules = new Map();
  for (const name of Object.keys(index.payload.topics)) {
    const text = await readCapped(path.join(directory, 'topics', `${name}.json`));
    for (const rule of validateRoutedTopic(JSON.parse(text), index, name, text).payload.rules) rules.set(rule.id, rule);
  }
  return rules;
}

/**
 * Promotion and rollback select an already published, re-validated version.
 * Detector bindings of the previously promoted version carry forward only for rules whose
 * record hash and detector version are unchanged; everything else must be bound again.
 */
export async function promoteRouted(storeDir, version) {
  checkVersion(version);
  const root = path.join(storeDir, 'routed');
  const { index } = await readGenerated(path.join(root, version));
  if (index.payload.version !== version) fail('VERSION_MISMATCH', 'Stored index belongs to another version');
  // Carry-forward is best-effort: a missing or corrupt previous version must never block
  // promotion or rollback. The new version itself was fully validated above.
  const carried = [];
  let carryError;
  try {
    let previous = null;
    try { previous = JSON.parse(await readFile(path.join(root, 'latest.json'), 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') fail('LATEST_INVALID', 'Latest pointer is unreadable'); }
    if (previous?.version && previous.checksum !== index.checksum) {
      const old = await readGenerated(path.join(root, checkVersion(previous.version)));
      const oldBindings = await readStoreBindings(storeDir, old.index.checksum);
      if (oldBindings.length) {
        const oldRules = await rulesOf(path.join(root, previous.version), old.index);
        const newRules = await rulesOf(path.join(root, version), index);
        for (const binding of oldBindings) {
          const before = oldRules.get(binding.ruleId);
          const after = newRules.get(binding.ruleId);
          if (binding.detectorVersion === DETECTOR_VERSION && before && after && after.mode === 'detector' &&
              ruleHash(before) === ruleHash(after) && binding.ruleHash === ruleHash(after)) {
            carried.push({ ...binding, canonChecksum: index.checksum, carriedFrom: old.index.checksum });
          }
        }
      }
    }
  } catch (error) {
    carried.length = 0;
    carryError = error.code ?? 'CARRY_FAILED';
  }
  if (carried.length) {
    try { await writeStoreBindings(storeDir, index.checksum, carried); }
    catch (error) { carried.length = 0; carryError = error.code ?? 'CARRY_WRITE_FAILED'; }
  }
  const temporary = path.join(root, `.latest-${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, stableStringify({ version, checksum: index.checksum }), { flag: 'wx' });
    await rename(temporary, path.join(root, 'latest.json'));
  } finally { await rm(temporary, { force: true }); }
  return { version, checksum: index.checksum, carriedBindings: carried.map(item => item.ruleId),
    ...(carryError ? { carryError } : {}) };
}

/** Read side used by the MCP server. Every read is re-validated against the index. */
export function createRoutedStore(storeDir) {
  const seen = new Map();
  async function readText(rel, missingCode) {
    let root;
    try { root = await realpath(path.join(storeDir, 'routed')); }
    catch { fail('UNKNOWN_VERSION', 'No routed canon is published'); }
    let file;
    try { file = await realpath(path.join(root, rel)); }
    catch (error) { if (error.code === 'ENOENT') fail(missingCode, 'Not found'); throw error; }
    if (!file.startsWith(root + path.sep)) fail('OUT_OF_STORE', 'Path escapes the store');
    return readCapped(file);
  }
  const parse = text => { try { return JSON.parse(text); } catch { fail('SCHEMA', 'Invalid JSON in store'); } };
  async function readIndex(version) {
    let selected = version;
    let pointer;
    if (selected === undefined) {
      pointer = parse(await readText('latest.json', 'UNKNOWN_VERSION'));
      selected = pointer.version;
    }
    checkVersion(selected);
    const text = await readText(`${selected}/index.json`, 'UNKNOWN_VERSION');
    const envelope = validateRoutedIndex(parse(text), selected);
    if (pointer && pointer.checksum !== envelope.checksum) fail('CHECKSUM', 'Latest pointer checksum mismatch');
    if (seen.has(selected) && seen.get(selected) !== envelope.checksum) fail('REVISION_CHANGED', 'Immutable version changed');
    seen.set(selected, envelope.checksum);
    return { envelope, text };
  }
  async function readTopic(version, topic) {
    checkVersion(version);
    checkTopic(topic);
    const { envelope: index } = await readIndex(version);
    if (!index.payload.topics[topic]) fail('UNKNOWN_TOPIC', `Topic ${topic} is not routed in ${version}`);
    const text = await readText(`${version}/topics/${topic}.json`, 'MISSING_TOPIC');
    return { envelope: validateRoutedTopic(parse(text), index, topic, text), text };
  }
  return Object.freeze({ readIndex, readTopic });
}

/**
 * Instructions per initialize for a long-lived process: cached by the exact latest.json
 * pointer (version + index checksum), rebuilt as soon as a promote changes it.
 * An unreadable pointer is never cached, so recovery is picked up on the next connect.
 */
export function createInstructionsSource(storeDir, store = createRoutedStore(storeDir), options) {
  let key = null;
  let text = null;
  return async () => {
    let pointer;
    try { pointer = await readFile(path.join(storeDir, 'routed', 'latest.json'), 'utf8'); }
    catch { pointer = null; }
    if (pointer !== null && pointer === key) return text;
    const built = await storeInstructions(store, options);
    if (pointer !== null && !built.includes('CANON UNAVAILABLE')) { key = pointer; text = built; }
    return built;
  };
}
