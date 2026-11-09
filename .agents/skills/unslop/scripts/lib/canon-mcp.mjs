import { readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { CanonError, validateCanon } from './canon.mjs';
import { canonUri } from './canon-mcp-core.mjs';
export * from './canon-mcp-core.mjs';

/** Operator-managed directory: latest.json points to an immutable VERSION.json. */
export function createCanonStore(directory) {
  const seen = new Map();
  async function readJson(name) {
    const root = await realpath(directory);
    const file = await realpath(path.join(root, name));
    if (path.dirname(file) !== root) throw new CanonError('REVISION', 'Canon file is outside the store');
    return JSON.parse(await readFile(file, 'utf8'));
  }
  return async version => {
    const selected = version ?? (await readJson('latest.json')).version;
    canonUri(selected);
    if (selected === undefined) throw new CanonError('REVISION', 'Latest pointer is missing a revision');
    const snapshot = validateCanon(await readJson(`${selected}.json`), selected);
    if (seen.has(selected) && seen.get(selected) !== snapshot.checksum) {
      throw new CanonError('REVISION_CHANGED', 'Immutable revision changed');
    }
    seen.set(selected, snapshot.checksum);
    return snapshot;
  };
}

