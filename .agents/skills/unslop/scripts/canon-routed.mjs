#!/usr/bin/env node
// Operator CLI for the routed canon. Not used by the skill at audit time.
//   generate --input canon/public/records.json --out canon/public-generated
//   publish  --store DIR --from canon/public-generated/VERSION [--promote]
//   promote  --store DIR --version VERSION            (also rollback)
//   bind     --store DIR --version VERSION --rules B-1[,B-2] [--out FILE]
// Bindings live in STORE/bindings/<index checksum>.json; promote carries unchanged ones forward.
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { buildRoutedCanon, writeGenerated, publishRouted, promoteRouted, createRoutedStore, stableStringify, ruleHash,
  writeStoreBindings } from './lib/canon-routed.mjs';
import { ALL_RULES } from './rules/index.mjs';
import { DETECTOR_VERSION } from './lib/detector-version.mjs';

const [command, ...rest] = process.argv.slice(2);
const flags = {};
for (let i = 0; i < rest.length; i++) {
  if (rest[i] === '--promote') { flags.promote = true; continue; }
  if (!rest[i].startsWith('--') || !rest[i + 1] || rest[i + 1].startsWith('--')) usage();
  flags[rest[i].slice(2)] = rest[++i];
}
function usage() {
  process.stderr.write('Usage: canon-routed.mjs generate|publish|promote|bind (see header)\n');
  process.exit(2);
}
const need = (...names) => names.forEach(name => { if (!flags[name]) usage(); });

try {
  let out;
  if (command === 'generate') {
    need('input', 'out');
    const built = buildRoutedCanon(JSON.parse(await readFile(flags.input, 'utf8')));
    const result = await writeGenerated(flags.out, built);
    out = { version: built.version, result, directory: path.join(flags.out, built.version),
      checksum: JSON.parse(built.files.get('index.json')).checksum };
  } else if (command === 'publish') {
    need('store', 'from');
    out = await publishRouted(flags.store, flags.from, { promote: Boolean(flags.promote) });
    out.promoted = Boolean(flags.promote);
  } else if (command === 'promote') {
    need('store', 'version');
    out = await promoteRouted(flags.store, flags.version);
  } else if (command === 'bind') {
    need('store', 'version', 'rules');
    const store = createRoutedStore(flags.store);
    const { envelope: index } = await store.readIndex(flags.version);
    const known = new Set(ALL_RULES.map(rule => rule.id));
    const bindings = [];
    for (const ruleId of flags.rules.split(',')) {
      const topic = Object.keys(index.payload.topics).find(name => index.payload.topics[name].ruleIds.includes(ruleId));
      if (!topic) throw Object.assign(new Error(`${ruleId} is not routed in ${flags.version}`), { code: 'UNKNOWN_RULE' });
      const { envelope } = await store.readTopic(flags.version, topic);
      const rule = envelope.payload.rules.find(item => item.id === ruleId);
      if (rule.mode !== 'detector' || !known.has(ruleId)) {
        throw Object.assign(new Error(`${ruleId} has no local detector`), { code: 'NO_DETECTOR' });
      }
      bindings.push({ ruleId, canonChecksum: index.checksum, detectorVersion: DETECTOR_VERSION, ruleHash: ruleHash(rule) });
    }
    await writeStoreBindings(flags.store, index.checksum, bindings);
    if (flags.out) await writeFile(flags.out, stableStringify(bindings));
    out = { version: flags.version, checksum: index.checksum, bound: bindings.map(item => item.ruleId) };
  } else usage();
  process.stdout.write(JSON.stringify({ command, ...out }) + '\n');
} catch (error) {
  process.stderr.write(JSON.stringify({ command, status: 'failed', code: error.code ?? 'ERROR', message: error.message }) + '\n');
  process.exitCode = 1;
}
