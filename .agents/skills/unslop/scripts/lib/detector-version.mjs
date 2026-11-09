import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Bind coverage to shipped detector code, not a manually maintained package label.
const root = fileURLToPath(new URL('../', import.meta.url));
const files = ['detect.mjs', ...['rules', 'lib'].flatMap(dir =>
  readdirSync(path.join(root, dir)).filter(name => name.endsWith('.mjs') &&
    (dir === 'rules' || ['css.mjs', 'heuristics.mjs', 'reporter.mjs', 'scan.mjs', 'walker.mjs'].includes(name)))
    .map(name => `${dir}/${name}`))].sort();
const hash = createHash('sha256');
for (const file of files) hash.update(file).update('\0').update(readFileSync(path.join(root, file))).update('\0');
export const DETECTOR_VERSION = `sha256:${hash.digest('hex')}`;
