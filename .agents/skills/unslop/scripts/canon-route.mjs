#!/usr/bin/env node
// Skill side of the routed canon: read the index once, pick topics from the
// project's files via the index routes, request only those topics, then audit.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRoutedRun, readStoreBindings } from './lib/canon-routed.mjs';
import { mcpRoutedReader } from './lib/canon-mcp.mjs';
import { auditRoutedProject } from './lib/canon-audit.mjs';
import { walk } from './lib/walker.mjs';

const USAGE = 'Usage: node scripts/canon-route.mjs --project PATH [--endpoint URL | --store LOCAL_CANON_DIR] [--version V] [--bindings FILE]\n';
const args = process.argv.slice(2);
const options = {};
for (let i = 0; i < args.length; i += 2) {
  if (!['--project', '--endpoint', '--store', '--version', '--bindings'].includes(args[i]) ||
      !args[i + 1] || args[i + 1].startsWith('--') || options[args[i]]) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  options[args[i]] = args[i + 1];
}
if (!options['--project'] || (options['--endpoint'] && options['--store'])) {
  process.stderr.write(options['--project'] ? 'Choose one explicit transport; there is no automatic fallback.\n' : USAGE);
  process.exit(2);
}

const localStore = Boolean(options['--store']);
const endpoint = localStore ? `stdio:${options['--store']}` : options['--endpoint'] ?? 'https://oleg.design/unslop/mcp';
const client = new Client({ name: 'unslop-skill-routed', version: '0.1.0' });
try {
  const project = path.resolve(options['--project']);
  const files = walk(project).map(file => path.relative(project, file).split(path.sep).join('/'));
  const transport = localStore
    ? new StdioClientTransport({ command: process.execPath,
      args: [fileURLToPath(new URL('./canon-server.mjs', import.meta.url)), options['--store']], stderr: 'inherit' })
    : new StreamableHTTPClientTransport(new URL(endpoint));
  await client.connect(transport);
  const run = createRoutedRun({ endpoint, reader: mcpRoutedReader(client), version: options['--version'] });
  // Explicit --bindings wins; otherwise a local store supplies its own (carried forward on promote).
  const explicit = options['--bindings'] ? JSON.parse(readFileSync(options['--bindings'], 'utf8')) : null;
  const bindingsFor = async current => explicit ?? (localStore ? readStoreBindings(options['--store'], current.checksum) : []);
  const { index, topics, audit, notes } = await auditRoutedProject(project, files, run, { bindingsFor, localStore });
  const { bytes: indexBytes } = await run.loadIndex();
  const received = [];
  for (const topic of topics) {
    const { envelope, bytes } = await run.loadTopic(topic);
    received.push({ topic, checksum: envelope.checksum, bytes, ruleIds: envelope.payload.rules.map(rule => rule.id) });
  }
  const all = Object.entries(index.payload.topics);
  const report = {
    schemaVersion: 1,
    kind: 'unslop-routed-audit',
    transport: { endpoint, localStore, note: localStore ? 'explicit local store; never reported as clean' : 'remote' },
    canon: { version: index.payload.version, checksum: index.checksum, publishedAt: index.payload.publishedAt },
    routing: { projectFiles: files.length, requestedTopics: topics,
      notRequested: all.map(([name]) => name).filter(name => !topics.includes(name)),
      routes: Object.fromEntries(all.map(([name, entry]) => [name, entry.ruleIds])) },
    bytes: { received: indexBytes + received.reduce((sum, item) => sum + item.bytes, 0),
      fullCanon: indexBytes + all.reduce((sum, [, entry]) => sum + entry.bytes, 0) },
    topics: received,
    notes,
    hints: audit.coverage.filter(item => item.hint).map(item => `${item.ruleId}: ${item.hint}`),
    audit,
  };
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} catch (error) {
  process.stderr.write(JSON.stringify({ status: 'unavailable', code: error.code ?? 'TRANSPORT',
    message: 'No verified routed canon was loaded; do not report an audit pass.' }) + '\n');
  process.exitCode = 2;
} finally {
  await client.close();
}
