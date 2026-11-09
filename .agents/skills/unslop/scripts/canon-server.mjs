#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createCanonServer, createCanonStore } from './lib/canon-mcp.mjs';
import { createRoutedStore, createInstructionsSource } from './lib/canon-routed.mjs';

const directory = process.argv[2];
if (!directory || process.argv.length !== 3) {
  process.stderr.write('Usage: unslop-canon-server <operator-managed-canon-directory>\n');
  process.exit(2);
}
// One stdio process serves one connection: the index in `instructions` is read at connect,
// so a new connection after promote sees the new version.
const routed = createRoutedStore(directory);
const instructions = await createInstructionsSource(directory, routed)();
await createCanonServer(createCanonStore(directory), { routed, instructions }).connect(new StdioServerTransport());
