// Pure MCP server/reader core (no node: imports; Worker-safe). The file store is in canon-mcp.mjs.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListResourcesRequestSchema, ListResourceTemplatesRequestSchema, ReadResourceRequestSchema, ListToolsRequestSchema,
  ListPromptsRequestSchema, McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { CanonError, validateCanon } from './canon.mjs';
import { ROUTED_INDEX_LATEST_URI, ROUTED_INDEX_TEMPLATE, ROUTED_TOPIC_TEMPLATE, parseRoutedUri, indexUri, topicUri,
  checkVersion } from './canon-routed-core.mjs';

export const CANON_LATEST_URI = 'unslop://canon/latest';
const prefix = 'unslop://canon/';
const revisionPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function canonUri(version) {
  if (version === undefined) return CANON_LATEST_URI;
  if (!revisionPattern.test(version) || version === 'latest') throw new CanonError('REVISION', 'Invalid immutable revision');
  return prefix + version;
}

// Routed errors that mean "this version/topic does not exist here"; everything else is integrity.
const ROUTED_NOT_FOUND = new Set(['UNKNOWN_VERSION', 'UNKNOWN_TOPIC', 'LATEST_FORBIDDEN', 'BAD_URI']);

async function readRouted(routed, uri, request) {
  try {
    if (request.kind === 'index') {
      const { text } = await routed.readIndex(request.version);
      return { contents: [{ uri, mimeType: 'application/json', text }] };
    }
    const { text } = await routed.readTopic(request.version, request.topic);
    return { contents: [{ uri, mimeType: 'application/json', text }] };
  } catch (error) {
    const code = error instanceof CanonError ? error.code : 'UNAVAILABLE';
    if (ROUTED_NOT_FOUND.has(code)) throw new McpError(-32002, 'Routed canon resource not found', { code });
    throw new McpError(-32603, 'Routed canon unavailable or invalid', { code });
  }
}

/** `routed` (optional) adds the index resource and per-topic template; without it nothing changes. */
export function createCanonServer(read, { routed, instructions } = {}) {
  const server = new Server({ name: 'unslop-canon', version: '0.1.0' },
    { capabilities: { resources: {}, tools: {}, prompts: {} }, ...(instructions ? { instructions } : {}) });
  // Some MCP clients call tools/list and prompts/list on connect and fail on -32601.
  // There are deliberately no tools or prompts: answer with empty lists.
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: [] }));
  // `read` may be null (e.g. a Worker serving only the routed canon): the legacy resource is then absent.
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [...(read ? [{
    uri: CANON_LATEST_URI, name: 'Unslop canon', mimeType: 'application/json',
    description: routed
      ? `Legacy full canon; for routed runs read ${ROUTED_INDEX_LATEST_URI} first.`
      : 'Read once per run, then retain the returned immutable version and checksum.',
  }] : []), ...(routed ? [{
    uri: ROUTED_INDEX_LATEST_URI, name: 'Unslop canon index (entry point)', mimeType: 'application/json',
    description: 'Entry point: read this first, once per run. Routes topic -> file globs -> rule ids; '
      + 'then read only the matching unslop://canon-topic/{version}/{topic} with the version from this index.',
  }] : [])] }));
  if (routed) {
    server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({ resourceTemplates: [
      { uriTemplate: ROUTED_INDEX_TEMPLATE, name: 'Unslop canon index by version', mimeType: 'application/json',
        description: 'Explicit immutable version only.' },
      { uriTemplate: ROUTED_TOPIC_TEMPLATE, name: 'Unslop canon topic', mimeType: 'application/json',
        description: 'Explicit version from the index plus one routed topic. latest is rejected.' },
    ] }));
  }
  server.setRequestHandler(ReadResourceRequestSchema, async ({ params }) => {
    if (routed) {
      let request;
      try { request = parseRoutedUri(params.uri); }
      catch (error) { throw new McpError(-32002, 'Routed canon resource not found', { code: error.code ?? 'BAD_URI' }); }
      if (request) return readRouted(routed, params.uri, request);
    }
    try {
      const uri = params.uri;
      if (!read || !uri.startsWith(prefix)) throw new CanonError('REVISION', 'Unknown resource');
      const suffix = uri.slice(prefix.length);
      const version = suffix === 'latest' ? undefined : suffix;
      if (canonUri(version) !== uri) throw new CanonError('REVISION', 'Unknown resource');
      const snapshot = validateCanon(await read(version), version);
      return { contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(snapshot) }] };
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'REVISION') throw new McpError(-32002, 'Canon revision not found');
      throw new McpError(-32603, 'Canon unavailable or invalid', { code: error instanceof CanonError ? error.code : 'UNAVAILABLE' });
    }
  });
  return server;
}

/** Reader for createCanonRun, using an already connected official SDK client. */
export function mcpCanonReader(client) {
  return async ({ version, signal }) => {
    const uri = canonUri(version);
    let result;
    try {
      result = await client.readResource({ uri }, { signal });
    } catch (error) {
      if (error instanceof McpError) {
        if (error.code === ErrorCode.ConnectionClosed) throw new CanonError('OFFLINE', 'MCP connection closed');
        if (error.code === ErrorCode.RequestTimeout) throw new CanonError('TIMEOUT', 'MCP request timed out');
        const reported = error.data?.code;
        if (reported === 'CHECKSUM' || reported === 'SCHEMA' || reported === 'REVISION_CHANGED') {
          throw new CanonError(reported, 'MCP canon request failed');
        }
        throw new CanonError(error.code === -32002 ? 'REVISION' : 'PROTOCOL', 'MCP canon request failed');
      }
      throw error;
    }
    if (result.contents.length !== 1 || result.contents[0].uri !== uri ||
        result.contents[0].mimeType !== 'application/json' || typeof result.contents[0].text !== 'string') {
      throw new CanonError('SCHEMA', 'Unexpected MCP resource response');
    }
    try { return JSON.parse(result.contents[0].text); }
    catch { throw new CanonError('SCHEMA', 'Invalid JSON in canon resource'); }
  };
}

function routedError(error) {
  if (error instanceof McpError) {
    if (error.code === ErrorCode.ConnectionClosed) return new CanonError('OFFLINE', 'MCP connection closed');
    if (error.code === ErrorCode.RequestTimeout) return new CanonError('TIMEOUT', 'MCP request timed out');
    return new CanonError(typeof error.data?.code === 'string' ? error.data.code : 'PROTOCOL', 'MCP routed canon request failed');
  }
  return error;
}

/** Reader for createRoutedRun. Returns parsed envelope plus the exact received text (for bytes). */
export function mcpRoutedReader(client) {
  async function readOne(uri) {
    let result;
    try { result = await client.readResource({ uri }); }
    catch (error) { throw routedError(error); }
    if (result.contents.length !== 1 || result.contents[0].uri !== uri ||
        result.contents[0].mimeType !== 'application/json' || typeof result.contents[0].text !== 'string') {
      throw new CanonError('SCHEMA', 'Unexpected MCP resource response');
    }
    const text = result.contents[0].text;
    try { return { envelope: JSON.parse(text), text }; }
    catch { throw new CanonError('SCHEMA', 'Invalid JSON in routed canon resource'); }
  }
  return Object.freeze({
    readIndex: version => readOne(indexUri(version)),
    readTopic: (version, topic) => readOne(topicUri(checkVersion(version), topic)),
  });
}
