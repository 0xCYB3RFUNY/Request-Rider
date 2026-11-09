#!/usr/bin/env node
// unslop — deterministic slop detector for the machine-checkable rules.
// Node >= 20, zero dependencies.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { walk } from './lib/walker.mjs';
import { buildContext, runFile, runProject } from './lib/scan.mjs';
import { selectRules, SECTIONS } from './rules/index.mjs';
import { sortFindings, toTable, toJson } from './lib/reporter.mjs';

const USAGE = `unslop — deterministic slop detector

  usage: unslop <path> [--json] [--rules B,G] [--max-findings N]

  <path>            file or directory to scan
  --json            machine-readable findings array on stdout
  --rules A,B,…     only these catalog sections or rule ids (${SECTIONS.join(',')})
  --max-findings N  stop reporting after N findings
  --help            this text

  exit codes: 0 clean (or no red findings) · 1 at least one red finding · 2 usage error`;

function fail(message) {
  process.stderr.write(`${message}\n\n${USAGE}\n`);
  process.exit(2);
}

export function parseArgs(argv) {
  const options = { path: null, json: false, rules: null, maxFindings: Infinity };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (arg === '--json') {
      options.json = true;
    } else if (arg === '--rules' || arg.startsWith('--rules=')) {
      const value = arg.includes('=') ? arg.split('=').slice(1).join('=') : argv[++i];
      if (!value) return { error: 'missing value for --rules' };
      options.rules = value.split(',').map((s) => s.trim()).filter(Boolean);
      if (options.rules.length === 0) return { error: 'missing value for --rules' };
    } else if (arg === '--max-findings' || arg.startsWith('--max-findings=')) {
      const value = arg.includes('=') ? arg.split('=')[1] : argv[++i];
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) return { error: `--max-findings needs a positive integer, got "${value}"` };
      options.maxFindings = n;
    } else if (arg.startsWith('-')) {
      return { error: `unknown option "${arg}"` };
    } else if (options.path == null) {
      options.path = arg;
    } else {
      return { error: `unexpected extra argument "${arg}"` };
    }
  }
  if (options.path == null) return { error: 'missing <path>' };
  return options;
}

/** Programmatic entry point — also used by the test suite. */
export function detect(target, { rules = null } = {}) {
  const abs = path.resolve(target);
  const stat = fs.statSync(abs);
  const rootDir = stat.isDirectory() ? abs : path.dirname(abs);
  const active = selectRules(rules);
  const files = walk(abs);

  const contexts = [];
  const findings = [];
  for (const file of files) {
    let ctx;
    try {
      ctx = buildContext(file, rootDir);
    } catch {
      continue; // unreadable / binary — not our problem to report
    }
    contexts.push(ctx);
    findings.push(...runFile(ctx, active));
  }
  findings.push(...runProject(contexts, active));

  return { findings: sortFindings(findings), scanned: files.length, rulesRun: active.length };
}

function main(argv) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    process.exit(0);
  }
  if (options.error) fail(`unslop: ${options.error}`);

  let result;
  try {
    result = detect(options.path, { rules: options.rules });
  } catch (err) {
    fail(`unslop: cannot scan "${options.path}" — ${err.message}`);
  }

  const shown = result.findings.slice(0, options.maxFindings);
  const truncated = result.findings.length - shown.length;

  if (options.json) {
    process.stdout.write(`${toJson(shown)}\n`);
  } else {
    process.stdout.write(
      `${toTable(shown, {
        color: process.stdout.isTTY === true,
        truncated,
        scanned: result.scanned,
        rulesRun: result.rulesRun,
      })}\n`,
    );
  }

  process.exit(result.findings.some((f) => f.severity === 'red') ? 1 : 0);
}

// Node runs the real file behind a symlinked path (a skills folder linked to a shared copy), so compare real paths.
const realPath = (file) => {
  try {
    return fs.realpathSync(file);
  } catch {
    return path.resolve(file);
  }
};
const invokedDirectly =
  process.argv[1] && realPath(process.argv[1]) === realPath(fileURLToPath(import.meta.url));
if (invokedDirectly) main(process.argv.slice(2));
