// walker.mjs — file discovery for the unslop detector. Node built-ins only.
import fs from 'node:fs';
import path from 'node:path';

export const SCANNED_EXTENSIONS = new Set([
  '.css',
  '.scss',
  '.html',
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.vue',
  '.svelte',
  '.md',
]);

export const SKIPPED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'out',
  '.next',
  'build',
  '_archive',
  '.turbo',
  '.cache',
  'coverage',
  '.svelte-kit',
  'vendor',
]);

/** Files we never scan even when the extension matches. */
export function isSkippedFile(name) {
  if (name.includes('.bak')) return true; // *.bak, *.bak2, foo.bak.css
  if (/\.min\./.test(name)) return true; // *.min.*
  if (name.startsWith('.')) return true; // dotfiles
  if (/\.d\.ts$/.test(name)) return true; // type declarations carry no UI
  return false;
}

export function isScannable(filePath) {
  const name = path.basename(filePath);
  if (isSkippedFile(name)) return false;
  return SCANNED_EXTENSIONS.has(path.extname(name).toLowerCase());
}

/**
 * Walk a file or directory and return absolute paths of scannable files.
 * Symlinked directories are not followed (cycle safety).
 */
export function walk(target) {
  const abs = path.resolve(target);
  const stat = fs.statSync(abs);
  if (stat.isFile()) return isScannable(abs) ? [abs] : [];

  const found = [];
  const queue = [abs];
  while (queue.length) {
    const dir = queue.shift();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIPPED_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.') && entry.name !== '.') continue;
        queue.push(full);
        continue;
      }
      if (entry.isFile() && isScannable(full)) found.push(full);
    }
  }
  return found.sort();
}
