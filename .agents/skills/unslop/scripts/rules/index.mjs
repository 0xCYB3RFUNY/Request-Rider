// index.mjs — the rule registry. One module per catalog section.
import ds from './ds.mjs';
import b from './b.mjs';
import c from './c.mjs';
import d from './d.mjs';
import e from './e.mjs';
import f from './f.mjs';
import g from './g.mjs';
import h from './h.mjs';
import i from './i.mjs';
import j from './j.mjs';

export const ALL_RULES = [...ds, ...b, ...c, ...d, ...e, ...f, ...g, ...h, ...i, ...j];

const duplicates = ALL_RULES.map((r) => r.id).filter((id, idx, arr) => arr.indexOf(id) !== idx);
if (duplicates.length) throw new Error(`duplicate rule ids: ${duplicates.join(', ')}`);

export function sectionOf(ruleId) {
  return ruleId.split('-')[0].toUpperCase();
}

export const SECTIONS = [...new Set(ALL_RULES.map((r) => sectionOf(r.id)))].sort();

/** @param {string[]|null} sections e.g. ['B','G'] — null means every rule. */
export function selectRules(sections) {
  if (!sections || sections.length === 0) return ALL_RULES;
  const wanted = new Set(sections.map((s) => s.trim().toUpperCase()).filter(Boolean));
  return ALL_RULES.filter((r) => wanted.has(sectionOf(r.id)) || wanted.has(r.id.toUpperCase()));
}
