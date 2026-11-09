import { DETECTOR_VERSION } from './detector-version.mjs';
import { detect } from '../detect.mjs';
import { ALL_RULES } from '../rules/index.mjs';
import { validateCanon, ruleCoverage } from './canon.mjs';
import { applyVerdicts, auditRunStatus } from './verdict.mjs';
import { ruleHash, routeTopics } from './canon-routed.mjs';

/** Read-only audit. A local detector binding is valid for one exact canon hash. */
export async function auditCanon(target, run, { bindings = [], facts = {}, evidenceByRule = {} } = {}) {
  const loaded = await run.load();
  const snapshot = validateCanon(loaded.snapshot);
  const known = new Set(ALL_RULES.map(rule => rule.id));
  const bound = bindings.filter(binding => binding.canonChecksum === snapshot.checksum &&
    binding.detectorVersion === DETECTOR_VERSION && known.has(binding.ruleId));
  const coverage = snapshot.payload.rules.map(rule => {
    const result = ruleCoverage(snapshot, rule.id, bound.map(binding => binding.ruleId));
    return { ...result, detectorVersion: result.coverage === 'detector'
      ? bound.find(binding => binding.ruleId === rule.id).detectorVersion : null };
  });
  const executable = coverage.filter(rule => rule.coverage === 'detector').map(rule => rule.ruleId);
  // detect([]) means all rules in the legacy detector; never use it for no coverage.
  const result = executable.length ? detect(target, { rules: executable }) : { findings: [], scanned: 0, rulesRun: 0 };
  const detected = result.findings.map(finding => ({ ...finding,
    canon: coverage.find(rule => rule.ruleId === finding.rule),
  }));
  const findings = applyVerdicts(snapshot.payload.rules, detected, facts, evidenceByRule);
  return {
    schemaVersion: 1,
    status: auditRunStatus({
      findings,
      coverage,
      scanned: result.scanned,
      stale: loaded.stale,
    }),
    provenance: { version: snapshot.payload.version, checksum: snapshot.checksum,
      source: snapshot.payload.source, endpoint: loaded.endpoint, origin: loaded.origin, stale: loaded.stale },
    coverage, findings, scanned: result.scanned, rulesRun: result.rulesRun,
    ownerAccepted: false,
  };
}

/**
 * Routed audit: only the requested topics' rules. Bindings bind to the INDEX checksum,
 * so a new canon version never silently inherits an old binding. A local store never reports clean.
 */
export async function auditRouted(target, run, { topics, bindings = [], facts = {}, evidenceByRule = {}, localStore = false } = {}) {
  const { envelope: index } = await run.loadIndex();
  const loaded = [];
  for (const topic of topics) loaded.push(await run.loadTopic(topic));
  const rules = loaded.flatMap(item => item.envelope.payload.rules);
  const pinned = { payload: { version: index.payload.version, rules }, checksum: index.checksum };
  const known = new Set(ALL_RULES.map(rule => rule.id));
  // A binding counts only for this index checksum, this detector version and the exact rule record.
  const hashes = new Map(rules.map(rule => [rule.id, ruleHash(rule)]));
  const bound = bindings.filter(binding => binding.canonChecksum === index.checksum &&
    binding.detectorVersion === DETECTOR_VERSION && known.has(binding.ruleId) &&
    typeof binding.ruleHash === 'string' && binding.ruleHash === hashes.get(binding.ruleId));
  const coverage = rules.map(rule => {
    const result = ruleCoverage(pinned, rule.id, bound.map(binding => binding.ruleId));
    // A binding exists, but for an older index checksum or detector version: say so explicitly.
    const stale = result.coverage === 'unsupported' && rule.mode === 'detector' &&
      bindings.some(binding => binding.ruleId === rule.id);
    const unbound = rule.mode === 'detector' && result.coverage === 'unsupported';
    return { ...result, coverage: stale ? 'binding-stale' : result.coverage, topic: rule.topic,
      detectorVersion: result.coverage === 'detector' ? DETECTOR_VERSION : null,
      ...(unbound ? { hint: `needs bind for ${index.checksum}` } : {}) };
  });
  const executable = coverage.filter(rule => rule.coverage === 'detector').map(rule => rule.ruleId);
  const result = executable.length ? detect(target, { rules: executable }) : { findings: [], scanned: 0, rulesRun: 0 };
  const detected = result.findings.map(finding => ({ ...finding, canon: coverage.find(rule => rule.ruleId === finding.rule) }));
  const findings = applyVerdicts(rules, detected, facts, evidenceByRule);
  let status = auditRunStatus({ findings, coverage, scanned: result.scanned, stale: false });
  if (!topics.length) status = 'needs-review';
  if (localStore && status === 'machine-checks-clear') status = 'needs-review';
  return {
    status,
    provenance: { version: index.payload.version, checksum: index.checksum, endpoint: run.endpoint,
      origin: localStore ? 'local-store' : 'remote', localStore },
    coverage, findings, scanned: result.scanned, rulesRun: result.rulesRun, ownerAccepted: false,
  };
}

/**
 * Route + audit for one project. If the served index changed during the run (see
 * createRoutedRun), topics are re-routed against the new index and the audit runs once more,
 * so findings never mix versions. `bindingsFor(index)` supplies bindings per index checksum.
 */
export async function auditRoutedProject(project, files, run, { bindingsFor = async () => [], ...options } = {}) {
  let index = (await run.loadIndex()).envelope;
  let topics = routeTopics(index, files);
  let audit = await auditRouted(project, run, { ...options, topics, bindings: await bindingsFor(index) });
  const changed = run.indexChanged;
  if (changed) {
    index = (await run.loadIndex()).envelope;
    topics = routeTopics(index, files);
    audit = await auditRouted(project, run, { ...options, topics, bindings: await bindingsFor(index) });
  }
  const notes = changed ? [`index changed during run: ${changed.from} -> ${changed.to}`] : [];
  return { index, topics, audit, notes };
}
