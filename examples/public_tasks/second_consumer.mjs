// A second independent, standard-library public caller. No Python client or GaugeMesh library imports.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const [binaryArgument, outputArgument] = process.argv.slice(2);
const binary = fs.realpathSync(binaryArgument), root = path.resolve(outputArgument);
fs.mkdirSync(root, { recursive: false });
const workerRoot = path.join(root, 'worker'); fs.mkdirSync(workerRoot);
const config = path.join(root, 'gateway.yaml');
execFileSync(binary, ['init', config]);
fs.writeFileSync(config, fs.readFileSync(config, 'utf8').replace('mode: memory', 'mode: sqlite\n  database: ' + JSON.stringify(path.join(root, 'state.sqlite'))));
execFileSync(binary, ['add', 'mcp', 'javascript', '--config', config, '--command', process.execPath,
  '--arg', fileURLToPath(new URL('./worker.mjs', import.meta.url)), '--arg', workerRoot]);
const canonical = value => JSON.stringify(value, (_, v) => v && !Array.isArray(v) && typeof v === 'object'
  ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : v);
const digest = value => 'sha256:' + createHash('sha256').update(canonical(value)).digest('hex');
const gateway = spawn(binary, ['mcp-stdio', '--config', config], { stdio: ['pipe', 'pipe', 'pipe'] });
gateway.stderr.on('data', bytes => fs.appendFileSync(path.join(root, 'gateway-stderr.txt'), bytes));
const pending = new Map(); let sequence = 0;
const wire = data => fs.appendFileSync(path.join(root, 'client-wire.jsonl'), JSON.stringify(data) + '\n');
readline.createInterface({ input: gateway.stdout }).on('line', line => {
  const response = JSON.parse(line); wire({ received: response });
  const waiter = pending.get(response.id); if (!waiter) throw Error('Unsolicited response');
  clearTimeout(waiter.timer); pending.delete(response.id);
  if (response.error) waiter.reject(Error(JSON.stringify(response.error))); else waiter.resolve(response.result);
});
function rpc(method, params = {}) {
  const id = ++sequence;
  const request = { jsonrpc: '2.0', id, method, params: { ...params, _meta: {
    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientInfo': { name: 'independent-javascript-caller', version: '1.0.0' },
    'io.modelcontextprotocol/clientCapabilities': { extensions: { 'io.modelcontextprotocol/tasks': {} } } } } };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(Error('RPC_TIMEOUT')); }, 10000);
    pending.set(id, { resolve, reject, timer }); wire({ sent: request }); gateway.stdin.write(JSON.stringify(request) + '\n');
  });
}
async function tool(name, args) {
  const result = await rpc('tools/call', { name, arguments: args });
  assert.ok(!result.isError, JSON.stringify(result)); return result.structuredContent;
}
try {
  await rpc('server/discover');
  const description = await tool('gaugemesh_describe', { alias: 'javascript__normalize' });
  const lease = await tool('gaugemesh_lease', { aliases: ['javascript__normalize'], ttlMs: 600000,
    sideEffects: ['read_only', 'idempotent_write', 'non_idempotent_write'] });
  const step = (id, source) => {
    const args = { value: source ? { kind: 'predecessor', step: source, pointer: '/normalized' } : { kind: 'literal', value: 23 } };
    const policy = { schemaVersion: 'gaugemesh.json-artifact-policy/1', checks: [{ pointer: '/normalized', expected: 23, required: true }] };
    return { id, dependsOn: source ? [source] : [], alias: 'javascript__normalize', capabilityId: description.capabilityId,
      providerInterfaceVersion: description.schemaDigest, arguments: args, inputsSha256: digest(args), policy, policySha256: digest(policy),
      permittedEffect: 'non_idempotent_write', maxRuntimeMs: 30000, maxArtifactBytes: 1048576 };
  };
  const plan = { schemaVersion: 'gaugemesh.run-plan/1', runKey: 'javascript-two-step', deadlineUnixMs: Date.now() + 120000,
    maxConcurrency: 2, maxAttempts: 1, failurePolicy: 'fail_fast_account_inflight', uncertaintyPolicy: 'stop_no_replay',
    cancellationPolicy: 'intent_then_poll', artifactRoot: workerRoot, steps: [step('first'), step('second', 'first')] };
  const accepted = await tool('gaugemesh_run', { action: 'submit', plan, leaseId: lease.leaseId });
  let state;
  for (let attempt = 0; attempt < 300; attempt++) {
    state = await tool('gaugemesh_run', { action: 'resume', runId: accepted.runId, leaseId: lease.leaseId });
    if (state.status === 'verified') break;
    assert.ok(['ready', 'in_progress'].includes(state.status), JSON.stringify(state));
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(state.status, 'verified');
  const evidence = await tool('gaugemesh_run', { action: 'export', runId: accepted.runId });
  const evidenceFile = path.join(root, 'export.json'); fs.writeFileSync(evidenceFile, JSON.stringify(evidence));
  const verification = JSON.parse(execFileSync(binary, ['run-verify', '--evidence', evidenceFile], { encoding: 'utf8' }));
  assert.equal(verification.complete, true);
  const events = fs.readdirSync(workerRoot).filter(name => /^javascript-events-.*\.jsonl$/.test(name))
    .flatMap(name => fs.readFileSync(path.join(workerRoot, name), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse));
  assert.equal(events.filter(e => e.kind === 'worker-start').length, 2);
  assert.equal(events.filter(e => e.kind === 'worker-effect').length, 2);
  const result = { status: 'PASS', suite: 'independent-javascript-client-and-worker/1', runId: accepted.runId,
    starts: 2, effects: 2, verification, binarySha256: createHash('sha256').update(fs.readFileSync(binary)).digest('hex') };
  fs.writeFileSync(path.join(root, 'result.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
} finally {
  gateway.stdin.end();
  const timeout = setTimeout(() => gateway.kill('SIGTERM'), 5000);
  await new Promise(resolve => gateway.once('exit', resolve)); clearTimeout(timeout);
}
