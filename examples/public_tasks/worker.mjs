// Independently implemented, dependency-free JavaScript MCP worker for compatibility qualification.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const [root, childId] = process.argv.slice(2);
const file = fileURLToPath(import.meta.url);
const canonical = value => JSON.stringify(value, (_, v) => v && !Array.isArray(v) && typeof v === 'object'
  ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : v);
const digest = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const log = (kind, data = {}) => fs.appendFileSync(path.join(root, `javascript-events-${process.pid}.jsonl`),
  JSON.stringify({ kind, pid: process.pid, ...data }) + '\n');
if (!root || !fs.lstatSync(root).isDirectory() || fs.lstatSync(root).isSymbolicLink()) throw Error('Owned root required');
if (childId) {
  let input = '';
  for await (const data of process.stdin) input += data;
  const { arguments: args, binding } = JSON.parse(input);
  log('worker-start', { taskId: childId });
  if (Date.now() >= binding.submission.task.deadlineUnixMs) throw Error('deadline');
  const result = { normalized: args.value, binding };
  const descriptor = fs.openSync(path.join(root, childId + '.json'), 'wx');
  fs.writeFileSync(descriptor, canonical(result));
  fs.fsyncSync(descriptor);
  fs.closeSync(descriptor);
  log('worker-effect', { taskId: childId });
} else {
  const tasks = new Map();
  const session = randomUUID();
  const execution = 'dev.gaugemesh/taskExecution';
  const meta = { 'io.modelcontextprotocol/serverInfo': { name: 'independent-javascript-worker', version: '1.0.0' } };
  const capabilities = { tools: {}, extensions: { 'io.modelcontextprotocol/tasks': {} } };
  const tool = { name: 'normalize', description: 'Original synthetic integer normalization in a JavaScript child',
    inputSchema: { type: 'object', properties: { value: { type: 'integer' } }, required: ['value'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false } };
  log('provider-start', { session });
  const cleanup = () => { for (const task of tasks.values()) if (task.code === null) task.process.kill('SIGTERM'); };
  process.on('SIGTERM', () => { cleanup(); process.exit(0); });
  for await (const line of readline.createInterface({ input: process.stdin })) {
    const request = JSON.parse(line);
    if (!Object.hasOwn(request, 'id')) continue;
    log('received', { request });
    const params = request.params ?? {};
    let result;
    try {
      switch (request.method) {
        case 'server/discover': result = { resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities, ttlMs: 0, cacheScope: 'private' }; break;
        case 'tools/list': result = { resultType: 'complete', tools: [tool], ttlMs: 0, cacheScope: 'private' }; break;
        case 'ping': result = { resultType: 'complete' }; break;
        case 'tools/call': {
          const binding = params._meta?.[execution];
          if (params.name !== 'normalize' || !Number.isSafeInteger(params.arguments?.value) || !binding) throw Error('INVALID_REQUEST');
          const taskId = 'js-' + randomUUID();
          const child = spawn(process.execPath, [file, root, taskId], { stdio: ['pipe', 'ignore', 'ignore'] });
          const task = { process: child, code: null, binding, taskId, createdAt: new Date().toISOString() };
          tasks.set(taskId, task);
          child.on('exit', code => { task.code = code ?? -1; });
          child.stdin.end(canonical({ arguments: params.arguments, binding }));
          log('accepted', { taskId, binding });
          result = { resultType: 'task', taskId, status: 'working', createdAt: task.createdAt,
            lastUpdatedAt: task.createdAt, ttlMs: 3600000, pollIntervalMs: 10, _meta: { [execution]: binding } };
          break;
        }
        case 'tasks/get': {
          const task = tasks.get(params.taskId);
          if (!task) throw Error('UNKNOWN_TASK');
          result = { resultType: 'complete', taskId: task.taskId, status: task.code === null ? 'working' : task.code === 0 ? 'completed' : 'failed',
            createdAt: task.createdAt, lastUpdatedAt: new Date().toISOString(), ttlMs: 3600000, _meta: { [execution]: task.binding } };
          if (task.code === 0) {
            const bytes = fs.readFileSync(path.join(root, task.taskId + '.json'));
            result.result = { resultType: 'complete', content: [], isError: false,
              structuredContent: { ...JSON.parse(bytes), artifact: { path: task.taskId + '.json', sha256: digest(bytes) } },
              _meta: { [execution]: task.binding, ...meta } };
          } else if (task.code !== null) result.error = { code: -32001, message: 'WORKER_FAILED' };
          break;
        }
        case 'tasks/cancel': {
          const task = tasks.get(params.taskId);
          if (!task) throw Error('UNKNOWN_TASK');
          if (task.code === null) task.process.kill('SIGTERM');
          result = { resultType: 'complete' };
          break;
        }
        default: throw Error('UNSUPPORTED_METHOD');
      }
      result._meta = { ...result._meta, ...meta };
      const response = { jsonrpc: '2.0', id: request.id, result };
      log('emitted', { response });
      process.stdout.write(JSON.stringify(response) + '\n');
    } catch (error) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, error: { code: -32602, message: error.message } }) + '\n');
    }
  }
  cleanup();
}
