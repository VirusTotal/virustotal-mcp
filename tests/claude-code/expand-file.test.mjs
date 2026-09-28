// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { expandFile, MAX_BYTES, MAX_INPUT_BYTES } from '../../plugins/claude-code/scripts/expand-file.mjs';

const script = fileURLToPath(new URL('../../plugins/claude-code/scripts/expand-file.mjs', import.meta.url));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function fixture(t, bytes = Buffer.from('Public test fixture, never submitted.')) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vtai upload '));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const filename = path.join(dir, 'sample ü.bin');
  await fs.writeFile(filename, bytes);
  const event = {
    hook_event_name: 'PreToolUse',
    cwd: dir,
    tool_name: 'mcp__plugin_virustotal_virustotal__submit_file',
    mcp_server: { name: 'plugin:virustotal:virustotal', source: 'plugin' },
    tool_input: { sha256: digest(bytes), content_base64: `file:${filename}` },
  };
  return { dir, filename, event, bytes };
}

const run = (input, env = {}) => spawnSync(process.execPath, [script], {
  input: typeof input === 'string' ? input : JSON.stringify(input),
  encoding: 'utf8', timeout: 15_000, maxBuffer: 36_000_000,
  env: { ...process.env, VTAI_UPLOAD_ROOTS: '[]', ...env },
});

test('expands actual bytes and preserves arguments while explicitly allowing', async (t) => {
  const { event, bytes } = await fixture(t);
  event.tool_input.extra = { keep: 'unchanged' };
  const original = structuredClone(event);
  const output = await expandFile(event);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'allow');
  assert.deepEqual(output.hookSpecificOutput.updatedInput, { ...event.tool_input, content_base64: bytes.toString('base64') });
  assert.deepEqual(event, original);
});

test('accepts both imported aliases with case-insensitive alias spelling', async (t) => {
  const { event, bytes } = await fixture(t);
  for (const alias of ['ai.virustotal.com', 'AI.VirusTotal.COM', 'VirusTotal', 'virustotal', 'VIRUSTOTAL']) {
    event.mcp_server = { name: `claude.ai ${alias}`, source: 'claudeai' };
    event.tool_name = `mcp__claude_ai_${alias.replaceAll('.', '_')}__submit_file`;
    assert.equal((await expandFile(event)).hookSpecificOutput.updatedInput.content_base64, bytes.toString('base64'));
  }
});

test('imported aliases require matching tool identity and trusted source before file access', async (t) => {
  const { event } = await fixture(t);
  for (const [source, name, tool] of [
    ['user', 'claude.ai VirusTotal', 'mcp__claude_ai_VirusTotal__submit_file'],
    ['project', 'claude.ai VirusTotal', 'mcp__claude_ai_VirusTotal__submit_file'],
    ['claudeai', 'claude.ai VirusTotal backup', 'mcp__claude_ai_VirusTotal_backup__submit_file'],
    ['claudeai', 'claude.ai VirusTotal', 'mcp__claude_ai_ai_virustotal_com__submit_file'],
    ['claudeai', 'claude.ai ai.virustotal.com', 'mcp__claude_ai_virustotal__submit_file'],
    ['claudeai', 'Claude.ai VirusTotal', 'mcp__claude_ai_VirusTotal__submit_file'],
    ['claudeai', 'claude.ai VirusTotal', 'mcp__claude_ai_VirusTotal__get_submission'],
    ['claudeai', 'claude.ai VirusTotal', 'mcp__claude_ai_VirusTotal__submit_file_extra'],
  ]) {
    await assert.rejects(expandFile({ ...event, mcp_server: { source, name }, tool_name: tool }, { io: {} }));
  }
});

test('credential filenames are denied before any filesystem access, with no changed input', async (t) => {
  const { event, dir } = await fixture(t);
  const names = ['.env', '.ENV.production', 'certificate.PEM', 'private.key', 'id_rsa', 'id_rsa.pub',
    'ID_ED25519_sk', 'id_dsa.old', 'id_ecdsa_sk.pub', 'id_xmss', 'ssh_host_ed25519_key.pub',
    '.NETRC', '.npmrc', '.pypirc', 'credentials', 'CREDENTIALS.json', 'vault.KDBX', 'KubeConfig',
    '.env\nproduction', 'credentials\nx', '.git-credentials', '.pgpass', '.htpasswd',
    'certificate.P12', 'backup.pfx', 'ssh.ppk', 'java.JKS', 'android.keystore'];
  const io = new Proxy({}, { get() { throw new Error('No filesystem operation is allowed'); } });
  for (const name of names) {
    const value = { ...event, tool_input: { ...event.tool_input, content_base64: `file:${path.join(dir, name)}` } };
    const before = structuredClone(value);
    const output = await expandFile(value, { io });
    assert.equal(output.hookSpecificOutput.permissionDecision, 'deny', name);
    assert.equal('updatedInput' in output.hookSpecificOutput, false);
    assert.match(output.hookSpecificOutput.permissionDecisionReason, /human review/);
    assert.ok(!JSON.stringify(output).includes(dir));
    assert.deepEqual(value, before);
  }
});

test('credential filename denial reaches the native launcher protocol without reading bytes', async (t) => {
  const { event, dir } = await fixture(t);
  event.tool_input.content_base64 = `file:${path.join(dir, '.env.nonexistent')}`;
  const result = run(event);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const output = JSON.parse(result.stdout).hookSpecificOutput;
  assert.equal(output.permissionDecision, 'deny');
  assert.equal('updatedInput' in output, false);
  assert.ok(!result.stdout.includes(dir));
});

test('ordinary filenames still expand with allow and exact original bytes', async (t) => {
  const { event, bytes, dir } = await fixture(t);
  for (const name of ['unfamiliar.bin', 'environment.txt', 'public-key.txt', 'public-certificate.crt']) {
    const filename = path.join(dir, name);
    await fs.writeFile(filename, bytes);
    event.tool_input.content_base64 = `file:${filename}`;
    const output = (await expandFile(event)).hookSpecificOutput;
    assert.equal(output.permissionDecision, 'allow');
    assert.deepEqual(Buffer.from(output.updatedInput.content_base64, 'base64'), bytes);
  }
});

for (const source of ['project', 'user', 'local', 'sdk', 'managed', 'future-source', null]) {
  test(`rejects ${source} provenance before touching files`, async (t) => {
    const { event } = await fixture(t);
    event.mcp_server.source = source;
    await assert.rejects(expandFile(event, { io: {} }), /requires the VirusTotal/);
  });
}

test('rejects missing provenance, mixed name/source and similar tool aliases', async (t) => {
  const { event } = await fixture(t);
  const variants = [
    { ...event, mcp_server: undefined },
    { ...event, mcp_server: { source: 'plugin', name: 'claude.ai ai.virustotal.com' } },
    { ...event, mcp_server: { source: 'plugin', name: 'plugin_virustotal_virustotal' } },
    { ...event, tool_name: 'mcp__untrusted_virustotal__submit_file' },
    { ...event, hook_event_name: 'PostToolUse' },
  ];
  for (const value of variants) await assert.rejects(expandFile(value, { io: {} }));
});

test('leaves inline base64 and other input untouched without file access or allow', async () => {
  for (const content_base64 of ['cHVibGlj', '', 'not base64', 1, null]) {
    const event = { tool_input: { content_base64 } };
    assert.equal(await expandFile(event, { io: {} }), null);
    const result = run(event);
    assert.equal(result.status, 0);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  }
});

test('inline payload at the supported base64 limit passes the launcher unchanged', () => {
  const input = { tool_input: { sha256: '0'.repeat(64), content_base64: 'A'.repeat(4 * Math.ceil(MAX_BYTES / 3)) } };
  const result = run(input);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
});

test('malformed and oversized stdin fail without echoing input', () => {
  for (const value of ['{"private":"do not echo', ' '.repeat(MAX_INPUT_BYTES + 1)]) {
    const result = run(value);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.ok(result.stderr.length < 150);
    assert.ok(!result.stderr.includes('do not echo'));
  }
});

test('launcher expands a path with spaces and Unicode without shell interpretation', async (t) => {
  const { event, bytes } = await fixture(t);
  const result = run(event);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const output = JSON.parse(result.stdout).hookSpecificOutput;
  assert.equal(output.permissionDecision, 'allow');
  assert.deepEqual(Buffer.from(output.updatedInput.content_base64, 'base64'), bytes);
});

test('SHA mismatch and malformed SHA never produce expanded bytes', async (t) => {
  const { event } = await fixture(t);
  for (const value of ['0'.repeat(64), 'short', 'A'.repeat(64), null]) {
    const result = run({ ...event, tool_input: { ...event.tool_input, sha256: value } });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
  }
});

test('scope denies sibling paths and accepts only explicitly configured additional roots', async (t) => {
  const inside = await fixture(t);
  const outside = await fixture(t);
  const event = { ...outside.event, cwd: inside.dir };
  await assert.rejects(expandFile(event, { rootsJSON: '[]' }), /outside/);
  assert.equal((await expandFile(event, { rootsJSON: JSON.stringify([outside.dir]) })).hookSpecificOutput.permissionDecision, 'allow');
  for (const rootsJSON of ['bad', '{}', '["relative"]']) await assert.rejects(expandFile(event, { rootsJSON }));
});

test('relative paths and NUL paths are rejected', async (t) => {
  const { event } = await fixture(t);
  for (const content_base64 of ['file:relative.bin', 'file:~/secret', 'file:\0']) {
    await assert.rejects(expandFile({ ...event, tool_input: { ...event.tool_input, content_base64 } }));
  }
});

test('empty files, directories and files over the byte cap are rejected before open', async (t) => {
  const { event, filename, dir } = await fixture(t, Buffer.alloc(0));
  const io = { ...fs, open: () => { throw new Error('must not open'); } };
  await assert.rejects(expandFile(event, { io }), /1 to 24,000,000/);
  await fs.truncate(filename, MAX_BYTES + 1);
  await assert.rejects(expandFile(event, { io }), /1 to 24,000,000/);
  await fs.mkdir(path.join(dir, 'directory'));
  event.tool_input.content_base64 = `file:${path.join(dir, 'directory')}`;
  await assert.rejects(expandFile(event, { io }), /regular file/);
});

test('exact byte cap is locally encoded and rehashed without a network call', async (t) => {
  const { event } = await fixture(t, Buffer.alloc(MAX_BYTES, 37));
  const output = (await expandFile(event)).hookSpecificOutput;
  const bytes = Buffer.from(output.updatedInput.content_base64, 'base64');
  assert.equal(bytes.length, MAX_BYTES);
  assert.equal(digest(bytes), event.tool_input.sha256);
});

test('leaf symlinks and symlinked subdirectories cannot escape or alias the scope', async (t) => {
  const { event, dir, filename } = await fixture(t);
  const leaf = path.join(dir, 'alias.bin');
  await fs.symlink(filename, leaf, 'file');
  await assert.rejects(expandFile({ ...event, tool_input: { ...event.tool_input, content_base64: `file:${leaf}` } }), /symbolic links/);
  const directory = path.join(dir, 'linked');
  await fs.symlink(dir, directory, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(expandFile({ ...event, tool_input: { ...event.tool_input, content_base64: `file:${path.join(directory, path.basename(filename))}` } }), /symbolic links/);
});

test('replacement between lstat and open is rejected', async (t) => {
  const { event, filename } = await fixture(t);
  let closed = false;
  const io = { ...fs, open: async (...args) => {
    await fs.rename(filename, filename + '.old');
    await fs.writeFile(filename, 'Replacement bytes');
    const handle = await fs.open(...args);
    const close = handle.close.bind(handle);
    handle.close = async () => { closed = true; await close(); };
    return handle;
  } };
  await assert.rejects(expandFile(event, { io }), /changed/);
  assert.equal(closed, true);
});

for (const change of ['grow', 'shrink', 'replace-name']) {
  test(`detects ${change} during reading and closes the descriptor`, async (t) => {
    const { event, filename } = await fixture(t, Buffer.alloc(1000, 12));
    let totalRequested = 0, changed = false, closed = false;
    const io = { ...fs, open: async (...args) => {
      const handle = await fs.open(...args);
      const read = handle.read.bind(handle), close = handle.close.bind(handle);
      handle.read = async (buffer, offset, length, position) => {
        totalRequested += length;
        if (!changed) {
          changed = true;
          if (change === 'grow') await fs.appendFile(filename, Buffer.alloc(2000));
          if (change === 'shrink') await fs.truncate(filename, 10);
          if (change === 'replace-name') { await fs.rename(filename, filename + '.old'); await fs.writeFile(filename, Buffer.alloc(1000, 12)); }
        }
        return read(buffer, offset, length, position);
      };
      handle.close = async () => { closed = true; await close(); };
      return handle;
    } };
    await assert.rejects(expandFile(event, { io }), /changed/);
    assert.ok(totalRequested <= 2002);
    assert.equal(closed, true);
  });
}

test('partial descriptor reads assemble the exact file', async (t) => {
  const { event, bytes } = await fixture(t);
  const io = { ...fs, open: async (...args) => {
    const handle = await fs.open(...args), read = handle.read.bind(handle);
    handle.read = (buffer, offset, length, position) => read(buffer, offset, Math.min(length, 3), position);
    return handle;
  } };
  assert.equal((await expandFile(event, { io })).hookSpecificOutput.updatedInput.content_base64, bytes.toString('base64'));
});

for (const replaceAncestor of [false, true]) {
  test(`rejects replacement of the ${replaceAncestor ? 'root ancestor' : 'root'} after realpath`, async (t) => {
    const initial = await fixture(t);
    const outside = await fixture(t);
    const root = path.join(initial.dir, 'parent', 'root');
    await fs.mkdir(root, { recursive: true });
    await fs.mkdir(path.join(outside.dir, 'root'));
    const leaf = path.join(root, 'file.bin');
    await fs.writeFile(leaf, initial.bytes);
    await fs.writeFile(path.join(outside.dir, 'root', 'file.bin'), initial.bytes);
    await fs.writeFile(path.join(outside.dir, 'file.bin'), initial.bytes);
    const event = { ...initial.event, cwd: root, tool_input: { ...initial.event.tool_input, content_base64: `file:${leaf}` } };
    const io = { ...fs, realpath: async (...args) => {
      const result = await fs.realpath(...args);
      const replace = replaceAncestor ? path.dirname(root) : root;
      await fs.rename(replace, replace + '.old');
      await fs.symlink(outside.dir, replace, process.platform === 'win32' ? 'junction' : 'dir');
      return result;
    } };
    await assert.rejects(expandFile(event, { io }), /symbolic link|changed/);
  });
}

test('Windows network, device and alternate stream paths fail before file reads', async (t) => {
  const { event } = await fixture(t);
  const paths = process.platform === 'win32'
    ? ['\\\\server\\share\\file.bin', '\\\\?\\C:\\file.bin', 'C:\\dir\\file:secret', 'C:\\dir\\NUL.txt', 'C:\\dir\\.. \\private.bin', 'C:\\dir\\trailing.\\file.bin']
    : ['C:\\file.bin', '\\\\server\\share\\file.bin'];
  for (const filename of paths) {
    await assert.rejects(expandFile({ ...event, tool_input: { ...event.tool_input, content_base64: `file:${filename}` } }, { io: {} }));
  }
});

test('missing or unreadable file reports a bounded error without paths or content', async (t) => {
  const { event, filename } = await fixture(t);
  await fs.rm(filename);
  const result = run(event);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.ok(!result.stderr.includes(filename));
  assert.ok(result.stderr.length < 150);
});
