// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const MAX_BYTES = 24_000_000;
export const MAX_INPUT_BYTES = 4 * Math.ceil(MAX_BYTES / 3) + 65_536;

const IMPORTED_ALIASES = ['virustotal', 'ai.virustotal.com'];
const CREDENTIAL_NAME = /^(?:\.env.*|id_(?:rsa|dsa|ecdsa|ed25519|xmss).*|ssh_host_.*_key.*|\.netrc|\.npmrc|\.pypirc|credentials.*|kubeconfig)$|\.(?:pem|key|kdbx)$/is;

function trustedTool(server, tool) {
  if (!object(server) || typeof server.name !== 'string' || typeof tool !== 'string') return false;
  if (server.source === 'plugin') {
    return server.name === 'plugin:virustotal:virustotal' && tool === 'mcp__plugin_virustotal_virustotal__submit_file';
  }
  if (server.source !== 'claudeai' || !server.name.startsWith('claude.ai ') ||
      !tool.startsWith('mcp__claude_ai_') || !tool.endsWith('__submit_file')) return false;
  const alias = server.name.slice('claude.ai '.length).toLowerCase();
  return IMPORTED_ALIASES.includes(alias) &&
    tool.slice('mcp__claude_ai_'.length, -'__submit_file'.length).toLowerCase() === alias.replaceAll('.', '_');
}

class UploadError extends Error {}
const reject = (message) => { throw new UploadError(message); };
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const within = (root, target) => {
  const relative = path.relative(root, target);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};
const sameFile = (a, b) => ['dev', 'ino', 'mode', 'size', 'mtimeNs', 'ctimeNs'].every((key) => a[key] === b[key]);

function absoluteFile(value) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value)) {
    reject('Use file: followed by an absolute local path.');
  }
  if (process.platform === 'win32') {
    // Exclude network/device namespaces, alternate streams and DOS device names.
    if (!/^[a-z]:[\\/]/i.test(value) || value.slice(2).includes(':') ||
        value.split(/[\\/]/).some((part) => /[ .]$/.test(part) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) {
      reject('Use an ordinary local drive path, without device names or alternate streams.');
    }
  }
  return path.resolve(value);
}

async function scopedPath(filename, cwd, rootsJSON, io) {
  const roots = [absoluteFile(cwd)];
  if (rootsJSON !== undefined) {
    let extra;
    try { extra = JSON.parse(rootsJSON); } catch { reject('VTAI_UPLOAD_ROOTS must be a JSON array of absolute directories.'); }
    if (!Array.isArray(extra) || extra.length > 16) reject('VTAI_UPLOAD_ROOTS must contain at most 16 directories.');
    roots.push(...extra.map(absoluteFile));
  }
  for (const root of roots) {
    const canonical = await io.realpath(root);
    const base = within(root, filename) ? root : within(canonical, filename) ? canonical : null;
    if (base === null) continue;
    const target = path.join(canonical, path.relative(base, filename));
    // Trust the configured root itself; reject symlinks below it, including the leaf.
    const parents = [];
    let current = path.parse(canonical).root;
    const rootParts = path.relative(current, canonical).split(path.sep).filter(Boolean);
    for (const part of ['', ...rootParts]) {
      current = path.join(current, part);
      const state = await io.lstat(current, { bigint: true });
      if (!state.isDirectory() || state.isSymbolicLink()) reject('The upload root changed or contains a symbolic link.');
      parents.push([current, state]);
    }
    const parts = path.relative(canonical, target).split(path.sep);
    for (const part of parts.slice(0, -1)) {
      current = path.join(current, part);
      const state = await io.lstat(current, { bigint: true });
      if (!state.isDirectory() || state.isSymbolicLink()) reject('Upload paths must not contain symbolic links.');
      parents.push([current, state]);
    }
    return { target, parents };
  }
  reject('The file is outside this working directory and VTAI_UPLOAD_ROOTS.');
}

async function readFile(filename, cwd, rootsJSON, io) {
  const { target, parents } = await scopedPath(filename, cwd, rootsJSON, io);
  const expected = await io.lstat(target, { bigint: true });
  if (!expected.isFile() || expected.isSymbolicLink()) reject('Upload only a regular file, without symbolic links.');
  if (expected.size < 1n || expected.size > BigInt(MAX_BYTES)) reject('The file must contain 1 to 24,000,000 bytes.');
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0);
  const handle = await io.open(target, flags);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || !sameFile(expected, before)) reject('The file changed before it could be read.');
    // One extra byte detects growth without an unbounded read or another open.
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, Math.min(65_536, buffer.length - length), length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const named = await io.lstat(target, { bigint: true });
    if (length !== Number(before.size) || !sameFile(before, after) ||
        !named.isFile() || named.isSymbolicLink() || !sameFile(after, named)) {
      reject('The file changed while it was being read.');
    }
    for (const [directory, state] of parents) {
      const now = await io.lstat(directory, { bigint: true });
      if (!now.isDirectory() || now.isSymbolicLink() || now.dev !== state.dev || now.ino !== state.ino) {
        reject('The upload directory changed while reading.');
      }
    }
    return buffer.subarray(0, length);
  } finally {
    await handle.close();
  }
}

export async function expandFile(event, { io = fs, rootsJSON = process.env.VTAI_UPLOAD_ROOTS } = {}) {
  if (!object(event) || !object(event.tool_input)) reject('Invalid upload hook input.');
  const input = event.tool_input;
  if (typeof input.content_base64 !== 'string' || !input.content_base64.startsWith('file:')) return null;
  const server = event.mcp_server;
  if (event.hook_event_name !== 'PreToolUse' || !trustedTool(server, event.tool_name)) {
    reject('The local file reference requires the VirusTotal plugin or verified imported VirusTotal connection.');
  }
  const filename = absoluteFile(input.content_base64.slice(5));
  if (CREDENTIAL_NAME.test(path.basename(filename))) {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: 'This filename may contain credentials. Ask the user for human review. Do not rename, encode or reroute it to bypass this block.',
      },
    };
  }
  if (typeof input.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(input.sha256)) reject('Compute the original file SHA256 before submitting.');
  const bytes = await readFile(filename, event.cwd, rootsJSON, io);
  if (createHash('sha256').update(bytes).digest('hex') !== input.sha256) reject('The file bytes do not match the supplied SHA256.');
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      updatedInput: { ...input, content_base64: bytes.toString('base64') },
      permissionDecision: 'allow',
      permissionDecisionReason: 'VirusTotal file bytes, SHA256 and permitted local scope verified.',
    },
  };
}

async function main() {
  try {
    const chunks = [];
    let length = 0;
    for await (const chunk of process.stdin) {
      length += chunk.length;
      if (length > MAX_INPUT_BYTES) reject('Upload hook input exceeds the supported size.');
      chunks.push(chunk);
    }
    const output = await expandFile(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    if (output !== null) process.stdout.write(JSON.stringify(output));
  } catch (error) {
    // Exit 2 blocks the call even when Claude ignores stdout after a hook error.
    process.stderr.write(error instanceof UploadError ? error.message : 'VirusTotal could not validate or read this local file.');
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
