// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));
const json = async (filename) => JSON.parse(await readFile(path.join(root, filename), 'utf8'));

test('marketplace resolves to the packaged plugin and its canonical credential-free MCP server', async () => {
  const marketplace = await json('.claude-plugin/marketplace.json');
  const pluginRoot = marketplace.plugins[0].source;
  const manifest = await json(`${pluginRoot}/.claude-plugin/plugin.json`);
  const contract = await json('src/vt_mcp/client_contracts.json');
  assert.deepEqual(await json(`${pluginRoot}/client-contracts.json`), contract);
  assert.equal(manifest.version, contract.claude_code.plugin_version);
  assert.equal(contract.claude_code.node_minimum_major, 22);
  assert.deepEqual(contract.claude_code.verified_node_majors, [22, 24]);
  assert.equal(marketplace.name, 'virustotal');
  assert.equal(marketplace.plugins[0].name, manifest.name);
  assert.equal(manifest.name, 'virustotal');
  assert.deepEqual(await json(`${pluginRoot}/.mcp.json`), { virustotal: { type: 'http', url: 'https://ai.virustotal.com/mcp' } });
  const hooks = await json(`${pluginRoot}/hooks/hooks.json`);
  const entry = hooks.hooks.PreToolUse[0];
  assert.equal(entry.hooks[0].command, 'node');
  assert.deepEqual(entry.hooks[0].args, ['${CLAUDE_PLUGIN_ROOT}/scripts/expand-file.mjs']);
  const matcher = new RegExp(entry.matcher);
  assert.ok(matcher.test('mcp__plugin_virustotal_virustotal__submit_file'));
  assert.ok(matcher.test('mcp__claude_ai_ai_virustotal_com__submit_file'));
  for (const alias of ['VirusTotal', 'virustotal', 'VIRUSTOTAL', 'AI_VirusTotal_COM']) {
    assert.ok(matcher.test(`mcp__claude_ai_${alias}__submit_file`));
  }
  assert.equal(matcher.test('mcp__claude_ai_VirusTotal_backup__submit_file'), false);
  assert.equal(matcher.test('mcp__claude_ai_VirusTotal__get_submission'), false);
  assert.equal(matcher.test('mcp__untrusted_virustotal__submit_file'), false);
  assert.equal(matcher.test('prefix_mcp__plugin_virustotal_virustotal__submit_file_suffix'), false);
  const executable = entry.hooks[0].args[0].replace('${CLAUDE_PLUGIN_ROOT}', pluginRoot);
  await readFile(path.join(root, executable));
});
