# Google client connections

Start with [Agy](clients.md#antigravity-cli-agy); the other primary guides are
[Claude Code](clients.md#claude-code) and [Codex](clients.md#codex-cli--remote-http).
This page adds native remote configuration for Antigravity and a Gemini CLI
extension. The existing Agy stdio setup remains available for unattended use.

## Antigravity native OAuth

Merge [antigravity-oauth.json](../examples/client-configs/antigravity-oauth.json)
into the configuration opened by your application's MCP manager:

```json
{
  "mcpServers": {
    "virustotal": {
      "serverUrl": "https://ai.virustotal.com/mcp"
    }
  }
}
```

Preserve other servers. Replace an existing `virustotal` entry rather than mixing
`command` and `serverUrl` or configuring two connections. This OAuth recipe has no
static token, custom header or Google ADC requirement. Antigravity's remote field
is `serverUrl`; Gemini CLI's `httpUrl` is a different configuration format.

For Agy, the equivalent command is:

```sh
agy mcp add --type http virustotal https://ai.virustotal.com/mcp
```

Reload the server in `/mcp`. In Antigravity's graphical MCP settings, use
**Authenticate**, complete the browser consent, and finish any callback/code step
shown by your application. Approve only permissions needed for your tasks. An
Antigravity model login does not itself grant VTAI access.

If your installed client has no working OAuth action, use the
[stdio token-file setup](clients.md#antigravity-cli-agy). Do not work around a
missing OAuth flow by pasting a credential into a shared JSON file.

Google documents global configuration at `~/.gemini/config/mcp_config.json` and
workspace configuration at `.agents/mcp_config.json`. Use the application's
**View raw config** action to select the right file for your version.
[Official configuration and OAuth guide](https://antigravity.google/docs/mcp).

For updates, refresh/reconnect the remote server; no local vt-mcp package is used.
Remove it through the manager or `agy mcp remove virustotal`. Also revoke the
connection in [Your connections](https://ai.virustotal.com/oauth/connections) when
disconnecting permanently; removing a local entry alone does not revoke access.

## Gemini CLI extension

Gemini CLI users with an eligible model account can install the extension from
the official source repository:

```sh
gemini extensions install https://github.com/VirusTotal/virustotal-mcp --ref main
gemini extensions list
```

Accept the CLI's source-trust prompt after reviewing the repository. `--ref main`
selects the current manifest; older package release archives do not contain it.
If the CLI offers a Git-clone fallback for that branch, accept it. Git is required.
There is no Python process, package installation or token-setting prompt in this
extension: it connects to the hosted service using OAuth.

If `virustotal` already exists in your Gemini `settings.json`, choose one
connection and preserve unrelated entries. A manual entry can override the
extension's server; installing the extension does not migrate existing settings.

Start Gemini in a trusted workspace and run:

```text
/mcp auth virustotal
/mcp list
```

Complete browser sign-in and consent. The extension requests report access, file
submission and network-analysis permissions. Submission permissions allow your
application to send authorized files or indicators under VirusTotal's standard
sharing terms without a VTAI confirmation on each call. Host tool permissions
still apply. For a read-only manual setup, copy the manifest's `mcpServers` entry
into your own configuration with only `vt:reports:read` in `oauth.scopes`, and
disable the extension to avoid duplicate configuration. Adding write scopes later
requires a new consent; refreshing an old token does not expand its grant.

Run an actual report query to verify the connection:

> Use VirusTotal to retrieve the existing report for example.com. Explain its
> source, analysis date and coverage. Do not request a new analysis.

Inspect the tool result. A connected status or successful install alone does not
establish that a model called a tool. The remote service has ten tools; the local
`submit_local_file` tool requires stdio.

Maintain or remove the extension with:

```sh
gemini extensions update virustotal
gemini extensions uninstall virustotal
```

Restart Gemini after an update. Uninstalling does not revoke the grant; use
[Your connections](https://ai.virustotal.com/oauth/connections). Reuse your existing
access after quota errors rather than registering another identity.

Google retired consumer Gemini CLI Google login for Code Assist individuals,
Google AI Pro and Ultra on 18 June 2026. Those users should use Agy. Eligible
Standard/Enterprise accounts and Gemini API-key authentication have separate
model-access requirements; installing this extension does not provide model
access. [Google transition notice](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/).

## Validation and discovery

On 23 September 2026, Gemini CLI 0.58.0 installed the exact extension manifest
from a local checkout in an isolated client configuration. Its native extension
listing recognized version 0.9.1 and the `virustotal` MCP server. No production
OAuth consent, tool call or model workflow was performed in that check. The
manifest follows [Gemini's extension format](https://geminicli.com/docs/extensions/reference/)
and [MCP OAuth configuration](https://geminicli.com/docs/tools/mcp-server/).

Antigravity's OAuth fragment follows Google's current documentation. Agy 1.2.2
help accepts the HTTP add command; its `mcp list` command did not list a temporary
workspace-only fixture. Global configuration was preserved. Native remote login,
tool calls, renewal and revocation remain unverified; the earlier
[stdio workflow evidence](clients.md#validation-levels) retains its original scope.

The public repository's root `gemini-extension.json` provides gallery metadata.
Google's [gallery discovery process](https://geminicli.com/docs/extensions/releasing/)
uses the `gemini-cli-extension` repository topic and a periodic crawl. A published
manifest or topic is not proof of gallery acceptance or Antigravity Store placement.
