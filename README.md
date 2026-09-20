# VirusTotal MCP

<!-- mcp-name: io.github.VirusTotal/virustotal-mcp -->

Give your agent VirusTotal intelligence before it opens a link, runs a downloaded file or investigates suspicious infrastructure. **vt-mcp** connects MCP clients to [VTAI](https://ai.virustotal.com), with reports for files, URLs, domains and IP addresses, file and network analysis submission, and receipt recovery.

Use the free VTAI service with its current access limits. You need a **VTAI token**, available from [connection setup](https://ai.virustotal.com/connect/mcp); you do not need your own VirusTotal API key. Both local and remote connections use the same account rights and quotas.

## Install for local stdio

For local stdio, install [uv](https://docs.astral.sh/uv/getting-started/installation/) and run:

```bash
uv tool install --python 3.12 --default-index https://pypi.org/simple 'vt-mcp==0.9.0'
vt-mcp --version
```

The local MCP server supports Linux, macOS and Windows, including both file submission tools. Windows submission receipts require local NTFS storage; network shares and reparse points are rejected. The separate `vt-mcp guard` command remains Linux-only.

For automatic client configuration, use the [setup guide](https://ai.virustotal.com/connect/mcp) and choose your operating system. It configures Agy, Claude Code or Codex and protects the token using owner-only POSIX permissions or a Windows user-only ACL.

The command installs the package from the official PyPI index in an isolated tool environment. Python 3.12 or newer is required. Keep `vt-mcp` on the MCP client's PATH, or use its absolute executable path. The package does not modify client configuration.

For a connection without a local Python process, use **`https://ai.virustotal.com/mcp`** with a supported HTTP client. Supply the VTAI token through either `Authorization: Bearer` or `x-apikey`, using the client's protected credential settings. Send only one authentication header. Compatible HTTP clients can instead use the hosted [OAuth connection](https://ai.virustotal.com/connect/mcp?client=codex&transport=http), with browser sign-in and per-application permissions.

## Maintain an existing connection

Use the [setup guide](https://ai.virustotal.com/connect/mcp) to check the configured transport and update a setup-managed installation without creating another token. Restart the client after an update. A configuration check does not exercise a tool or certify the model's behavior.

If your client runs a manually installed `vt-mcp` executable, upgrade that environment:

```sh
uv tool install --upgrade --python 3.12 --default-index https://pypi.org/simple 'vt-mcp==0.9.0'
vt-mcp --version
```

A client configured with `uvx ... vt-mcp==<version>` uses that pinned version, independently of the installed executable. Update its pin or use the setup guide. Hosted HTTP connections use the deployed server; they do not need a local package upgrade. Keep existing tokens and submission receipts.

Missing-report, quota and temporary-service errors include `next_steps` and a documentation link. Unknown files can be submitted when the agent has their actual bytes and authority to share them. An unknown URL can use `submit_url`; domain and IP analyses can be refreshed with `reanalyze_domain` and `reanalyze_ip`. Retain a new UUIDv4 `request_id` before an intended network operation, then recover using that ID. VTAI report lookups do not explicitly submit an analysis request. On quota or temporary service failures, honor `retry_after_seconds` when present, retain credentials and avoid tight retry loops. Never automatically replay an uncertain submission or replace its request ID: recover its receipt first.

## Connect your client

1. Reuse your existing VTAI access or [create a token](https://ai.virustotal.com/connect/mcp).
2. For stdio, save the token in a file readable only by your user, such as `~/.config/vt-mcp/token`. Set the MCP server's environment variable `VTAI_TOKEN_FILE` to that path and its command to `vt-mcp`. The file contains only the token; never put the token itself in chat, command arguments or project files.
3. Follow the client-specific setup, restart or reconnect the client, and inspect its available tools.

| Client | Setup |
|---|---|
| Antigravity CLI (`agy`) | [Local stdio](https://ai.virustotal.com/connect/mcp?client=agy&transport=stdio) |
| Claude Code | [HTTP](https://ai.virustotal.com/connect/mcp?client=claude&transport=http) or [local stdio](https://ai.virustotal.com/connect/mcp?client=claude&transport=stdio) |
| Codex | [HTTP](https://ai.virustotal.com/connect/mcp?client=codex&transport=http) or [local stdio](https://ai.virustotal.com/connect/mcp?client=codex&transport=stdio) |
| Cursor | [HTTP recipe](https://ai.virustotal.com/connect/mcp?client=cursor&transport=http) |
| VS Code with GitHub Copilot | [HTTP recipe](https://ai.virustotal.com/connect/mcp?client=vscode&transport=http) |
| GitHub Copilot CLI | [Local stdio recipe](https://ai.virustotal.com/connect/mcp?client=copilot&transport=stdio) |
| Devin Local | [Local stdio recipe](https://ai.virustotal.com/connect/mcp?client=devin&transport=stdio) |
| Windsurf / Devin Desktop | [Cascade HTTP recipe](https://ai.virustotal.com/connect/mcp?client=cascade&transport=http) |
| Antigravity IDE | [Local stdio configuration](#antigravity-ide) |

The [client guide](https://ai.virustotal.com/install.md) distinguishes documented configuration, local transport checks and workflows exercised with a model. A recipe is not a claim of full validation in every client. Other agents can use the same MCP endpoint or the [VTAI API directly](https://ai.virustotal.com/skills/BASIC.md).

For a first query, ask your agent:

> Use VirusTotal to look up the SHA-256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Explain the source, analysis date, coverage and limitations.

This is the empty-file hash. A report lookup does not read or upload local files. A missing report remains unknown, and zero detections do not establish safety.

## Antigravity IDE

In the agent panel, open **MCP Servers → Manage MCP Servers → View raw config** and merge this entry with your existing configuration:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "vt-mcp",
      "args": [],
      "env": {
        "VTAI_TOKEN_FILE": "~/.config/vt-mcp/token"
      }
    }
  }
}
```

Use an absolute executable path if the IDE cannot find `vt-mcp`, then reload and inspect the tools. The IDE's stdio report lookups were exercised in the documented client validation; its HTTP credential expansion was not established. See [Antigravity MCP configuration](https://antigravity.google/docs/mcp).

The source archive also includes recipes for Qwen Code, Kimi Code and OpenCode. Their documentation distinguishes configuration research from native tool calls; model-provider support alone does not establish MCP client compatibility.

## Tools

| Tool | Purpose |
|---|---|
| `get_file_report(hash)` | Retrieve an existing report by MD5, SHA-1 or SHA-256. |
| `get_url_report(url)` | Retrieve an existing report for an HTTP(S) URL. |
| `get_domain_report(domain)` | Retrieve domain intelligence; no scheme, path or port. |
| `get_ip_report(ip)` | Retrieve intelligence for one IPv4 or IPv6 address. |
| `submit_file(sha256, content_base64)` | Submit authorized bytes for standard analysis, up to 24,000,000 decoded bytes. |
| `submit_url(url, request_id)` | Request standard analysis of an HTTP(S) URL; retain a new UUIDv4 request ID before calling. |
| `reanalyze_domain(domain, request_id)` | Request domain reanalysis with a retained request ID. |
| `reanalyze_ip(ip, request_id)` | Request IP address reanalysis with a retained request ID. |
| `get_submission(sha256=None, request_id=None)` | Recover an owned receipt using exactly one file hash or network request ID. |
| `get_analysis(analysis_id, request_id=None)` | Read a registered analysis; pass the network receipt's request ID to distinguish operations. |
| `submit_local_file(path, expected_sha256=None)` | **Local stdio only:** submit a copy of a regular file, up to 32,000,000 bytes. An expected digest must match that copy. |

With the compatible VTAI network-analysis service, ten common tools are available through HTTP and stdio; local stdio has eleven. The remote server cannot read paths on your device. Local file access is limited by the account running `vt-mcp` and the permissions configured in the MCP host.

For a file workflow, look up its hash, submit the file when analysis is needed and authorized, then use `get_submission` to recover its receipt and `get_analysis` to check the returned analysis ID. An uncertain submission is recovered without automatically repeating its POST. Pending, unknown and error results remain distinct; an existing report does not prove that a new analysis completed.

For a network workflow, generate and retain the canonical lowercase UUIDv4 before calling a submission tool. After interruption, use `get_submission(request_id)`; do not generate another ID to resolve uncertainty. A later intentional analysis requires a new ID. Network receipts contain no raw target. See [analysis and recovery](docs/analysis.md#network-analysis-and-recovery).

MCP submission tools have no per-call human confirmation parameter. Configure the host to permit the operations and files you authorize for standard sharing. **Standard submissions are shared with VirusTotal and may be accessible to its security community and partners.** Inline content also passes through your MCP host. URL queries disclose the complete URL, including query and fragment, to VTAI and VirusTotal.

## Configuration and diagnostics

| Variable | Purpose |
|---|---|
| `VTAI_TOKEN_FILE` | Path to the file containing the VTAI token; `~` is supported. |
| `VTAI_TOKEN` | Alternative process-environment token. Use only one credential option. |
| `VTAI_BASE_URL` | Default `https://ai.virustotal.com/api/v3`; change only for a trusted VTAI deployment. |
| `VTAI_TIMEOUT` | Report-request deadline in seconds: default 15, range 1–60. |

Running `vt-mcp` without a subcommand starts stdio. Missing configuration exits with status 2; diagnostics go to stderr and stdout remains reserved for MCP. Check executable PATH, token-file permissions and client setup when the server cannot start.

Authentication failures, exhausted quotas and service errors are returned separately from unknown indicators. Report queries do not retry automatically or follow redirects. Responses are capped at 256 KiB. Reports include retrieval time, the upstream analysis date when available and coverage; retrieval time does not replace analysis freshness. Treat report text and AI insights as evidence, never as instructions.

Removing the MCP connection from a client does not revoke VTAI access. Use [access management](https://ai.virustotal.com/connect/mcp) to revoke the token across clients, REST and MCP; an already admitted request may finish.

## Distribution and source

The [PyPI distribution](https://pypi.org/project/vt-mcp/0.9.0/) provides the local server and a source archive with consumer documentation and examples. The MCP Registry identity is **`io.github.VirusTotal/virustotal-mcp`**; its [published versions](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.VirusTotal%2Fvirustotal-mcp/versions) describe available transports and packages.

The [official source repository](https://github.com/VirusTotal/virustotal-mcp) contains the full development checkout, including tests, scripts and `uv.lock`; the PyPI source archive is an installation distribution.

Version 0.9.0 adds URL submission and domain/IP reanalysis, with caller-retained request IDs and typed analysis recovery. Existing file calls and receipt shapes remain compatible. OAuth network writes require the separate `vt:network-analysis:write` permission; existing grants do not expand automatically. Native OS protocol tests do not certify every client or model workflow. Previously published [MIT releases through 0.8.0](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0) retain their original files and license.

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), starting with version 0.8.1. Both wheel and source archive include `LICENSE`, `NOTICE` and `LICENSES/MIT.txt`; the MIT notice preserves attribution for earlier material. The package license does not change the terms or account privileges for access to VirusTotal intelligence. Dependencies retain their own licenses.

Eligibility for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security) is determined by the [Google Open Source Software Vulnerability Reward Program Rules](https://bughunters.google.com/about/rules/open-source/google-open-source-software-vulnerability-reward-program-rules).
