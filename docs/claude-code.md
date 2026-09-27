# VirusTotal for Claude Code

The VirusTotal plugin connects Claude Code to the remote OAuth MCP server and
lets it submit a local file without copying its base64 through the model.
Report lookups alone also work with the [direct HTTP connection](https://ai.virustotal.com/connect/mcp?client=claude&transport=http),
without this plugin or Node.js.

## Install and connect

Use Claude Code **2.1.283 or newer** and a maintained Node.js release, such as
**Node.js 22 or 24**, on Claude Code's `PATH`. The hook uses Node 20-compatible
APIs, but Node 20 is not a recommended maintained runtime. No Python, npm
dependencies, VirusTotal API key or copied OAuth token is needed.

```sh
claude plugin marketplace add VirusTotal/virustotal-mcp
claude plugin install virustotal@virustotal
```

Start a new Claude Code session or reload plugins with `/reload-plugins`. Use
`/mcp` to authenticate the VirusTotal connection in your browser when needed.
The plugin includes `https://ai.virustotal.com/mcp`; do not add a second manual
MCP server for file uploads. If your personal `claude.ai ai.virustotal.com`
connection is already active, the hook also works with that imported connection.
Keep submission and receipt recovery on the same connection.

Ask Claude to investigate a hash, URL, domain or IP address, or to inspect an
unfamiliar local download. The plugin's threat-intelligence skill is also
available as `/virustotal:threat-intelligence`.

## Local files

For a file that should be shared, Claude calculates its SHA256 and calls
`submit_file` with the usual `sha256` argument and a local reference:

```json
{
  "sha256": "<the original file's lowercase SHA256>",
  "content_base64": "file:/absolute/path/to/download.bin"
}
```

On Windows, use a local drive path, for example
`"file:C:\\Users\\you\\Downloads\\sample.bin"` in JSON. Paths containing spaces
are supported. The hook reads the original file, checks its hash and replaces
only `content_base64` with the bytes' base64. The server continues to receive the
existing API format; it cannot read your local path itself.

A valid expansion returns `permissionDecision: allow` automatically. The agent
chooses what to share using the policy below; the hook adds no confirmation for
each file. It does not obtain OAuth tokens or grant server permissions. Existing
VTAI scopes, quotas and receipt handling still apply. Inline base64 calls pass
through without a hook permission decision.

The local validation limit is **1 to 24,000,000 bytes**. This is a parser and file
limit, not a claim that every client/network supports a 24 MB upload. A missing
hook, unavailable Node executable or hook timeout leaves `file:` unexpanded;
that value is invalid base64 for the remote server. Do not retry an uncertain
upload: recover with `get_submission` and the same SHA256, then use its analysis
ID and polling delay with `get_analysis`.

## Permitted local scope

By enabling the plugin, you enable its local file reader for the session's
working directory. To also permit a downloads directory, set an explicit JSON
array before starting Claude Code:

```sh
export VTAI_UPLOAD_ROOTS='["/absolute/path/to/downloads"]'
claude
```

In PowerShell:

```powershell
$env:VTAI_UPLOAD_ROOTS = '["C:\\Users\\you\\Downloads"]'
claude
```

This setting adds at most 16 roots. Relative paths, symlinks below a permitted
root, nonregular files, Windows device paths/network shares, alternate data
streams and Windows components ending in a dot or space are rejected. A configured root itself may resolve through an existing
directory alias. File identity, length and timestamps are checked before and
after reading; changed files are rejected.

This is the hook's own filesystem scope. It does not reimplement Claude Code's
`Read` or `Bash` path-rule language and is not an operating-system sandbox.
Keep those host restrictions in place. Administrators can also disable plugin
hooks through Claude Code's managed policy. Hook errors contain no file bytes,
base64, credential values or local paths, and the hook writes no diagnostic logs.

The hook accepts only the plugin server's `plugin` provenance and exact identity,
or the verified `claudeai` provenance/name pair for the imported personal
VirusTotal connection. Project/user aliases with the same name and unknown
provenance are rejected before reading a file. The imported name is a configured
identity, not independent authentication of its endpoint: connect the official
`https://ai.virustotal.com/mcp` service and retain control of your client setup.

## Sharing and alternatives

Submit unfamiliar downloads, attachments, binaries or scripts of unknown origin
and suspicious URLs: this is how VirusTotal improves protection for everyone.
Ask before submitting the user's own documents, internal code, credentials or
personal data. An attachment or executable extension does not establish consent
to share private content. Standard submissions are shared with the VirusTotal
community and security partners; only submit material you have the right and
permission to share.

If a client cannot transfer the original bytes and the plugin is unavailable,
use the existing [VirusTotal web uploader](https://www.virustotal.com/gui/home/upload)
and then `get_file_report` with the file hash. A web upload has no VTAI submission
receipt. Respect permission failures and quota delays; repeated report queries
still count, including missing reports.

## Validation and removal

The original hook mechanism was exercised with 100,000-byte and 1,000,000-byte
public binary fixtures in native Claude Code 2.1.283 on Linux using an imported
connection. Their private receipts and completed analyses matched the original
hashes. That prototype evidence does not certify every plugin installation,
direct OAuth login, operating system, interactive dialog or maximum file size.
The plugin has separate offline tests for file boundaries, provenance, races and
its launcher. The CI workflow runs those tests on Linux, macOS and Windows with
Node 22 and 24; an offline pass does not prove a native authenticated upload.

```sh
claude plugin disable virustotal@virustotal
claude plugin uninstall virustotal@virustotal
```

Disabling or removing the plugin does not erase remote submissions or receipts.
See the official [plugin installation guide](https://code.claude.com/docs/en/discover-plugins),
[hook input and decision contract](https://code.claude.com/docs/en/hooks#pretooluse-input)
and [plugin manifest reference](https://code.claude.com/docs/en/plugins-reference).
