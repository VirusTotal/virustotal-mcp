# Find and connect to VirusTotal MCP

The corporate source is being prepared at
[VirusTotal/virustotal-mcp](https://github.com/VirusTotal/virustotal-mcp), currently
a private repository. It is a new repository with the existing public source
history copied into it, not a transfer of the original repository ID. The
[public source](https://github.com/king-tero/vt-mcp) and its
[v0.8.0 release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0) remain the
available distribution until the corporate cutover. No corporate release or
registry publication is claimed here.

Start with the setup for [Antigravity CLI (`agy`)](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), or [Codex](clients.md#codex-cli--remote-http).

## MCP Registry

The active entry is still
[`io.github.king-tero/vt-mcp` version 0.8.0](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.king-tero%2Fvt-mcp/versions/0.8.0).
[`server.json`](../server.json) prepares the corporate name
`io.github.VirusTotal/virustotal-mcp`, bound to GitHub repository ID `1361592455`.
Both describe the same Streamable HTTP endpoint at `https://ai.virustotal.com/mcp`
and [free VTAI registration](https://ai.virustotal.com/connect/mcp). Preparing this
file does not move or publish the active entry.

The manifest requests one secret VTAI token and constructs `Authorization: Bearer`
for the client. Use the host's protected credential settings; no token belongs in
the manifest, chat, source control or a shared installation URL. The alternative
`x-apikey` configuration remains documented in the [access guide](access.md).
Send only one authentication header. This is static token authentication, not OAuth.

The entry describes seven remote tools, including file submission and recovery.
The eighth tool, `submit_local_file`, requires the local stdio package. Registry
discovery does not establish support in every client, approval by a model provider,
or a connection to hosted ChatGPT/Claude. Consult the [client evidence](clients.md).

The registry manifest uses MCP server version **0.8.0**, matching the tool interface
and published package. Backend VTAI 0.8.1 supplies the Bearer alternative. A remote
entry needs no PyPI package; the verified [GitHub release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0)
remains the local installation channel.

### Maintaining the entry

The `MCP Registry` workflow is bound to the corporate repository ID and main
branch. After metadata validation and that exact main commit's CI pass, dispatch
the workflow with its full SHA in `reviewed_sha`.

The default `verify-identity` operation checks the GitHub Actions OIDC exchange
and the issued corporate namespace permission, then removes the temporary
credential. It can run while this repository is private and publishes nothing.
It inspects the claims received through the authenticated HTTPS exchange; it
does not independently verify the token's cryptographic signature locally.

The `publish` operation additionally requires a public repository. It uses the
publisher fixed by version and SHA-256, then reads the exact published version
anonymously and compares its manifest and active status. Neither operation needs
a permanent registry secret or a VTAI token. These capabilities do not establish
that the corporate entry has already been published.

The publisher does not overwrite an existing name/version. Check the exact entry
before retrying a failed run: publication may have succeeded before a later step
failed. A new name using the same endpoint also requires an explicit registry
cutover; changing this manifest alone does not retire the old name. Preserve
published release bytes and their source history. Registry metadata, package
publication and backend deployment remain separate operations.

See the official [remote server format](https://modelcontextprotocol.io/registry/remote-servers)
and [GitHub Actions publication guide](https://modelcontextprotocol.io/registry/github-actions).

## Glama

[`glama.json`](../glama.json) names the GitHub account `bernardoquintero` as the
maintainer for the prepared corporate source, using Glama's documented schema.
This identifies a user account, not an organization or an email address. No
corporate listing, ownership verification, crawler refresh or managed hosting is
claimed. Committing metadata does not establish any of those states.

Use the setup links above for the working connection. Do not put a VTAI token in
a shareable inspector or installation URL. Glama's listing status is distinct
from the availability of the live MCP endpoint.
