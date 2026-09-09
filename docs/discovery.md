# Find and connect to VirusTotal MCP

The corporate source is being prepared at
[VirusTotal/virustotal-mcp](https://github.com/VirusTotal/virustotal-mcp), currently
a private repository. It is a new repository with the existing public source
history copied into it, not a transfer of the original repository ID. The
[public source](https://github.com/king-tero/vt-mcp) and its
[v0.8.0 release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0) remain the
public distribution until the corporate cutover. Corporate version 0.8.2 uses
Apache-2.0, while the existing 0.8.0 release retains MIT. The corporate repository
remains private, and its registry entry has not been published.

Start with the setup for [Antigravity CLI (`agy`)](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), or [Codex](clients.md#codex-cli--remote-http).

## MCP Registry

The active entry is still
[`io.github.king-tero/vt-mcp` version 0.8.0](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.king-tero%2Fvt-mcp/versions/0.8.0).
[`server.json`](../server.json) prepares the corporate name
`io.github.VirusTotal/virustotal-mcp` version 0.8.2. The remote-only manifest omits `repository` while the corporate
source remains private; its publication workflow is bound to GitHub repository
ID `1361592455`.
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

The corporate manifest identifies distribution **0.8.2**. This licensing and
packaging revision preserves the tool interface introduced in 0.8.0 and does not
deploy a new hosted server. Backend VTAI 0.8.1 supplies the Bearer alternative. A
remote entry needs no PyPI package; the verified public
[0.8.0 GitHub release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0)
remains the public local-installation channel during the transition.

### Maintaining the entry

The `MCP Registry` workflow is bound to the corporate repository ID and main
branch. After metadata validation and that exact main commit's CI pass, dispatch
the workflow with its full SHA in `reviewed_sha`.

The default `verify-identity` operation checks the GitHub Actions OIDC exchange
and the issued corporate namespace permission, then removes the temporary
credential. It can run while this repository is private and publishes nothing.
It inspects the claims received through the authenticated HTTPS exchange; it
does not independently verify the token's cryptographic signature locally.

The `publish` operation accepts this private repository's remote-only manifest:
no package or private source URL is advertised. It uses the publisher fixed by
version and SHA-256, then reads the exact published version anonymously and
compares its manifest and active status. No permanent Registry secret or VTAI
token is needed. The default identity check does not publish an entry.

The `retire` and `restore` operations change only the reviewed version's status.
Retirement marks it deleted and preserves its manifest and migration message in
the Registry's `include_deleted=true` view. Restoration reactivates the same
version and clears that message; it does not republish or rebuild a package.
These operations check both namespaces for unexpected versions and metadata.
The temporary local publisher credential is removed when the operation finishes.

The publisher does not overwrite an existing name/version. Check the exact entry
before retrying a failed run: publication may have succeeded before a later step
failed. A new name using the same endpoint also requires an explicit registry
cutover; changing this manifest alone does not retire the old name. Verify both
owner identities first, retire the personal entry from its own repository, then
publish the corporate entry here. The shared URL is freed only by deletion;
deprecation does not free it. Catalogue replacement is not atomic; the MCP
endpoint continues serving existing clients during the transition.

If an operation fails or times out, read both exact entries with
`include_deleted=true` before taking another action. An exact active corporate
entry establishes publication despite a lost response. To recover the personal
entry, retire any corporate entry occupying the URL first, then run `restore`
from the personal repository. The workflow never changes all versions or retries
a mutation automatically. Preserve published release bytes and their source
history. Registry metadata, package publication and backend deployment remain
separate operations.

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

## Distribution preparation

The [PyPI publishing guide](publishing.md) describes verification of existing
release assets and the separate Trusted Publisher setup. No PyPI publication is
established by this preparation. The [hosted-client guide](hosted-clients.md)
records account and authentication requirements without claiming a validated
ChatGPT or Claude hosted connection.
