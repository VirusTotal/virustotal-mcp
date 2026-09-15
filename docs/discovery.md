# Find and connect to VirusTotal MCP

Connect to the hosted endpoint or install
[`vt-mcp` 0.8.3 from PyPI](https://pypi.org/project/vt-mcp/0.8.3/) for local stdio.
The PyPI wheel and source distribution use Apache-2.0. The corporate repository,
[VirusTotal/virustotal-mcp](https://github.com/VirusTotal/virustotal-mcp), remains
private; installation from PyPI does not require GitHub access. The historical
[0.8.0 GitHub release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0)
retains its original MIT license and files.

Start with the setup for [Antigravity CLI (`agy`)](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), or [Codex](clients.md#codex-cli--remote-http).

## MCP Registry

Select
[`io.github.VirusTotal/virustotal-mcp` version 0.8.4](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.VirusTotal%2Fvirustotal-mcp/versions/0.8.4)
in a Registry catalogue. [`server.json`](../server.json) describes both the hosted
Streamable HTTP endpoint and the version-pinned PyPI stdio package. It omits
`repository` while the corporate source remains private. GitHub Actions OIDC
establishes the corporate namespace, and the workflow is bound to repository ID
`1361592455`. The package README carries the matching `mcp-name` ownership marker.

The hosted option connects to `https://ai.virustotal.com/mcp`. In a client that
supports MCP OAuth, add this URL and follow its browser sign-in and consent flow;
you do not need to create or paste a static token first. The descriptor leaves
headers unset so the client can discover authorization from the endpoint's
`WWW-Authenticate` challenge. The endpoint still requires authentication.

Corporate versions
[0.8.2](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.VirusTotal%2Fvirustotal-mcp/versions/0.8.2) and
[0.8.3](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.VirusTotal%2Fvirustotal-mcp/versions/0.8.3)
keep their original manifests and active status. The previous
[`io.github.king-tero/vt-mcp` 0.8.0 entry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.king-tero%2Fvt-mcp/versions/0.8.0?include_deleted=true)
is retired with a message pointing to the corporate name. Its original manifest
remains readable with `include_deleted=true`. Select the corporate name in a
Registry catalogue; existing endpoint-based configurations keep the same URL
and credential settings.

For unattended setup or clients using configurable headers, static Agent Tokens
remain supported. Obtain one through
[free VTAI registration](https://ai.virustotal.com/connect/mcp) and configure
`Authorization: Bearer <your-agent-token>` in the host's protected credential
settings. The alternative `x-apikey` configuration remains documented in the
[access guide](access.md). Send only one authentication header and do not combine
static headers with the client's OAuth connection. No token belongs in the
manifest, chat, source control or a shared installation URL. Static tokens also
remain the credential for the local stdio package and direct REST API access;
MCP OAuth tokens are not REST API keys.

The stdio configuration uses `uvx --python 3.12` with `vt-mcp==0.8.3`, so uv
selects a supported interpreter. Set `VTAI_TOKEN_FILE` to the path of a protected file containing only your
VTAI token, for example `/home/user/.config/vt-mcp/token`. The Registry input is
the file path; the credential stays in that file. Obtain it through the access
page above and restrict file access to your user. Clients that do not import
Registry configuration can use the [manual setup](clients.md).

There are seven remote tools, including file submission and recovery. The eighth
tool, `submit_local_file`, requires the local stdio package. Registry
discovery does not establish support in every client, approval by a model provider,
or a connection to hosted ChatGPT/Claude. Consult the [client evidence](clients.md).

Registry metadata **0.8.4** describes the OAuth-capable hosted endpoint and adds
the existing VirusTotal icon. Its stdio package remains **vt-mcp 0.8.3**: this
metadata update does not publish a new Python package or deploy a hosted server.
Connecting by HTTP requires no local package installation.

### Maintaining the entry

The `MCP Registry` workflow is bound to the corporate repository ID and main
branch. After metadata validation and that exact main commit's CI pass, dispatch
the workflow with its full SHA in `reviewed_sha`.

The default `verify-identity` operation checks the GitHub Actions OIDC exchange
and the issued corporate namespace permission, then removes the temporary
credential. It can run while this repository is private and publishes nothing.
It inspects the claims received through the authenticated HTTPS exchange; it
does not independently verify the token's cryptographic signature locally.

Run `publish` with the reviewed metadata commit on main. The package release is
pinned independently: metadata 0.8.4 reuses the already-published vt-mcp 0.8.3.
Before requesting OIDC, the helper checks PyPI's name, version and README ownership
marker, and requires exactly the wheel and source distribution, neither yanked.
Their SHA-256 hashes must match the corporate release's `SHA256SUMS` and GitHub
asset digests. The annotated `v0.8.3` tag object, package source commit and checksum
manifest are pinned in the helper; the metadata commit cannot substitute for the
package release. This verifies published bytes without rebuilding or uploading
PyPI files. A moved tag, changed release, partial upload or mismatched source
blocks Registry publication.

The helper then uses the publisher fixed by version and SHA-256, reads the exact
published version anonymously and compares its manifest and active status. No
permanent Registry secret or VTAI token is needed. CI validates the manifest's
schema and semantics without requiring an already-published PyPI package. The
default identity check does not publish an entry or depend on PyPI availability.

The `retire` and `restore` operations change only corporate version 0.8.4's status.
Retirement marks it deleted and preserves its manifest and migration message in
the Registry's `include_deleted=true` view. Restoration reactivates the same
version and clears that message; it does not republish or rebuild a package.
Restoration also requires the matching PyPI release; retirement does not depend
on PyPI availability. These operations check both namespaces for unexpected
versions and metadata. They allow only corporate 0.8.2/0.8.3/0.8.4 and personal
0.8.0, pin the previous manifests, and preserve corporate 0.8.2/0.8.3 as active
and personal 0.8.0 as deleted with its migration message. Only 0.8.4 is changed.
The Registry may update its computed latest-version flag on the older entry.
The temporary local publisher credential is removed when the operation finishes.

The publisher does not overwrite an existing name/version. Check the exact entry
before retrying a failed run: publication may have succeeded before a later step
failed. Older active versions under the same corporate name are preserved.
Retiring 0.8.4 therefore does not free the endpoint for a different Registry name:
corporate 0.8.2 and 0.8.3 still occupy it. A new identity cutover requires a separately
reviewed operation; this workflow never retires historical versions automatically.

If an operation fails or times out, read all four exact entries with
`include_deleted=true` before taking another action. An exact active corporate
entry establishes publication despite a lost response. Recovering the personal
entry requires a separate cutover while corporate versions occupy the URL. The
workflow never changes all versions or retries a mutation automatically. Preserve
published release bytes and their source history. Registry metadata, package
publication and backend deployment remain separate operations.

See the official [remote server format](https://modelcontextprotocol.io/registry/remote-servers)
and [PyPI package format and ownership rules](https://modelcontextprotocol.io/registry/package-types#pypi-packages),
plus [Registry versioning](https://modelcontextprotocol.io/registry/versioning)
and the [GitHub Actions publication guide](https://modelcontextprotocol.io/registry/github-actions).

## Glama

[`glama.json`](../glama.json) names the GitHub account `bernardoquintero` as the
maintainer for the prepared corporate source, using Glama's documented schema.
This identifies a user account, not an organization or an email address. No
corporate listing, ownership verification, crawler refresh or managed hosting is
claimed. Committing metadata does not establish any of those states.

Use the setup links above for the working connection. Do not put a VTAI token in
a shareable inspector or installation URL. Glama's listing status is distinct
from the availability of the live MCP endpoint.

## Distribution maintenance

The [PyPI publishing guide](publishing.md) describes verification of existing
release assets and the separate Trusted Publisher setup. The [hosted-client guide](hosted-clients.md)
records account and authentication requirements without claiming a validated
ChatGPT or Claude hosted connection.
