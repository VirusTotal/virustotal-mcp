# Hosted ChatGPT and Claude connections

The tested client guides remain [Agy](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), then [Codex](clients.md#codex-cli--remote-http).
This page covers separate hosted connections. Host setup requirements were
checked on 2026-09-08; VTAI's OAuth status was updated on 2026-09-15. No hosted
account or end-to-end hosted connection has been validated.

VTAI's public endpoint is `https://ai.virustotal.com/mcp`. It supports MCP OAuth
and also accepts a static VTAI Agent Token through one credential header,
including `Authorization: Bearer`. The service exposes seven tools, with file
submission and receipt recovery. Protected-resource and authorization-server
metadata are live. A successful CLI session does not establish hosted-account
access or a validated hosted connection.

## Claude organization request-header beta

**Status: documented setup for eligible organizations; not tested in Claude.**
Anthropic restricts Request headers to selected organizations. If the field is
absent, this route is unavailable in that account. The organization deliberately
shares one VTAI identity, including its quotas and submission ownership; this
is suitable only when that shared access is intended. Individual identities
require the OAuth route below.

1. Obtain an organization-owned VTAI token using the [access guide](access.md).
   Keep a protected copy for revocation. Use neither another user's token nor a
   development/CI credential.
2. In the organization's custom-connector dialog, enter the endpoint above and
   choose **Authentication: None**. This selects the host's non-OAuth mode;
   VTAI still authenticates every request.
3. Under **Request headers**, add required **Authorization** with the complete
   value `Bearer ` followed by the token. Enter it only in that credential field.
   Do not add `x-apikey` or OAuth to this connection.
4. Enable the connector in a conversation and run the acceptance query below.
   If authentication settings need changing later, remove and recreate the
   connector; removing it alone does not revoke VTAI access.

These steps follow [Anthropic's request-header documentation](https://claude.com/docs/connectors/custom/remote-mcp#authenticating-with-request-headers).
Host permissions still govern tool execution. Configure them for the intended
operations; the server's submission tools do not add a per-call confirmation
argument. The host may request confirmation independently.

## ChatGPT public connection and individual OAuth

**Status: VTAI OAuth is live; hosted account and connection validation remain pending.**
ChatGPT's authenticated public MCP connection uses OAuth. A static VTAI token
cannot be entered as an OAuth client secret. Its authorization contract includes
PKCE S256, protected-resource and issuer discovery, and resource-bound access
tokens. CIMD or a pre-registered client can avoid dynamic client registration.
[OpenAI authentication](https://developers.openai.com/plugins/build/auth).

VTAI uses a maintained authorization provider and validates issuer, resource,
expiry, approved scopes and active grants before applying its access controls,
quotas and receipt ownership. The resource is `https://ai.virustotal.com/mcp`,
and the issuer is `https://ai.virustotal.com`. Clients can discover these through
[protected-resource metadata](https://ai.virustotal.com/.well-known/oauth-protected-resource/mcp)
and [authorization-server metadata](https://ai.virustotal.com/.well-known/oauth-authorization-server).
The advertised registration endpoint supports DCR. Client ID Metadata Documents
(CIMD) are not yet supported; a host requiring them needs a separate compatibility
update. Configure the MCP URL without static headers for an OAuth connection and
follow the host's sign-in and explicit consent flow. This infrastructure does not
by itself establish compatibility with a particular hosted account or client.

Claude also supports OAuth for individual accounts. Use the exact callback and
registration mode documented for the chosen host; a client secret and DCR are
not universal requirements. [Claude authentication](https://claude.com/docs/connectors/building/authentication).

For private ChatGPT testing, OpenAI also offers Secure MCP Tunnel with stdio or
HTTP. It requires Platform tunnel permissions, a runtime API credential and the
correct ChatGPT workspace association. It does not replace the authenticated
public endpoint required for plugin distribution. No tunnel is provisioned or
validated by this project. [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

## First hosted acceptance query

For an initial read-only check, enable only `get_domain_report` in the host's
tool permissions where available. In a new conversation, ask:

> Use VirusTotal to get the domain report for example.com. Explain the source,
> analysis date and coverage. Do not submit a file or start an analysis.

Accept the connection only after observing the actual tool call and its result,
not just a Connected label or an assistant's prose. Record the host/account
mode, discovered tools, call name, domain, outcome, report link, source,
analysis date, retrieval time and coverage. Exclude the credential and private
conversation content from evidence. The current remote tool list has seven
entries; the local-file tool is available only through stdio.

A missing report remains unknown; errors and incomplete coverage are not safety
verdicts. A passing query does not validate file submission, refresh, revocation,
other tools or publication in a host's directory. Test those as separate flows.
For temporary testing, remove the connector and revoke its access: use
[Your connections](https://ai.virustotal.com/oauth/connections) for OAuth, or the
[access guide](access.md#revoke-access) for a static Agent Token.

For OAuth acceptance, verify receipt isolation between identities, rejection of
expired or revoked access, and refresh preserving the same VTAI identity. A
submission test must use intentionally public inert bytes and recover its
original receipt without repeating an ambiguous upload.
