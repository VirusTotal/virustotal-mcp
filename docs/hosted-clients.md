# Hosted ChatGPT and Claude connections

The tested client guides remain [Agy](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), then [Codex](clients.md#codex-cli--remote-http).
This page covers separate hosted connections. Requirements were checked on
2026-09-08; no hosted account or end-to-end connection has been validated.

VTAI's public endpoint is `https://ai.virustotal.com/mcp`. It accepts a VTAI
Agent Token through one credential header, including `Authorization: Bearer`.
The service exposes seven tools, with file submission and receipt recovery.
It currently provides no OAuth authorization server or protected-resource
metadata. A successful CLI session does not establish hosted-account access.

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

**Status: requires a maintained authorization provider and account validation.**
ChatGPT's authenticated public MCP connection uses OAuth. A static VTAI token
cannot be entered as an OAuth client secret. Its authorization contract includes
PKCE S256, protected-resource and issuer discovery, and resource-bound access
tokens. CIMD or a pre-registered client can avoid dynamic client registration.
[OpenAI authentication](https://developers.openai.com/plugins/build/auth).

The implementation path is to connect a maintained corporate authorization
provider to VTAI. VTAI must verify issuer, audience, expiry and scopes, then
resolve the user to its existing access controls, quotas and owned receipts.
The proposed resource identifier is `https://ai.virustotal.com/mcp`. An issuer
URL and client-registration settings must come from a real configured provider;
this guide does not announce an issuer or a working login endpoint.

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
For temporary testing, remove the connector and revoke its dedicated token as
specified in the [access guide](access.md#revoke-access).

After OAuth is implemented, additionally verify two identities cannot read each
other's receipts, expired or revoked access is rejected, and refresh preserves
the same VTAI identity. A submission test must use intentionally public inert
bytes and recover its original receipt without repeating an ambiguous upload.
