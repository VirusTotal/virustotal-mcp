# VirusTotal threat-intelligence skill

Portable instructions for an already connected VirusTotal MCP app. The skill
contains no scripts, credentials or server configuration. It does not install
or authenticate the connection and does not grant submission permissions.

For Gemini Apps, [connect the custom app and import the skill](../../docs/google-clients.md#gemini-apps-skill).
Download the plain-text [SKILL.md](https://raw.githubusercontent.com/VirusTotal/virustotal-mcp/main/skills/virustotal-threat-intelligence/SKILL.md)
and use **Settings → Skills → Upload**. A ZIP containing only `SKILL.md` at its
root is also accepted: use the reviewed [skill ZIP and checksum](https://github.com/VirusTotal/virustotal-mcp/releases/tag/gemini-skill-v0.1.0).
The repository's full source ZIP is not a skill archive.
Review the instructions before importing. Eligibility and hosted validation
limits are recorded in the guide.

The [Gemini CLI extension](../../docs/google-clients.md#gemini-cli-extension)
bundles this directory. Other skill-compatible hosts can reuse `SKILL.md` with
their connected MCP tools; format compatibility does not prove a tested workflow
in every host. Existing Antigravity installations retain their plugin's own skill.

Example after connection:

> Use VirusTotal to retrieve the existing report for example.com. Explain the
> source, analysis date, coverage and limitations. Do not request a new analysis.

Deleting or deactivating a skill does not revoke the MCP connection. Update or
replace imports explicitly after reviewing new instructions.
