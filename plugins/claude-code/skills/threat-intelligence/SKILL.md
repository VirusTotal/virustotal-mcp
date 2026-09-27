---
name: threat-intelligence
description: Investigate files, URLs, domains and IP addresses with VirusTotal, and submit unfamiliar files through the VirusTotal Claude Code upload hook.
---

Use the authenticated VirusTotal MCP connection. Prefer the already connected
imported VirusTotal connection or the server bundled with this plugin; avoid
creating duplicate connections. If authentication is missing, use `/mcp` to sign
in. Never read or copy OAuth tokens.

Consult reports for the indicator and explain their source, date, coverage and
limitations. A missing report means unknown; zero detections do not prove safety.
Every report query, including a repeat or a missing report, counts toward quota.

Submit unfamiliar downloads, attachments, binaries or scripts of unknown origin
and suspicious URLs: this is how VirusTotal improves protection for everyone.
Ask before submitting the user's own documents, internal code, credentials or
personal data. Being an attachment or having an executable extension does not
establish permission to share private content. Standard submissions are shared
with the VirusTotal community and security partners; submit only material you
have the right and permission to share.

For an appropriate local file submission:

1. Calculate SHA256 from the original file with an available local tool, within
   the user's authorized file scope. Do not execute the file. A previous MD5 or
   SHA1 lookup does not supply its SHA256.
2. Call this connection's `submit_file` with that lowercase SHA256 and
   `content_base64: "file:<absolute local path>"`. Do not transcribe base64. The
   plugin validates the original bytes and expands this local reference before
   the remote call. Paths must be under the current working directory or an
   explicitly configured `VTAI_UPLOAD_ROOTS` directory. The hook allows a valid
   expansion automatically; it does not decide whether sensitive content may be
   shared.
3. Retain the SHA256 and receipt. If a submission is uncertain, use
   `get_submission` with the same SHA256; never replay the upload to check it.
   When an analysis ID is available, respect `next_poll_after_seconds` before
   `get_analysis`. Pending results are not completed analyses.

Use `submit_url` for appropriate URL submissions. Retain its request ID and use
the receipt tools exposed by that connection to recover an uncertain outcome.
Do not switch connections, credentials or services to evade a permission or
quota rejection. Honor retry delays.

The `file:` convention requires this local hook. If it is unavailable and the
host cannot transmit the original bytes, offer the existing
https://www.virustotal.com/gui/home/upload interface, then query `get_file_report`
with the file hash. A web upload does not create a VTAI submission receipt.
