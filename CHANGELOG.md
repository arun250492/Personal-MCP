# Changelog

## 2.0.0 — 2026-11-19

### New: IsItMe? IT triage toolset
- `diagnose` — one-shot outage verdict (DNS, TLS, HTTP, hosting-provider detection + status page) with likely
  cause, next steps and a ticket-ready summary. Renders an interactive verdict card in MCP Apps hosts
  (ChatGPT, Claude).
- `check_dns`, `check_tls`, `check_http`, `check_email_auth`, `vendor_status`.
- `diagnose(compare_cloud=true)` compares your local view with the hosted cloud view.
- `personal-mcp --hosted`: public, read-only server exposing only the triage tools (SSRF protection, IP pinning,
  rate limiting, result cache, `/healthz`, OpenAI domain-verification route). Dockerfile, Render and Fly configs.
- ChatGPT plugin package (`chatgpt-plugin/`) with validator/packager, review test cases and listing assets.

### Fixed
- **Fresh installs crashed on startup**: dependency was `mcp>=1.2.0` with no upper bound, so pip installed MCP SDK
  2.x where `FastMCP` no longer exists. Ported to SDK 2.x (`MCPServer`) and pinned `mcp>=2.3,<3`.
- **`pip install personal-mcp-arun[all]` installed an unrelated third-party package** (`personal-mcp`) instead of
  this project's extras. Extras now reference `personal-mcp-arun[...]`.
- Command injection in `send_notification`, `set_reminder`, `text_to_speech` and the Windows screenshot fallback:
  text was interpolated into AppleScript/PowerShell. Now passed via argv, environment variables or stdin.
- `calculate` used `eval` (escapable); replaced with a safe AST evaluator.
- `open_application` on Windows passed the name through `cmd /c start` (shell injection); now `os.startfile`.
- `calendar_today` used the UTC date (missed early-morning events outside UTC); now uses local day boundaries.
- `calendar_create_event` sent a timezone abbreviation such as "IST" that Google rejects; now sends RFC 3339 with offset.
- `gmail_send` stripped of CR/LF in headers (header injection).
- `scan_ports` crashed on bad input; now validated (max 100 ports).
- `get_system_info` now reports the uptime it promised.
- LICENSE file contained the MCP project's license text; replaced with this project's MIT license.

### Changed
- Tools carry MCP annotations (read-only / destructive) so clients can ask before risky actions.
- `PERSONAL_MCP_SAFE_MODE=1` hides tools that run commands, delete/move/write files, kill processes, send e-mail or post.
- `--http` binds to 127.0.0.1 and warns if exposed further.
- Removed committed `mcp-publisher` binaries (27 MB) from the repository.
