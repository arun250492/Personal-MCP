# Personal MCP

<!-- mcp-name: io.github.arun250492/personal-mcp -->

Your AI-powered personal desktop assistant — an MCP server with **30+ tools** for managing your local machine, email, calendar, files, clipboard, browser, apps, and social media.

## Install

```bash
# Core (system, files, browser, shell)
pip install personal-mcp

# With Gmail + Calendar
pip install "personal-mcp[google]"

# With desktop tools (clipboard, screenshots, process manager)
pip install "personal-mcp[desktop]"

# Everything
pip install "personal-mcp[all]"
```

## Connect

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "personal": {
      "command": "personal-mcp",
      "args": []
    }
  }
}
```

### VS Code (Copilot / Cline)

Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "personal": {
      "command": "personal-mcp",
      "args": []
    }
  }
}
```

## Tools (30+)

### System & Network
| Tool | Description |
|------|-------------|
| `get_system_info` | OS, CPU, RAM, hostname, user |
| `get_ip_addresses` | Local + public IP |
| `get_disk_usage` | Disk space for any path |
| `scan_ports` | Check open ports on a host |
| `run_command` | Run shell commands |
| `get_datetime` | Current date, time, timezone |
| `calculate` | Safe math expression evaluator |

### File Management
| Tool | Description |
|------|-------------|
| `list_directory` | List files/folders |
| `read_file` | Read text file contents |
| `write_file` | Write/create text files |
| `search_files` | Recursive glob search |
| `move_file` | Move or rename files |
| `delete_file` | Delete (trash if available) |
| `get_file_info` | Size, dates, permissions |

### Clipboard & Screenshots
| Tool | Description |
|------|-------------|
| `clipboard_read` | Read clipboard text |
| `clipboard_write` | Write text to clipboard |
| `take_screenshot` | Capture screen to file |

### Browser & Web
| Tool | Description |
|------|-------------|
| `open_url` | Open URL in default browser |
| `web_search` | Google search in browser |
| `fetch_url` | Fetch URL content (for APIs) |

### App Launcher & Processes
| Tool | Description |
|------|-------------|
| `open_application` | Launch any desktop app |
| `list_processes` | List/filter running processes |
| `kill_process` | Kill a process by PID |

### Gmail (requires `[google]`)
| Tool | Description |
|------|-------------|
| `gmail_inbox` | List/search emails |
| `gmail_read` | Read full email content |
| `gmail_send` | Send an email |

### Google Calendar (requires `[google]`)
| Tool | Description |
|------|-------------|
| `calendar_today` | Today's events |
| `calendar_upcoming` | Next N days of events |
| `calendar_create_event` | Create a calendar event |

### Notifications
| Tool | Description |
|------|-------------|
| `send_notification` | Desktop notification |
| `set_reminder` | Reminder after N minutes |
| `text_to_speech` | Speak text aloud |

### Social Media (requires `[social]`)
| Tool | Description |
|------|-------------|
| `twitter_post` | Post a tweet to X/Twitter |

## Gmail & Calendar Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a project → Enable **Gmail API** and **Google Calendar API**
3. Credentials → Create → OAuth client ID → Desktop app
4. Download JSON → save to `~/.personal-mcp/gmail_credentials.json`
5. First tool call opens browser for OAuth consent

## Twitter/X Setup

Set these environment variables:

```bash
export TWITTER_API_KEY=your_key
export TWITTER_API_SECRET=your_secret
export TWITTER_ACCESS_TOKEN=your_token
export TWITTER_ACCESS_SECRET=your_token_secret
```

## Example Prompts

- "What's my IP address and system info?"
- "Show me the files on my Desktop"
- "Find all PDFs in my Downloads folder"
- "What's on my calendar today?"
- "Send an email to alice@example.com about tomorrow's meeting"
- "Open VS Code"
- "Take a screenshot and save it"
- "Set a reminder in 30 minutes to check the oven"
- "What processes are using the most CPU?"
- "Read whatever is in my clipboard"

## Publishing to MCP Registry

This project includes everything needed to publish to the official MCP Registry:

### 1. Prepare

Replace `arun250492` in these files with your GitHub username:
- `pyproject.toml` → URLs + `mcpName`
- `.mcp/server.json` → `name` and `repository.url`
- `README.md` → the `mcp-name` HTML comment

### 2. Publish to PyPI

```bash
pip install build twine
python -m build
twine upload dist/*
```

### 3. Publish to MCP Registry (manual)

```bash
# Install the CLI
curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz mcp-publisher
sudo mv mcp-publisher /usr/local/bin/

# Login with GitHub
mcp-publisher login

# Publish
mcp-publisher publish .mcp/server.json
```

### 4. Auto-publish (CI/CD)

The included `.github/workflows/publish.yml` auto-publishes to both PyPI and MCP Registry on every git tag:

```bash
git tag v1.0.0
git push origin v1.0.0
# → GitHub Actions publishes to PyPI → then to MCP Registry
```

## License

MIT
