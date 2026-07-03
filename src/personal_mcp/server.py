"""
Personal MCP Server — Your AI-powered local assistant.

Tools for:
  1. System & Network — IP, system info, disk, open ports, shell commands
  2. File Management — search, read, write, move, organize files
  3. Clipboard & Screenshots — copy/paste, capture screen
  4. Browser — open URLs, search the web
  5. App Launcher — open any app, manage processes
  6. Gmail — read, search, send emails
  7. Google Calendar — list, create, search events
  8. Notifications — desktop notifications, reminders
  9. Social Media — post to Twitter/X (via API)

Install:  pip install personal-mcp
Run:      personal-mcp                  (stdio, for Claude Desktop / Claude Code)
          personal-mcp --http           (streamable HTTP, for remote clients)
"""

import base64
import datetime
import json
import logging
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import sys
import time
import webbrowser

from mcp.server.fastmcp import FastMCP

# ─── Server ────────────────────────────────────────────────────────
mcp = FastMCP("Personal MCP")
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("personal-mcp")

HOME = str(pathlib.Path.home())
IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

# ═══════════════════════════════════════════════════════════════════
# 1. SYSTEM & NETWORK
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def get_system_info() -> dict:
    """Get OS, hostname, CPU, RAM, Python version, current user, and uptime."""
    info = {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "N/A",
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "home_dir": HOME,
        "cwd": os.getcwd(),
        "timestamp": datetime.datetime.now().isoformat(),
    }
    # RAM (cross-platform)
    try:
        import psutil
        mem = psutil.virtual_memory()
        info["ram_total_gb"] = round(mem.total / (1024**3), 1)
        info["ram_used_gb"] = round(mem.used / (1024**3), 1)
        info["ram_percent"] = mem.percent
    except ImportError:
        pass
    return info


@mcp.tool()
def get_ip_addresses() -> dict:
    """Get local and public IP addresses."""
    import httpx

    result = {"local_ips": [], "public_ip": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        result["local_ips"].append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        result["public_ip"] = httpx.get("https://api.ipify.org?format=json", timeout=5).json().get("ip")
    except Exception as e:
        result["public_ip_error"] = str(e)
    return result


@mcp.tool()
def get_disk_usage(path: str = "/") -> dict:
    """Get disk space for a given path (default: root)."""
    u = shutil.disk_usage(path)
    return {
        "path": path,
        "total_gb": round(u.total / (1024**3), 2),
        "used_gb": round(u.used / (1024**3), 2),
        "free_gb": round(u.free / (1024**3), 2),
        "percent_used": round(u.used / u.total * 100, 1),
    }


@mcp.tool()
def scan_ports(host: str = "127.0.0.1", ports: str = "22,80,443,3000,5432,8080,8000") -> list[dict]:
    """Scan common ports on a host. Pass comma-separated port numbers."""
    results = []
    for p in [int(x.strip()) for x in ports.split(",")]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            open_ = s.connect_ex((host, p)) == 0
            s.close()
            if open_:
                results.append({"port": p, "status": "open"})
        except Exception:
            pass
    return results


@mcp.tool()
def run_command(command: str) -> dict:
    """Run a shell command and return stdout/stderr. Use responsibly."""
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30,
            cwd=HOME,
        )
        return {"stdout": proc.stdout[:5000], "stderr": proc.stderr[:2000], "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out (30s limit)"}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# 2. FILE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def list_directory(path: str = "~", show_hidden: bool = False) -> list[dict]:
    """List files and folders in a directory."""
    p = pathlib.Path(path).expanduser()
    items = []
    for entry in sorted(p.iterdir()):
        if not show_hidden and entry.name.startswith("."):
            continue
        items.append({
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "size_bytes": entry.stat().st_size if entry.is_file() else None,
            "modified": datetime.datetime.fromtimestamp(entry.stat().st_mtime).isoformat(),
        })
    return items[:100]  # cap at 100 entries


@mcp.tool()
def read_file(path: str, max_chars: int = 10000) -> dict:
    """Read text file contents. Truncates at max_chars."""
    p = pathlib.Path(path).expanduser()
    if not p.exists():
        return {"error": f"File not found: {path}"}
    if not p.is_file():
        return {"error": f"Not a file: {path}"}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        return {"path": str(p), "content": text[:max_chars], "truncated": len(text) > max_chars, "size": len(text)}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def write_file(path: str, content: str, create_dirs: bool = True) -> dict:
    """Write content to a text file. Creates parent directories if needed."""
    p = pathlib.Path(path).expanduser()
    try:
        if create_dirs:
            p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return {"success": True, "path": str(p), "bytes_written": len(content.encode("utf-8"))}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def search_files(directory: str = "~", pattern: str = "*", max_results: int = 20) -> list[str]:
    """Search for files matching a glob pattern recursively."""
    p = pathlib.Path(directory).expanduser()
    results = []
    for match in p.rglob(pattern):
        results.append(str(match))
        if len(results) >= max_results:
            break
    return results


@mcp.tool()
def move_file(source: str, destination: str) -> dict:
    """Move or rename a file/directory."""
    try:
        src = pathlib.Path(source).expanduser()
        dst = pathlib.Path(destination).expanduser()
        shutil.move(str(src), str(dst))
        return {"success": True, "from": str(src), "to": str(dst)}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def delete_file(path: str) -> dict:
    """Delete a file (moves to trash if available, otherwise permanent delete)."""
    p = pathlib.Path(path).expanduser()
    if not p.exists():
        return {"error": f"Not found: {path}"}
    try:
        try:
            from send2trash import send2trash
            send2trash(str(p))
            return {"success": True, "method": "trash", "path": str(p)}
        except ImportError:
            if p.is_file():
                p.unlink()
            else:
                shutil.rmtree(str(p))
            return {"success": True, "method": "permanent", "path": str(p)}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def get_file_info(path: str) -> dict:
    """Get detailed file metadata (size, dates, permissions)."""
    p = pathlib.Path(path).expanduser()
    if not p.exists():
        return {"error": f"Not found: {path}"}
    stat = p.stat()
    return {
        "path": str(p),
        "name": p.name,
        "extension": p.suffix,
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
        "size_bytes": stat.st_size,
        "size_human": _human_size(stat.st_size),
        "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "permissions": oct(stat.st_mode)[-3:],
    }


def _human_size(b):
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"


# ═══════════════════════════════════════════════════════════════════
# 3. CLIPBOARD & SCREENSHOTS
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def clipboard_read() -> dict:
    """Read current clipboard text content."""
    try:
        import pyperclip
        return {"content": pyperclip.paste()}
    except ImportError:
        # Fallback: platform-specific
        try:
            if IS_MAC:
                result = subprocess.run(["pbpaste"], capture_output=True, text=True)
            elif IS_WIN:
                result = subprocess.run(["powershell", "-command", "Get-Clipboard"], capture_output=True, text=True)
            else:
                result = subprocess.run(["xclip", "-selection", "clipboard", "-o"], capture_output=True, text=True)
            return {"content": result.stdout}
        except Exception as e:
            return {"error": f"Install pyperclip: pip install pyperclip. ({e})"}


@mcp.tool()
def clipboard_write(text: str) -> dict:
    """Write text to the clipboard."""
    try:
        import pyperclip
        pyperclip.copy(text)
        return {"success": True, "chars": len(text)}
    except ImportError:
        try:
            if IS_MAC:
                subprocess.run(["pbcopy"], input=text.encode(), check=True)
            elif IS_WIN:
                subprocess.run(["clip"], input=text.encode(), check=True)
            else:
                subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)
            return {"success": True, "chars": len(text)}
        except Exception as e:
            return {"error": str(e)}


@mcp.tool()
def take_screenshot(save_path: str = "~/screenshot.png") -> dict:
    """Capture a screenshot and save it."""
    p = pathlib.Path(save_path).expanduser()
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        img.save(str(p))
        return {"success": True, "path": str(p), "size": f"{img.width}x{img.height}"}
    except ImportError:
        # Fallback
        try:
            if IS_MAC:
                subprocess.run(["screencapture", str(p)], check=True)
            elif IS_WIN:
                subprocess.run(["powershell", "-command",
                    f"Add-Type -AssemblyName System.Windows.Forms; "
                    f"[System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object {{ "
                    f"$b = New-Object Drawing.Bitmap($_.Bounds.Width,$_.Bounds.Height); "
                    f"[Drawing.Graphics]::FromImage($b).CopyFromScreen($_.Bounds.Location,[Drawing.Point]::Empty,$_.Bounds.Size); "
                    f"$b.Save('{p}') }}"], check=True)
            else:
                subprocess.run(["gnome-screenshot", "-f", str(p)], check=True)
            return {"success": True, "path": str(p)}
        except Exception as e:
            return {"error": f"Install Pillow: pip install Pillow. ({e})"}


# ═══════════════════════════════════════════════════════════════════
# 4. BROWSER & WEB
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def open_url(url: str) -> dict:
    """Open a URL in the default browser."""
    webbrowser.open(url)
    return {"success": True, "url": url}


@mcp.tool()
def web_search(query: str) -> dict:
    """Open a Google search in the default browser."""
    import urllib.parse
    url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
    webbrowser.open(url)
    return {"success": True, "query": query, "url": url}


@mcp.tool()
def fetch_url(url: str, max_chars: int = 5000) -> dict:
    """Fetch a URL and return the text content (useful for APIs)."""
    import httpx
    try:
        resp = httpx.get(url, timeout=10, follow_redirects=True)
        return {"status": resp.status_code, "content": resp.text[:max_chars], "truncated": len(resp.text) > max_chars}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# 5. APP LAUNCHER & PROCESSES
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def open_application(app_name: str) -> dict:
    """Open a desktop application by name."""
    try:
        if IS_MAC:
            subprocess.Popen(["open", "-a", app_name])
        elif IS_WIN:
            subprocess.Popen(["start", app_name], shell=True)
        else:
            subprocess.Popen([app_name])
        return {"success": True, "app": app_name}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def list_processes(filter_name: str = "") -> list[dict]:
    """List running processes. Optionally filter by name."""
    try:
        import psutil
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            info = p.info
            if filter_name and filter_name.lower() not in info["name"].lower():
                continue
            procs.append(info)
        procs.sort(key=lambda x: x.get("cpu_percent", 0) or 0, reverse=True)
        return procs[:30]
    except ImportError:
        return [{"error": "Install psutil: pip install psutil"}]


@mcp.tool()
def kill_process(pid: int) -> dict:
    """Kill a process by PID."""
    try:
        import psutil
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        return {"success": True, "killed": name, "pid": pid}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# 6. GMAIL
# ═══════════════════════════════════════════════════════════════════

_gmail_service = None
GMAIL_CREDS = os.environ.get("GMAIL_CREDENTIALS_PATH", os.path.join(HOME, ".personal-mcp", "gmail_credentials.json"))
GMAIL_TOKEN = os.environ.get("GMAIL_TOKEN_PATH", os.path.join(HOME, ".personal-mcp", "gmail_token.json"))


def _gmail():
    global _gmail_service
    if _gmail_service:
        return _gmail_service
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError:
        raise RuntimeError("pip install google-auth google-auth-oauthlib google-api-python-client")

    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.send"]
    creds = None
    if os.path.exists(GMAIL_TOKEN):
        creds = Credentials.from_authorized_user_file(GMAIL_TOKEN, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(GMAIL_CREDS):
                raise FileNotFoundError(f"Gmail credentials not found at {GMAIL_CREDS}")
            flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDS, SCOPES)
            creds = flow.run_local_server(port=0)
        os.makedirs(os.path.dirname(GMAIL_TOKEN), exist_ok=True)
        with open(GMAIL_TOKEN, "w") as f:
            f.write(creds.to_json())
    _gmail_service = build("gmail", "v1", credentials=creds)
    return _gmail_service


@mcp.tool()
def gmail_inbox(max_results: int = 10, query: str = "is:inbox") -> dict:
    """List recent Gmail messages. Supports Gmail search syntax."""
    try:
        svc = _gmail()
        msgs = svc.users().messages().list(userId="me", maxResults=max_results, q=query).execute().get("messages", [])
        results = []
        for m in msgs:
            msg = svc.users().messages().get(userId="me", id=m["id"], format="metadata",
                metadataHeaders=["From", "To", "Subject", "Date"]).execute()
            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            results.append({
                "id": msg["id"], "from": headers.get("From", ""), "subject": headers.get("Subject", ""),
                "date": headers.get("Date", ""), "snippet": msg.get("snippet", "")[:150],
            })
        return {"messages": results, "count": len(results)}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def gmail_read(message_id: str) -> dict:
    """Read full email content by message ID."""
    try:
        svc = _gmail()
        msg = svc.users().messages().get(userId="me", id=message_id, format="full").execute()
        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        body = _extract_body(msg.get("payload", {}))
        return {"id": msg["id"], "from": headers.get("From"), "to": headers.get("To"),
                "subject": headers.get("Subject"), "date": headers.get("Date"), "body": body[:5000]}
    except Exception as e:
        return {"error": str(e)}


def _extract_body(payload):
    if payload.get("mimeType") == "text/plain" and payload.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="replace")
    for part in payload.get("parts", []):
        r = _extract_body(part)
        if r:
            return r
    if payload.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="replace")
    return ""


@mcp.tool()
def gmail_send(to: str, subject: str, body: str) -> dict:
    """Send an email via Gmail."""
    from email.mime.text import MIMEText
    try:
        svc = _gmail()
        msg = MIMEText(body)
        msg["to"] = to
        msg["subject"] = subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        sent = svc.users().messages().send(userId="me", body={"raw": raw}).execute()
        return {"success": True, "message_id": sent["id"]}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# 7. GOOGLE CALENDAR
# ═══════════════════════════════════════════════════════════════════

_calendar_service = None
GCAL_CREDS = os.environ.get("GCAL_CREDENTIALS_PATH", GMAIL_CREDS)  # reuse Gmail OAuth
GCAL_TOKEN = os.environ.get("GCAL_TOKEN_PATH", os.path.join(HOME, ".personal-mcp", "gcal_token.json"))


def _gcal():
    global _calendar_service
    if _calendar_service:
        return _calendar_service
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError:
        raise RuntimeError("pip install google-auth google-auth-oauthlib google-api-python-client")

    SCOPES = ["https://www.googleapis.com/auth/calendar"]
    creds = None
    if os.path.exists(GCAL_TOKEN):
        creds = Credentials.from_authorized_user_file(GCAL_TOKEN, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(GCAL_CREDS, SCOPES)
            creds = flow.run_local_server(port=0)
        os.makedirs(os.path.dirname(GCAL_TOKEN), exist_ok=True)
        with open(GCAL_TOKEN, "w") as f:
            f.write(creds.to_json())
    _calendar_service = build("calendar", "v3", credentials=creds)
    return _calendar_service


@mcp.tool()
def calendar_today() -> dict:
    """Get today's calendar events."""
    try:
        svc = _gcal()
        now = datetime.datetime.utcnow()
        start = now.replace(hour=0, minute=0, second=0).isoformat() + "Z"
        end = now.replace(hour=23, minute=59, second=59).isoformat() + "Z"
        events = svc.events().list(calendarId="primary", timeMin=start, timeMax=end,
            singleEvents=True, orderBy="startTime").execute().get("items", [])
        return {"date": now.strftime("%Y-%m-%d"), "events": [
            {"summary": e.get("summary"), "start": e["start"].get("dateTime", e["start"].get("date")),
             "end": e["end"].get("dateTime", e["end"].get("date")), "location": e.get("location")}
            for e in events
        ]}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def calendar_upcoming(days: int = 7, max_results: int = 20) -> dict:
    """Get upcoming calendar events for the next N days."""
    try:
        svc = _gcal()
        now = datetime.datetime.utcnow()
        end = now + datetime.timedelta(days=days)
        events = svc.events().list(calendarId="primary", timeMin=now.isoformat() + "Z",
            timeMax=end.isoformat() + "Z", singleEvents=True, orderBy="startTime",
            maxResults=max_results).execute().get("items", [])
        return {"events": [
            {"summary": e.get("summary"), "start": e["start"].get("dateTime", e["start"].get("date")),
             "end": e["end"].get("dateTime", e["end"].get("date")), "location": e.get("location")}
            for e in events
        ]}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def calendar_create_event(summary: str, start_time: str, end_time: str, description: str = "", location: str = "") -> dict:
    """Create a calendar event. Times in ISO format: 2026-07-05T10:00:00."""
    try:
        svc = _gcal()
        tz = datetime.datetime.now().astimezone().tzname()
        event = {
            "summary": summary,
            "description": description,
            "location": location,
            "start": {"dateTime": start_time, "timeZone": tz},
            "end": {"dateTime": end_time, "timeZone": tz},
        }
        created = svc.events().insert(calendarId="primary", body=event).execute()
        return {"success": True, "event_id": created["id"], "link": created.get("htmlLink")}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# 8. NOTIFICATIONS & REMINDERS
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def send_notification(title: str, message: str) -> dict:
    """Send a desktop notification."""
    try:
        if IS_MAC:
            subprocess.run(["osascript", "-e",
                f'display notification "{message}" with title "{title}"'], check=True)
        elif IS_WIN:
            # PowerShell toast notification
            ps = (
                f'[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, '
                f'ContentType = WindowsRuntime] > $null; '
                f'$template = [Windows.UI.Notifications.ToastNotificationManager]::'
                f'GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); '
                f'$text = $template.GetElementsByTagName("text"); '
                f'$text.Item(0).AppendChild($template.CreateTextNode("{title}")) > $null; '
                f'$text.Item(1).AppendChild($template.CreateTextNode("{message}")) > $null; '
                f'$toast = [Windows.UI.Notifications.ToastNotification]::new($template); '
                f'[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Personal MCP").Show($toast)'
            )
            subprocess.run(["powershell", "-command", ps], check=True)
        else:
            subprocess.run(["notify-send", title, message], check=True)
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def set_reminder(message: str, minutes: int) -> dict:
    """Set a reminder that fires as a desktop notification after N minutes."""
    import threading

    def _fire():
        send_notification("Reminder", message)

    timer = threading.Timer(minutes * 60, _fire)
    timer.daemon = True
    timer.start()
    fire_at = (datetime.datetime.now() + datetime.timedelta(minutes=minutes)).strftime("%H:%M")
    return {"success": True, "message": message, "fires_at": fire_at, "minutes": minutes}


# ═══════════════════════════════════════════════════════════════════
# 9. SOCIAL MEDIA (Twitter/X via API)
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def twitter_post(text: str) -> dict:
    """Post a tweet to Twitter/X. Requires TWITTER_BEARER_TOKEN and tweepy."""
    try:
        import tweepy
        bearer = os.environ.get("TWITTER_BEARER_TOKEN")
        api_key = os.environ.get("TWITTER_API_KEY")
        api_secret = os.environ.get("TWITTER_API_SECRET")
        access_token = os.environ.get("TWITTER_ACCESS_TOKEN")
        access_secret = os.environ.get("TWITTER_ACCESS_SECRET")
        if not all([api_key, api_secret, access_token, access_secret]):
            return {"error": "Set TWITTER_API_KEY, TWITTER_API_SECRET, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET env vars"}
        client = tweepy.Client(
            consumer_key=api_key, consumer_secret=api_secret,
            access_token=access_token, access_token_secret=access_secret
        )
        response = client.create_tweet(text=text)
        return {"success": True, "tweet_id": str(response.data["id"])}
    except ImportError:
        return {"error": "pip install tweepy"}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# 10. UTILITIES
# ═══════════════════════════════════════════════════════════════════


@mcp.tool()
def get_datetime() -> dict:
    """Get current date, time, timezone, and day of week."""
    now = datetime.datetime.now()
    return {
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "day": now.strftime("%A"),
        "timezone": str(datetime.datetime.now().astimezone().tzinfo),
        "iso": now.isoformat(),
    }


@mcp.tool()
def calculate(expression: str) -> dict:
    """Evaluate a math expression safely. Examples: '2**10', 'sqrt(144)', '45 * 12.5'"""
    import math
    allowed = {k: getattr(math, k) for k in dir(math) if not k.startswith("_")}
    allowed.update({"abs": abs, "round": round, "min": min, "max": max, "sum": sum})
    try:
        result = eval(expression, {"__builtins__": {}}, allowed)
        return {"expression": expression, "result": result}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def text_to_speech(text: str) -> dict:
    """Speak text aloud using the system's text-to-speech engine."""
    try:
        if IS_MAC:
            subprocess.Popen(["say", text])
        elif IS_WIN:
            subprocess.Popen(["powershell", "-command",
                f'Add-Type -AssemblyName System.Speech; '
                f'$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; '
                f'$s.Speak("{text}")'])
        else:
            subprocess.Popen(["espeak", text])
        return {"success": True, "text": text[:100]}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════


def main():
    transport = "streamable-http" if "--http" in sys.argv else "stdio"
    logger.info(f"Starting Personal MCP with {transport} transport")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
