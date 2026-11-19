#!/usr/bin/env python3
"""Validate and package the IsItMe? ChatGPT plugin ZIP.

Usage:
    python chatgpt-plugin/build.py --mcp-url https://isitme.example.com/mcp \
        --demo-url https://youtu.be/xxxx [--check-live]

Writes dist/isitme-plugin-<version>.zip containing plugin.json, mcp.json and assets/.
Fails with a list of problems if anything would be rejected by the submission portal.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LIMITS = {"displayName": 30, "shortDescription": 30, "longDescription": 4000, "developerName": 80}
URL_FIELDS = ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL")
ICON_FIELDS = ("logo", "logoDark", "composerIcon", "composerIconDark")


def png_size(path: Path) -> tuple[int, int] | None:
    data = path.read_bytes()[:24]
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


def validate(plugin: dict, mcp: dict) -> list[str]:
    errors: list[str] = []
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", plugin.get("name", "")) or len(plugin["name"]) > 64:
        errors.append("name must be lowercase letters/numbers/single hyphens, max 64 chars")
    if not re.fullmatch(r"\d+\.\d+\.\d+", plugin.get("version", "")):
        errors.append("version must be semantic (x.y.z)")
    if len(plugin.get("description", "")) > 4000:
        errors.append("description > 4000 chars")
    oa = plugin.get("extensions", {}).get("com.openai", {})
    ui = oa.get("interface", {})
    for field, limit in LIMITS.items():
        value = ui.get(field, "")
        if not value:
            errors.append(f"interface.{field} is required")
        elif len(value) > limit:
            errors.append(f"interface.{field} is {len(value)} chars (max {limit})")
    for field in URL_FIELDS:
        url = ui.get(field, "")
        if not url.startswith("https://") or len(url) > 1024 or "@" in url.split("/")[2]:
            errors.append(f"interface.{field} must be an https URL without credentials")
    for field in ICON_FIELDS:
        rel = ui.get(field)
        if not rel:
            continue
        p = (HERE / rel).resolve()
        if not rel.startswith("./") or HERE not in p.parents or not p.exists():
            errors.append(f"interface.{field}: {rel} must be a ./ path to an included file")
            continue
        size = png_size(p)
        if size and (size[0] != size[1] or size[0] < 48 or size[0] > 4096):
            errors.append(f"interface.{field}: {rel} must be square, 48-4096 px (is {size[0]}x{size[1]})")
        if p.stat().st_size > 5 * 1024 * 1024:
            errors.append(f"interface.{field}: {rel} larger than 5 MiB")
    for color in ("brandColor", "brandColorDark"):
        if color in ui and not re.fullmatch(r"#[0-9A-Fa-f]{6}", ui[color]):
            errors.append(f"interface.{color} must be #RRGGBB")
    prompts = ui.get("defaultPrompt", [])
    if len(prompts) > 3 or len(set(prompts)) != len(prompts) or any(len(p) > 128 or "@" in p for p in prompts):
        errors.append("defaultPrompt: max 3 unique prompts, 128 chars each, no @mentions")
    caps = ui.get("capabilities", [])
    if len(caps) > 20 or any(len(c) > 120 for c in caps):
        errors.append("capabilities: max 20 items of 120 chars")

    review = oa.get("review", {})
    tc = review.get("test_cases", {})
    pos, neg = tc.get("positive", []), tc.get("negative", [])
    if len(pos) != 5 or len(neg) != 3:
        errors.append(f"need exactly 5 positive and 3 negative test cases (have {len(pos)}/{len(neg)})")
    for i, c in enumerate(pos):
        for k in ("description", "prompt", "tools_triggered", "expected_behavior"):
            if not c.get(k):
                errors.append(f"positive test case {i + 1} missing {k}")
    for i, c in enumerate(neg):
        for k in ("description", "prompt"):
            if not c.get(k):
                errors.append(f"negative test case {i + 1} missing {k}")
    demo = review.get("demo_recording_url", "")
    if not demo.startswith("https://") or "REPLACE" in demo:
        errors.append("review.demo_recording_url must be your real https demo video URL (use --demo-url)")

    servers = mcp.get("mcpServers", {})
    if len(servers) != 1:
        errors.append("mcp.json must declare exactly one MCP server")
    for name, s in servers.items():
        url = s.get("url", "")
        if s.get("type") != "streamable-http":
            errors.append(f"mcp server {name}: type must be streamable-http")
        if not url.startswith("https://") or "REPLACE" in url:
            errors.append(f"mcp server {name}: url must be your public https MCP URL (use --mcp-url)")
        if s.get("headers") or "clientSecret" in json.dumps(s):
            errors.append(f"mcp server {name}: no headers or client secrets allowed in the package")
    blob = json.dumps(plugin) + json.dumps(mcp)
    for banned in ("test_credentials", "reviewer_instructions", ".app.json", "\"apps\""):
        if banned in blob:
            errors.append(f"package must not contain {banned}")
    return errors


def check_live(plugin: dict, mcp: dict) -> list[str]:
    problems = []
    ui = plugin["extensions"]["com.openai"]["interface"]
    mcp_url = next(iter(mcp["mcpServers"].values()))["url"]
    base = mcp_url.rsplit("/mcp", 1)[0]
    targets = [(f, ui[f]) for f in URL_FIELDS] + [("healthz", base + "/healthz")]
    for label, url in targets:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "isitme-build"}), timeout=15) as r:
                if r.status >= 400:
                    problems.append(f"{label}: {url} returned HTTP {r.status}")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{label}: {url} not reachable ({exc})")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mcp-url", help="public MCP endpoint, e.g. https://isitme.example.com/mcp")
    ap.add_argument("--demo-url", help="https URL of your demo video")
    ap.add_argument("--check-live", action="store_true", help="also check the listing URLs and /healthz respond")
    ap.add_argument("--out", default=str(ROOT / "dist"))
    args = ap.parse_args()

    plugin = json.loads((HERE / "plugin.json").read_text())
    mcp = json.loads((HERE / "mcp.json").read_text())
    if args.mcp_url:
        next(iter(mcp["mcpServers"].values()))["url"] = args.mcp_url.rstrip("/")
    if args.demo_url:
        plugin["extensions"]["com.openai"]["review"]["demo_recording_url"] = args.demo_url

    errors = validate(plugin, mcp)
    if not errors and args.check_live:
        errors = check_live(plugin, mcp)
    if errors:
        print("✗ Plugin package is not ready:\n  - " + "\n  - ".join(errors))
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    zpath = out / f"{plugin['name']}-plugin-{plugin['version']}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("plugin.json", json.dumps(plugin, indent=2, ensure_ascii=False) + "\n")
        z.writestr("mcp.json", json.dumps(mcp, indent=2) + "\n")
        for f in sorted((HERE / "assets").iterdir()):
            if f.suffix.lower() in (".png", ".svg", ".jpg", ".jpeg", ".webp"):
                z.write(f, f"assets/{f.name}")
    print(f"✓ Wrote {zpath}")
    print("  Next: upload it at https://platform.openai.com/plugins → Create plugin → Upload ZIP")
    return 0


if __name__ == "__main__":
    sys.exit(main())
