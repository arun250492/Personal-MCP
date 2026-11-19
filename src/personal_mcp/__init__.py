"""Personal MCP — your AI-powered personal assistant + IsItMe? IT triage toolkit."""

from ._version import __version__
from .server import main, mcp

__all__ = ["__version__", "main", "mcp"]
