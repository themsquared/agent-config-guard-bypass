#!/usr/bin/env python3
"""
A toy "agent file guard" of the kind an agent harness, MCP client, or IDE
copilot uses to stop an LLM-driven tool call from writing outside its
workspace.

This version has the bug class behind CVE-2026-103572 (Visual Studio
Copilot / SSMS, patched 2026-10-13): it VALIDATES the raw path string the
caller supplied, then WRITES using a path the filesystem resolves
differently.

The real CVE's primary vector (a trailing dot the Win32 layer strips but
NTFS does not, so "settings.json" and "settings.json." name the same file)
is Windows-specific and not reproducible on macOS/Linux. This demo
reproduces the OS-portable variant of the same root cause that the same
researcher also reported in the disclosure: a ".." path-traversal escape
from a trusted directory, checked as a string before resolution.
"""
from pathlib import Path

WORKSPACE = Path("./workspace").resolve()


def guard_write(requested_path: str, content: str) -> Path:
    """Validate, then write -- using two different notions of "the path"."""
    candidate = WORKSPACE / requested_path

    # BUG: checked as a raw string, before ".." is resolved. A path like
    # "../agent_home/mcp_settings.json" still starts with str(WORKSPACE)
    # here, because WORKSPACE / ".." hasn't collapsed yet -- it's just
    # string concatenation with a path separator.
    if not str(candidate).startswith(str(WORKSPACE)):
        raise PermissionError(f"refused: {requested_path} escapes workspace")

    # The actual write resolves the path, which collapses "..". By now the
    # containment check above already passed against the pre-resolution
    # string, so this write can land anywhere ".." can reach.
    resolved = candidate.resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content)
    print(f"wrote {resolved}")
    return resolved


if __name__ == "__main__":
    import sys

    guard_write(sys.argv[1], sys.argv[2])
