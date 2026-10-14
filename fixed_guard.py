#!/usr/bin/env python3
"""
Same guard, fixed the way Microsoft's 2026-10-13 patch is reported to have
fixed it: resolve the path first (collapsing ".." and symlinks), then
validate and write using that SAME resolved path. Validation and the write
now agree on what "the path" is, which is the whole fix.
"""
from pathlib import Path

WORKSPACE = Path("./workspace").resolve()


def guard_write(requested_path: str, content: str) -> Path:
    # FIX: resolve first. Every check after this line, and the write
    # itself, operate on the canonical form -- there is no longer a
    # pre-resolution string for an attacker to craft against.
    resolved = (WORKSPACE / requested_path).resolve()

    if resolved != WORKSPACE and WORKSPACE not in resolved.parents:
        raise PermissionError(f"refused: {requested_path} escapes workspace")

    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content)
    print(f"wrote {resolved}")
    return resolved


if __name__ == "__main__":
    import sys

    guard_write(sys.argv[1], sys.argv[2])
