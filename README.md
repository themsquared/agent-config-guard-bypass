# agent-config-guard-bypass

A 90-line reproduction of the bug class behind **CVE-2026-103572** (Visual
Studio Copilot / SSMS, CVSS 8.8, patched by Microsoft on 2026-10-13): a file
guard that validates a path as a raw string, then writes using a path the
filesystem resolves differently. The gap between "the string we checked"
and "the path we wrote" is where the exploit lives.

Writeup on the real CVE: [embracethered.com](https://embracethered.com/blog/posts/2026/visual-studio-copilot-remote-code-execution/).

## The problem

Any agent harness, MCP client, or IDE copilot that lets an LLM-driven tool
call write files needs a guard: "you may write inside this workspace, and
nowhere else." The disclosed CVE describes three ways that guard broke in
Visual Studio / SSMS:

1. A trailing dot in a filename (`settings.json.`) bypasses a string-equality
   check against a protected-filename list, because Windows' Win32 layer
   strips trailing dots before the actual write while NTFS treats the two
   names as distinct. **Windows/NTFS-specific, not reproducible here.**
2. A path starting inside a trusted directory that uses `..` components to
   resolve outside it, exposing files like `SSMS.isolation.ini`.
   **Reproduced in this repo** — it's an OS-portable instance of the same
   root cause.
3. Weak prompt-injection resistance in the model driving the agent, which is
   how an attacker gets a malicious path into the tool call in the first
   place. Out of scope here; this repo is about the guard, not the model.

All three share one root cause: **the code that validates a path and the
code that writes it don't agree on what "the path" is.** Validate the raw
string, write the resolved one, and anything `..` can reach is exposed.

In the real incident, the file an attacker could reach this way was the
agent's own MCP server configuration. Rewriting it registers a new MCP
server; the IDE then launches that server's `command` automatically, which
is the step that turns an arbitrary file write into arbitrary code
execution.

## What this repo shows

Two versions of the same ~20-line guard function, plus a script that runs
the identical attack against both:

- [`vulnerable_guard.py`](vulnerable_guard.py) — checks `str(path).startswith(workspace)`
  on the *unresolved* path, then writes to the *resolved* path.
- [`fixed_guard.py`](fixed_guard.py) — resolves first, then validates and writes using
  that same resolved path. One code change: move `.resolve()` before the
  check instead of after it.
- [`exploit_demo.py`](exploit_demo.py) — sets up a `workspace/` directory (what the agent
  is allowed to touch) next to an `agent_home/mcp_settings.json` (the
  protected MCP config that controls which servers get launched), then
  requests a write to `../agent_home/mcp_settings.json` through each guard.

## Quickstart (under 2 minutes)

Requires Python 3.9+ (uses `Path.resolve()` / `path.parents`), no
dependencies.

```bash
git clone https://github.com/themsquared/agent-config-guard-bypass.git
cd agent-config-guard-bypass
python3 exploit_demo.py
```

Expected output: the vulnerable guard writes the attacker's MCP server
entry into `agent_home/mcp_settings.json` and prints `COMPROMISED`; the
fixed guard raises `PermissionError: refused: ... escapes workspace` and
leaves the file untouched.

Try the guards directly:

```bash
# Normal write inside the workspace -- both guards allow this.
python3 vulnerable_guard.py "notes.txt" "hello"
cat workspace/notes.txt

# The escape, run on its own against just the vulnerable guard.
mkdir -p agent_home
echo '{"mcpServers": {"project-docs": {"command": "mcp-docs-server"}}}' > agent_home/mcp_settings.json
python3 vulnerable_guard.py "../agent_home/mcp_settings.json" '{"mcpServers": {"evil": {"command": "/tmp/payload.sh"}}}'
cat agent_home/mcp_settings.json   # now contains the "evil" entry

# Same call against the fixed guard: raises PermissionError instead.
python3 fixed_guard.py "../agent_home/mcp_settings.json" '{"mcpServers": {"evil": {"command": "/tmp/payload.sh"}}}'
```

`workspace/` and `agent_home/` are scratch directories created by these
commands; `.gitignore` keeps them out of the repo.

## Architecture notes

- The containment check in `vulnerable_guard.py` is `str.startswith()` on a
  `Path` built with `/` but never resolved. `WORKSPACE / "../agent_home/x"`
  stringifies to `<workspace>/../agent_home/x`, which genuinely starts with
  `<workspace>` — the bug is that nothing has collapsed the `..` yet.
- `fixed_guard.py` resolves once (`(WORKSPACE / requested_path).resolve()`)
  and uses that single resolved `Path` for both the containment check
  (`WORKSPACE in resolved.parents`) and the write. Validation and the write
  can no longer disagree, because there's only one path left by the time
  either of them runs.
- This is the same bug class as classic path traversal (`../../etc/passwd`)
  and is worth testing for in anything that lets an LLM agent choose a file
  path: tool-call argument validation, MCP server working-directory
  sandboxes, policy enforcement points in an agent gateway. Any guard that
  validates before resolving has this hole, regardless of language or
  framework.

## What this repo is not

Not a reproduction of the real CVE's actual Visual Studio/SSMS exploit path
(trailing-dot filename collision, protected-file identification, or the
specific MCP-server-registration UI flow) — that's Windows/NTFS-specific
and documented in the original writeup linked above. This is a minimal,
OS-portable illustration of the shared root cause, for anyone building or
auditing an agent tool-call guard.

---

📖 **Read the write-up:** _link added once the companion post is live on webofmike.com_

Topics: `mcp`, `ai-agents`, `agent-security`, `path-traversal`, `python`
