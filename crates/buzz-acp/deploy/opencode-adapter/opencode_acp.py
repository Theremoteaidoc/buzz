#!/usr/bin/env python3
"""Minimal ACP (Agent Client Protocol v2) adapter wrapping the opencode CLI.

buzz-acp (harness) <-- JSON-RPC/stdio --> this adapter <-- subprocess --> opencode run

Same contract as cursor_acp.py: each prompt runs one `opencode run -m $OPENCODE_MODEL`
in the persona workdir; AGENTS.md there instructs the agent to post its reply via the
`buzz` CLI (shell tool). We stream a courtesy agent_message_chunk and end the turn.

Timeout (WO #598): OPENCODE_TIMEOUT_SECS must not silently undercut the seat's
BUZZ_ACP_MAX_TURN_DURATION. When neither is set the historic default is 1500s.
On TimeoutExpired we drain already-written stdout, label the outcome
killed_timeout, and return a JSON-RPC error so the harness cannot record a
quiet success.
"""
import json, os, re, signal, subprocess, sys, threading

OPENCODE = os.environ.get("OPENCODE_BIN", "/opt/buzz/opencode/opencode")
MODEL = os.environ.get("OPENCODE_MODEL", "opencode/deepseek-v4-flash-free")
WORKDIR = os.environ.get("OPENCODE_WORKDIR", "/opt/buzz/agents/home/opencode")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
DEFAULT_TIMEOUT_SECS = 1500
KILLED_TIMEOUT = "killed_timeout"

_out_lock = threading.Lock()
_procs = {}  # session_id -> Popen


def _positive_int(raw):
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        value = int(text)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def resolve_timeout_secs(env):
    """Subprocess cap: explicit OPENCODE_TIMEOUT_SECS, else seat MAX_TURN_DURATION."""
    explicit = _positive_int(env.get("OPENCODE_TIMEOUT_SECS"))
    if explicit is not None:
        return explicit
    max_turn = _positive_int(env.get("BUZZ_ACP_MAX_TURN_DURATION"))
    if max_turn is not None:
        return max_turn
    return DEFAULT_TIMEOUT_SECS


TIMEOUT = resolve_timeout_secs(os.environ)


def format_killed_timeout(partial, timeout_secs):
    marker = f"(opencode {KILLED_TIMEOUT} after {int(timeout_secs)}s)"
    body = ANSI.sub("", (partial or "")).strip()
    return f"{body}\n{marker}" if body else marker


def timeout_rpc_error_message(timeout_secs):
    return f"opencode: {KILLED_TIMEOUT} after {int(timeout_secs)}s"


def finish_after_timeout(proc, timeout_secs, timeout_exc):
    """SIGKILL the process group, drain stdout, return labelled partial output."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    rest = ""
    try:
        drained, _ = proc.communicate(timeout=5)
        rest = drained or ""
    except Exception:
        rest = ""
    chunks = []
    for piece in (getattr(timeout_exc, "stdout", None), getattr(timeout_exc, "output", None), rest):
        if not piece:
            continue
        if isinstance(piece, bytes):
            piece = piece.decode("utf-8", "replace")
        chunks.append(piece)
    # Dedup if communicate() and TimeoutExpired carry the same buffer.
    merged = chunks[0] if chunks else ""
    for extra in chunks[1:]:
        if extra and extra not in merged:
            merged += extra
    return format_killed_timeout(merged, timeout_secs)


def send(obj):
    data = json.dumps(obj, separators=(",", ":"))
    with _out_lock:
        sys.stdout.write(data + "\n")
        sys.stdout.flush()


def reply(req_id, result):
    send({"jsonrpc": "2.0", "id": req_id, "result": result})


def notify(method, params):
    send({"jsonrpc": "2.0", "method": method, "params": params})


def text_from_prompt(params):
    parts = []
    for block in params.get("prompt", []):
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(parts)


def run_prompt(req_id, session_id, prompt_text):
    env = dict(os.environ)
    env.setdefault("HOME", "/opt/buzz/agents/home")
    # Per-persona opencode HOME: isolates each opencode-adapter seat's session
    # store / config / log (opencode keys all of these off HOME). Without this,
    # two opencode personas sharing one HOME tangle sessions and mix logs.
    _ochome = os.environ.get("OPENCODE_HOME")
    if _ochome:
        env["HOME"] = _ochome
    # --auto: headless agent can't answer permission prompts (external-dir reads of
    # shared skills / the codebase clone would hang forever). Same posture as the
    # cursor-agent adapter's --trust --force. Agent runs as the locked buzzagent user.
    cmd = [OPENCODE, "run", "--auto", "-m", MODEL, prompt_text]
    timed_out = False
    try:
        proc = subprocess.Popen(
            cmd, cwd=WORKDIR, env=env,
            stdin=subprocess.DEVNULL,  # opencode `run` reads stdin; without an
            # immediate-EOF stdin it inherits the harness JSON-RPC pipe and blocks
            # forever at "init". (nologin shell + model latency were secondary.)
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True,
        )
        _procs[session_id] = proc
        try:
            out, _ = proc.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            out = finish_after_timeout(proc, TIMEOUT, exc)
        out = ANSI.sub("", (out or "")).strip()
        if out:
            notify("session/update", {
                "sessionId": session_id,
                "update": {"sessionUpdate": "agent_message_chunk",
                           "content": {"type": "text", "text": out[-8000:]}},
            })
        if timed_out:
            send({"jsonrpc": "2.0", "id": req_id,
                  "error": {"code": -32000, "message": timeout_rpc_error_message(TIMEOUT)}})
        else:
            reply(req_id, {"stopReason": "end_turn"})
    except Exception as exc:  # report as turn error, keep pipe alive
        send({"jsonrpc": "2.0", "id": req_id,
              "error": {"code": -32000, "message": f"opencode: {exc}"}})
    finally:
        _procs.pop(session_id, None)


def main():
    session_counter = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params", {}) or {}
        if method == "initialize":
            reply(req_id, {
                "protocolVersion": 2,
                "agentCapabilities": {
                    "loadSession": False,
                    "mcpCapabilities": {"http": False, "sse": False},
                    "promptCapabilities": {"audio": False, "embeddedContext": False, "image": False},
                },
                "agentInfo": {"name": "opencode-acp-adapter", "version": "0.1.1"},
            })
        elif method == "authenticate":
            reply(req_id, {})
        elif method == "session/new":
            session_counter += 1
            reply(req_id, {"sessionId": f"opencode-{session_counter}"})
        elif method == "session/prompt":
            sid = params.get("sessionId", "opencode-0")
            text = text_from_prompt(params)
            threading.Thread(target=run_prompt, args=(req_id, sid, text), daemon=True).start()
        elif method == "session/cancel":
            sid = params.get("sessionId")
            proc = _procs.get(sid)
            if proc and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
            if req_id is not None:
                reply(req_id, {})
        elif req_id is not None:
            reply(req_id, {})


if __name__ == "__main__":
    main()
