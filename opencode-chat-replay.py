#!/usr/bin/env python3
"""Recreate an opencode session chat transcript from the opencode SQLite DB.

Reads ~/.local/share/opencode/opencode.db (message/part tables, plus the newer
session_message table when populated) and renders a session as Markdown, JSON,
or JSONL.

The DB is snapshotted to a temp dir first, including the -wal and -shm files, so
it is safe to run against a live opencode instance that is actively writing.

Examples:
  ./opencode-chat-replay.py --list
  ./opencode-chat-replay.py --latest
  ./opencode-chat-replay.py --session ses_f074ee112ffePU33E9jqR1TITX
  ./opencode-chat-replay.py --slug swift-star --format json --out chat.json
  ./opencode-chat-replay.py --slug swift-star --format jsonl --out chat.jsonl
  ./opencode-chat-replay.py --all --out-dir ./transcripts
"""

from __future__ import annotations

__description__ = "Recreate an opencode session chat transcript from the opencode SQLite DB"
__author__ = "Jim Clausing"
__version_info__ = (1, 0, 0)
__version__ = ".".join(map(str, __version_info__))
__date__ = "2026-10-07"

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Iterator

DEFAULT_DB = os.path.expanduser("~/.local/share/opencode/opencode.db")
DEFAULT_MAX_TOOL_OUTPUT = 2000


# --------------------------------------------------------------------------- #
# snapshot / connection
# --------------------------------------------------------------------------- #
def snapshot_db(db_path: str) -> tuple[str, str]:
    """Copy db plus -wal/-shm into a temp dir so reads never touch live files."""
    if not os.path.exists(db_path):
        sys.exit(f"error: database not found: {db_path}")

    tmpdir = tempfile.mkdtemp(prefix="opencode-replay-")
    dest = os.path.join(tmpdir, "opencode.db")
    shutil.copy2(db_path, dest)
    for suffix in ("-wal", "-shm"):
        side = db_path + suffix
        if os.path.exists(side):
            shutil.copy2(side, dest + suffix)
    return dest, tmpdir


def connect(db_path: str) -> tuple[sqlite3.Connection, str]:
    snap, tmpdir = snapshot_db(db_path)
    uri = f"file:{snap}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn, tmpdir


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def loads(raw: Any) -> dict:
    if not raw:
        return {}
    try:
        val = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return val if isinstance(val, dict) else {}


# --------------------------------------------------------------------------- #
# formatting helpers
# --------------------------------------------------------------------------- #
def ts(ms: Any) -> str:
    """Epoch milliseconds -> ISO-8601 UTC."""
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return "?"
    if ms <= 0:
        return "?"
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def truncate(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    return text[:limit] + f"\n... [{len(text) - limit} more chars truncated]"


def pretty(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def fence(text: str, lang: str = "") -> str:
    """Wrap in a fenced block, widening the fence if content has backticks."""
    longest = 0
    run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text}\n{ticks}"


# --------------------------------------------------------------------------- #
# data access
# --------------------------------------------------------------------------- #
def list_sessions(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT s.id, s.title, s.slug, s.directory, s.version, s.parent_id,
               s.time_created, s.time_updated,
               (SELECT COUNT(*) FROM message m WHERE m.session_id = s.id) AS n_msgs,
               (SELECT COUNT(*) FROM part   p WHERE p.session_id = s.id) AS n_parts
        FROM session s
        ORDER BY s.time_created
        """
    ).fetchall()


def get_session(conn: sqlite3.Connection, session_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM session WHERE id=?", (session_id,)
    ).fetchone()


def child_sessions(conn: sqlite3.Connection, parent_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM session WHERE parent_id=? ORDER BY time_created", (parent_id,)
    ).fetchall()


def fetch_turns(conn: sqlite3.Connection, session_id: str) -> list[dict]:
    """Return ordered turns for a session from message+part, or session_message."""
    if table_exists(conn, "session_message"):
        rows = conn.execute(
            "SELECT COUNT(*) AS n FROM session_message WHERE session_id=?", (session_id,)
        ).fetchone()
        if rows and rows["n"]:
            return turns_from_session_message(conn, session_id)
    return turns_from_message_part(conn, session_id)


def turns_from_message_part(conn: sqlite3.Connection, session_id: str) -> list[dict]:
    messages = conn.execute(
        "SELECT * FROM message WHERE session_id=? ORDER BY time_created, id",
        (session_id,),
    ).fetchall()

    parts_by_msg: dict[str, list[dict]] = {}
    for row in conn.execute(
        "SELECT * FROM part WHERE session_id=? ORDER BY time_created, id",
        (session_id,),
    ):
        data = loads(row["data"])
        data.setdefault("_id", row["id"])
        parts_by_msg.setdefault(row["message_id"], []).append(data)

    turns = []
    for msg in messages:
        meta = loads(msg["data"])
        turns.append(
            {
                "id": msg["id"],
                "role": meta.get("role", "unknown"),
                "agent": meta.get("agent") or meta.get("mode"),
                "model": format_model(meta),
                "time_created": msg["time_created"],
                "time_completed": (meta.get("time") or {}).get("completed"),
                "finish": meta.get("finish"),
                "cost": meta.get("cost"),
                "tokens": meta.get("tokens"),
                "error": meta.get("error"),
                "parts": parts_by_msg.get(msg["id"], []),
            }
        )
    return turns


def turns_from_session_message(conn: sqlite3.Connection, session_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM session_message WHERE session_id=? ORDER BY seq, time_created",
        (session_id,),
    ).fetchall()
    turns = []
    for row in rows:
        data = loads(row["data"])
        role = data.get("role") or row["type"]
        turns.append(
            {
                "id": row["id"],
                "role": role,
                "agent": data.get("agent"),
                "model": format_model(data),
                "time_created": row["time_created"],
                "time_completed": data.get("time", {}).get("completed")
                if isinstance(data.get("time"), dict)
                else None,
                "finish": data.get("finish"),
                "cost": data.get("cost"),
                "tokens": data.get("tokens"),
                "error": data.get("error"),
                "parts": normalise_parts(data.get("parts") or data.get("content") or []),
            }
        )
    return turns


def normalise_parts(parts: Any) -> list[dict]:
    """Coerce the newer nested part shape into the same dict shape as part.data."""
    if not isinstance(parts, list):
        return []
    out = []
    for p in parts:
        if isinstance(p, dict):
            out.append(p)
    return out


def format_model(meta: dict) -> str:
    model = meta.get("model")
    if isinstance(model, dict):
        prov, mid = model.get("providerID"), model.get("modelID")
    else:
        mid = meta.get("modelID")
        prov = meta.get("providerID")
    if mid and prov:
        return f"{prov}/{mid}"
    return mid or ""


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def render_markdown(
    session: sqlite3.Row | dict,
    turns: list[dict],
    *,
    include_reasoning: bool,
    include_tools: bool,
    max_tool_output: int,
) -> str:
    s = dict(session)
    children = s.pop("children", []) or []
    out: list[str] = []

    out.append(f"# {s.get('title') or s.get('slug') or 'Session'}")
    out.append("")
    out.append(f"- **Session ID:** `{s.get('id')}`")
    if s.get("slug"):
        out.append(f"- **Slug:** `{s['slug']}`")
    if s.get("directory"):
        out.append(f"- **Directory:** `{s['directory']}`")
    if s.get("version"):
        out.append(f"- **opencode version:** `{s['version']}`")
    if s.get("share_url"):
        out.append(f"- **Share URL:** {s['share_url']}")
    out.append(f"- **Created:** {ts(s.get('time_created'))}")
    out.append(f"- **Updated:** {ts(s.get('time_updated'))}")
    if s.get("cost"):
        out.append(f"- **Cost:** ${s['cost']:.4f}")
    ti, to, tr = s.get("tokens_input"), s.get("tokens_output"), s.get("tokens_reasoning")
    if any((ti, to, tr)):
        out.append(
            f"- **Tokens (session row):** in={ti or 0} out={to or 0} reasoning={tr or 0}"
        )
    out.append(f"- **Turns:** {len(turns)}")
    if children:
        out.append(f"- **Child sessions:** {len(children)}")
    out.append("")

    out.append("---")
    out.append("")

    for i, turn in enumerate(turns, 1):
        role = turn.get("role") or "unknown"
        head = f"## {i}. {role.upper()}"
        meta_bits = []
        if turn.get("agent"):
            meta_bits.append(f"agent={turn['agent']}")
        if turn.get("model"):
            meta_bits.append(f"model={turn['model']}")
        meta_bits.append(ts(turn.get("time_created")))
        if meta_bits:
            head += f"  \n<sub>{' | '.join(meta_bits)}</sub>"
        out.append(head)
        out.append("")

        err = turn.get("error")
        if err:
            out.append(f"> **ERROR:** {pretty(err)}")
            out.append("")

        body = False
        for part in turn.get("parts", []):
            ptype = part.get("type")

            if ptype == "text":
                text = (part.get("text") or "").strip()
                if text:
                    body = True
                    out.append(text)
                    out.append("")

            elif ptype == "reasoning":
                text = (part.get("text") or "").strip()
                if text and include_reasoning:
                    body = True
                    out.append("<details><summary>reasoning</summary>")
                    out.append("")
                    out.append(text)
                    out.append("")
                    out.append("</details>")
                    out.append("")

            elif ptype == "tool" and include_tools:
                body = True
                out.extend(render_tool(part, max_tool_output))

            elif ptype in ("step-start", "step-finish"):
                continue

            elif ptype and ptype not in ("text", "reasoning", "tool"):
                body = True
                out.append(f"**{ptype}**")
                out.append("")
                known = {"id", "messageID", "sessionID", "type", "callID", "tool"}
                payload = {k: v for k, v in part.items() if k not in known}
                if payload:
                    out.append(fence(pretty(payload)))
                    out.append("")

        if not body:
            out.append("_(no renderable content)_")
            out.append("")

        if turn.get("finish") or turn.get("tokens"):
            bits = []
            if turn.get("finish"):
                bits.append(f"finish={turn['finish']}")
            tok = turn.get("tokens") or {}
            if tok:
                cache = tok.get("cache") or {}
                bits.append(
                    "tokens: total={total} in={input} out={output} reason={reasoning} "
                    "cache_w={w} cache_r={r}".format(
                        total=tok.get("total", 0),
                        input=tok.get("input", 0),
                        output=tok.get("output", 0),
                        reasoning=tok.get("reasoning", 0),
                        w=cache.get("write", 0),
                        r=cache.get("read", 0),
                    )
                )
            if turn.get("cost"):
                bits.append(f"cost=${turn['cost']:.4f}")
            out.append(f"<sub>{' | '.join(bits)}</sub>")
            out.append("")

        out.append("---")
        out.append("")

    for child in children:
        out.append(f"## Child session: {child.get('title') or child.get('slug')}")
        out.append("")
        out.append(f"- **ID:** `{child.get('id')}`")
        out.append(f"- **Created:** {ts(child.get('time_created'))}")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


TOOL_STATUS_MARK = {
    "completed": "ok",
    "error": "ERROR",
    "running": "running",
    "pending": "pending",
    "aborted": "aborted",
}


def render_tool(part: dict, max_output: int) -> list[str]:
    state = part.get("state") or {}
    status = state.get("status", "?")
    mark = TOOL_STATUS_MARK.get(status, status)
    name = part.get("tool") or "tool"
    out = [
        f"<details><summary><b>tool:</b> <code>{name}</code> "
        f"[{mark}] <code>{part.get('callID', '')}</code></summary>",
        "",
    ]

    tool_input = state.get("input")
    if tool_input not in (None, {}, ""):
        out.append("**input**")
        out.append("")
        out.append(fence(truncate(pretty(tool_input), max_output), "json"))
        out.append("")

    title = state.get("title")
    metadata = state.get("metadata")
    if title or metadata:
        extra = {}
        if isinstance(metadata, dict):
            for k, v in metadata.items():
                if k in ("output", "input"):
                    continue
                if isinstance(v, (str, int, float, bool)) or v is None:
                    extra[k] = v
        if title:
            extra["title"] = title
        if extra:
            out.append("**meta**")
            out.append("")
            out.append(fence(pretty(extra), "json"))
            out.append("")

    if status == "error" and state.get("error"):
        out.append("**error**")
        out.append("")
        out.append(fence(truncate(pretty(state["error"]), max_output)))
        out.append("")

    tool_output = state.get("output")
    if tool_output not in (None, "", {}):
        out.append("**output**")
        out.append("")
        out.append(fence(truncate(pretty(tool_output), max_output)))
        out.append("")

    out.append("</details>")
    out.append("")
    return out


def render_json(session: dict, turns: list[dict]) -> str:
    return json.dumps(
        {"session": session, "turns": turns}, indent=2, ensure_ascii=False
    ) + "\n"


def render_jsonl(session: dict, turns: list[dict]) -> str:
    """Render session turns as JSON Lines (one turn per line)."""
    lines: list[str] = []
    for turn in turns:
        record = {
            "session": {
                k: v
                for k, v in session.items()
                if k not in ("children",)
            },
            "turn": turn,
        }
        lines.append(json.dumps(record, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


# --------------------------------------------------------------------------- #
# listing
# --------------------------------------------------------------------------- #
def print_list(conn: sqlite3.Connection) -> None:
    sessions = list_sessions(conn)
    if not sessions:
        print("no sessions found")
        return
    width = max(len(r["id"]) for r in sessions)
    slugs = [(r["slug"] or "") for r in sessions]
    slug_width = max([len("SLUG")] + [len(s) for s in slugs])
    print(
        f"{'SESSION ID'.ljust(width)}  {'SLUG'.ljust(slug_width)}  {'MSGS':>5}  "
        f"{'PARTS':>6}  {'CREATED (UTC)':<26}  TITLE"
    )
    for r, slug in zip(sessions, slugs):
        print(
            f"{r['id'].ljust(width)}  {slug.ljust(slug_width)}  {r['n_msgs']:>5}  "
            f"{r['n_parts']:>6}  {ts(r['time_created']):<26}  {r['title']}"
        )


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
def write_output(text: str, out_path: str | None) -> None:
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {out_path} ({len(text)} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(text)


def safe_name(text: str) -> str:
    keep = []
    for ch in text:
        keep.append(ch if (ch.isalnum() or ch in "-_.") else "-")
    return "".join(keep).strip("-") or "session"


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #
def resolve_session(
    conn: sqlite3.Connection, args: argparse.Namespace
) -> list[sqlite3.Row]:
    """Resolve --session/--slug/--latest/--all into a list of session rows."""
    if args.all:
        return list_sessions(conn)

    if args.session:
        row = get_session(conn, args.session)
        if row is None:
            matches = [
                r
                for r in list_sessions(conn)
                if r["id"].startswith(args.session)
            ]
            if len(matches) == 1:
                return matches
            if not matches:
                sys.exit(f"error: no session matching id '{args.session}'")
            print(f"ambiguous id prefix '{args.session}':", file=sys.stderr)
            for m in matches:
                print(f"  {m['id']}  {m['title']}", file=sys.stderr)
            sys.exit(1)
        return [row]

    sessions = list_sessions(conn)

    if args.slug:
        matches = [r for r in sessions if r["slug"] == args.slug]
        if not matches:
            matches = [r for r in sessions if args.slug.lower() in r["slug"].lower()]
        if not matches:
            sys.exit(f"error: no session with slug matching '{args.slug}'")
        return matches

    if args.latest:
        if not sessions:
            sys.exit("error: no sessions found")
        return [sessions[-1]]

    print_list(conn)
    sys.exit(0)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Recreate an opencode session chat from the SQLite DB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--db", default=DEFAULT_DB, help=f"path to opencode.db (default: {DEFAULT_DB})"
    )
    p.add_argument(
        "-V",
        "--version",
        action="version",
        help="print version number",
        version="%(prog)s v" + __version__,
    )
    p.add_argument("--list", action="store_true", help="list sessions and exit")
    p.add_argument("--session", metavar="ID", help="session id or unique id prefix")
    p.add_argument("--slug", metavar="SLUG", help="session slug (exact or substring)")
    p.add_argument("--latest", action="store_true", help="most recent session")
    p.add_argument("--all", action="store_true", help="export every session")
    p.add_argument(
        "--include-children", action="store_true", help="follow child (sub) sessions"
    )
    p.add_argument(
        "--no-reasoning", action="store_true", help="omit assistant reasoning parts"
    )
    p.add_argument("--no-tools", action="store_true", help="omit tool calls")
    p.add_argument(
        "--max-tool-output",
        type=int,
        default=DEFAULT_MAX_TOOL_OUTPUT,
        help=(
            "truncate tool input/output to N chars, 0 = unlimited "
            f"(default: {DEFAULT_MAX_TOOL_OUTPUT})"
        ),
    )
    p.add_argument(
        "--format",
        choices=("md", "json", "jsonl"),
        default="md",
        help="output format (default: md)",
    )
    p.add_argument("--out", metavar="FILE", help="write to FILE instead of stdout")
    p.add_argument("--out-dir", metavar="DIR", help="write one file per session into DIR")
    args = p.parse_args()

    conn, tmpdir = connect(args.db)
    try:
        if args.list:
            print_list(conn)
            return 0

        if not (args.session or args.slug or args.latest or args.all):
            print_list(conn)
            return 0

        sessions = resolve_session(conn, args)

        if args.out_dir:
            os.makedirs(args.out_dir, exist_ok=True)

        for row in sessions:
            session = dict(row)
            if args.include_children:
                session["children"] = [dict(c) for c in child_sessions(conn, row["id"])]
            turns = fetch_turns(conn, row["id"])

            if args.format == "json":
                text = render_json(session, turns)
                ext = "json"
            elif args.format == "jsonl":
                text = render_jsonl(session, turns)
                ext = "jsonl"
            else:
                text = render_markdown(
                    session,
                    turns,
                    include_reasoning=not args.no_reasoning,
                    include_tools=not args.no_tools,
                    max_tool_output=args.max_tool_output,
                )
                ext = "md"

            if args.out_dir:
                path = os.path.join(
                    args.out_dir,
                    f"{ts(row['time_created'])[0:10]}_{safe_name(row['slug'])}.{ext}",
                )
                write_output(text, path)
            else:
                write_output(text, args.out)

        return 0
    finally:
        conn.close()
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
