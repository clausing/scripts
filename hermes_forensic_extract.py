#!/usr/bin/env python3
"""
Hermes Agent Forensic Log Extractor

Extracts chat/prompt/reasoning logs from Hermes Agent's data stores for
forensic investigation or incident response.

Data sources:
- ~/.hermes/state.db (SQLite) - sessions, messages, model usage, routing
- ~/.hermes/sessions/*.json - request/response dumps (full API payloads)
- ~/.hermes/logs/*.log - structured application logs (agent.log, errors.log, gateway.log, gui.log)

Output: JSON Lines (NDJSON) - one JSON object per record, streamable and parseable.
"""

__description__ = 'Extract forensic logs from Hermes Agent for incident response'
__author__ = 'Jim Clausing'
__version_info__ = (1, 2, 1)
__version__ = '.'.join(map(str, __version_info__))
__date__ = '2026-10-08'

import argparse
import base64
import json
import re
import shutil
import signal
import sqlite3
import sys
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, Iterator, Generator
from dataclasses import dataclass

signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def parse_timestamp(value: str) -> float:
    """Parse timestamp in 'YYYY-MM-DD HH:MM:SS' format (time optional, 24-hour).
    
    Also accepts raw Unix timestamp (float/int).
    
    Examples:
        '2026-10-07'            -> 2026-10-07 00:00:00
        '2026-10-07 14'         -> 2026-10-07 14:00:00
        '2026-10-07 14:30'      -> 2026-10-07 14:30:00
        '2026-10-07 14:30:45'   -> 2026-10-07 14:30:45
        '1728086400'            -> Unix timestamp
    """
    # Accept raw Unix timestamp
    try:
        return float(value)
    except ValueError:
        pass
    
    value = value.strip()
    
    # Try ISO format first (handles 'YYYY-MM-DD' and 'YYYY-MM-DDTHH:MM:SS')
    # Replace space with T for fromisoformat compatibility
    iso_candidate = value.replace(' ', 'T')
    try:
        return datetime.fromisoformat(iso_candidate).timestamp()
    except ValueError:
        pass
    
    # Try space-separated formats with optional time components
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d %H', '%Y-%m-%d'):
        try:
            return datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    
    raise argparse.ArgumentTypeError(
        f"Invalid timestamp: '{value}'. Use 'YYYY-MM-DD HH:MM:SS' "
        "(time optional, 24-hour) or Unix timestamp."
    )


@dataclass
class ExtractionConfig:  # pylint: disable=too-many-instance-attributes
    """Settings controlling which sources and filters the extractor uses."""
    hermes_home: Path
    output_file: Optional[Path]
    include_sessions: bool
    include_messages: bool
    include_model_usage: bool
    include_request_dumps: bool
    include_logs: bool
    session_filter: Optional[str]
    source_filter: Optional[str]
    start_time: Optional[float]
    end_time: Optional[float]
    limit: Optional[int]
    pretty: bool
    state_db: Optional[Path] = None


class HermesForensicExtractor:  # pylint: disable=too-many-instance-attributes
    """Reads Hermes Agent data stores and yields forensic records as dicts."""

    def __init__(self, config: ExtractionConfig):
        self.config = config
        self.hermes_home = config.hermes_home
        self.state_db = config.state_db or self.hermes_home / "state.db"
        self.sessions_dir = self.hermes_home / "sessions"
        self.logs_dir = self.hermes_home / "logs"
        self.stats = {
            "sessions": 0,
            "messages": 0,
            "model_usage": 0,
            "request_dumps": 0,
            "log_entries": 0,
        }
        self._snapshot_dir: Optional[str] = None
        self._snapshot_db: Optional[Path] = None

    def _snapshot(self) -> Path:
        """Copy state.db plus -wal/-shm into a temp dir (once) so reads never touch the source"""
        if self._snapshot_db is None:
            self._snapshot_dir = tempfile.mkdtemp(prefix="hermes-extract-")
            dest = Path(self._snapshot_dir) / self.state_db.name
            shutil.copy2(self.state_db, dest)
            for suffix in ("-wal", "-shm"):
                side = Path(str(self.state_db) + suffix)
                if side.exists():
                    shutil.copy2(side, Path(str(dest) + suffix))
            self._snapshot_db = dest
        return self._snapshot_db

    def close(self) -> None:
        """Remove the temporary database snapshot, if one was made"""
        if self._snapshot_dir:
            shutil.rmtree(self._snapshot_dir, ignore_errors=True)
            self._snapshot_dir = None
            self._snapshot_db = None

    def _connect_db(self) -> sqlite3.Connection:
        """Open read-only connection to a snapshot of state.db"""
        conn = sqlite3.connect(f"file:{self._snapshot()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def _parse_iso_time(self, ts_str: str) -> Optional[float]:
        """Parse ISO timestamp string to unix timestamp"""
        try:
            dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except ValueError:
            return None

    def _format_timestamp(self, ts: Optional[float]) -> Optional[str]:
        """Format unix timestamp to ISO string"""
        if ts is None:
            return None
        return datetime.fromtimestamp(ts, tz=datetime.now().astimezone().tzinfo).isoformat()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert sqlite3.Row to dict with proper JSON serialization"""
        return {key: row[key] for key in row.keys()}

    def _matches_time_filter(self, ts: Optional[float]) -> bool:
        """Check if timestamp matches time range filter"""
        if ts is None:
            return True
        if self.config.start_time and ts < self.config.start_time:
            return False
        if self.config.end_time and ts > self.config.end_time:
            return False
        return True

    def extract_sessions(self) -> Generator[Dict[str, Any], None, None]:  # pylint: disable=too-many-branches
        """Extract session records from state.db"""
        if not self.config.include_sessions:
            return

        conn = self._connect_db()
        try:
            query = "SELECT * FROM sessions WHERE 1=1"
            params = []

            if self.config.session_filter:
                query += " AND id LIKE ?"
                params.append(f"%{self.config.session_filter}%")

            if self.config.source_filter:
                query += " AND source = ?"
                params.append(self.config.source_filter)

            query += " ORDER BY started_at DESC"

            if self.config.limit:
                query += f" LIMIT {self.config.limit}"

            cursor = conn.execute(query, params)
            for row in cursor:
                session = self._row_to_dict(row)
                session["_extraction_type"] = "session"
                session["_extracted_at"] = datetime.now().isoformat()

                # Convert timestamps to ISO format for readability
                for ts_field in ["started_at", "ended_at", "last_activity_at", "last_read_at"]:
                    if session.get(ts_field):
                        session[f"{ts_field}_iso"] = self._format_timestamp(session[ts_field])

                # Parse model_config JSON if present
                if session.get("model_config"):
                    try:
                        session["model_config_parsed"] = json.loads(session["model_config"])
                    except json.JSONDecodeError:
                        session["model_config_parsed"] = None

                # Parse origin_json if present
                if session.get("origin_json"):
                    try:
                        session["origin_json_parsed"] = json.loads(session["origin_json"])
                    except json.JSONDecodeError:
                        session["origin_json_parsed"] = None

                # Parse tool_names if present
                if session.get("tool_names"):
                    try:
                        session["tool_names_parsed"] = json.loads(session["tool_names"])
                    except json.JSONDecodeError:
                        session["tool_names_parsed"] = None

                if not self._matches_time_filter(session.get("started_at")):
                    continue

                self.stats["sessions"] += 1
                yield session
        finally:
            conn.close()

    def extract_messages(self) -> Generator[Dict[str, Any], None, None]:  # pylint: disable=too-many-branches,too-many-nested-blocks
        """Extract message records from state.db"""
        if not self.config.include_messages:
            return

        conn = self._connect_db()
        try:
            query = """
                SELECT m.*, s.source as session_source, s.model as session_model
                FROM messages m
                JOIN sessions s ON s.id = m.session_id
                WHERE 1=1
            """
            params = []

            if self.config.session_filter:
                query += " AND m.session_id LIKE ?"
                params.append(f"%{self.config.session_filter}%")

            if self.config.source_filter:
                query += " AND s.source = ?"
                params.append(self.config.source_filter)

            query += " ORDER BY m.session_id, m.timestamp ASC"

            if self.config.limit:
                query += f" LIMIT {self.config.limit}"

            cursor = conn.execute(query, params)
            for row in cursor:
                msg = self._row_to_dict(row)
                msg["_extraction_type"] = "message"
                msg["_extracted_at"] = datetime.now().isoformat()

                # Convert timestamp
                if msg.get("timestamp"):
                    msg["timestamp_iso"] = self._format_timestamp(msg["timestamp"])

                # Parse JSON fields (skip binary/blob fields)
                for json_field in ["tool_calls", "reasoning_details", "codex_reasoning_items",
                                    "codex_message_items", "display_metadata",
                                    "absorbed_message_uids", "tool_call_uids", "api_content"]:
                    if msg.get(json_field):
                        try:
                            msg[f"{json_field}_parsed"] = json.loads(msg[json_field])
                        except (json.JSONDecodeError, TypeError):
                            msg[f"{json_field}_parsed"] = None

                # Handle binary fields - convert to base64 for JSON serialization
                for bin_field in ["display_identity"]:
                    if msg.get(bin_field) is not None:
                        if isinstance(msg[bin_field], bytes):
                            msg[f"{bin_field}_base64"] = base64.b64encode(
                                msg[bin_field]).decode('ascii')
                        else:
                            msg[f"{bin_field}_base64"] = str(msg[bin_field])
                        msg[f"{bin_field}_is_binary"] = True
                        # Replace original binary field with None to avoid JSON serialization errors
                        msg[bin_field] = None

                if not self._matches_time_filter(msg.get("timestamp")):
                    continue

                self.stats["messages"] += 1
                yield msg
        finally:
            conn.close()

    def extract_model_usage(self) -> Generator[Dict[str, Any], None, None]:
        """Extract model usage records from state.db"""
        if not self.config.include_model_usage:
            return

        conn = self._connect_db()
        try:
            query = """
                SELECT mu.*, s.source as session_source
                FROM session_model_usage mu
                JOIN sessions s ON s.id = mu.session_id
                WHERE 1=1
            """
            params = []

            if self.config.session_filter:
                query += " AND mu.session_id LIKE ?"
                params.append(f"%{self.config.session_filter}%")

            if self.config.source_filter:
                query += " AND s.source = ?"
                params.append(self.config.source_filter)

            query += " ORDER BY mu.last_seen DESC"

            if self.config.limit:
                query += f" LIMIT {self.config.limit}"

            cursor = conn.execute(query, params)
            for row in cursor:
                usage = self._row_to_dict(row)
                usage["_extraction_type"] = "model_usage"
                usage["_extracted_at"] = datetime.now().isoformat()

                for ts_field in ["first_seen", "last_seen"]:
                    if usage.get(ts_field):
                        usage[f"{ts_field}_iso"] = self._format_timestamp(usage[ts_field])

                if not self._matches_time_filter(usage.get("last_seen")):
                    continue

                self.stats["model_usage"] += 1
                yield usage
        finally:
            conn.close()

    def extract_request_dumps(self) -> Generator[Dict[str, Any], None, None]:
        """Extract request/response dump JSON files from sessions/ directory"""
        if not self.config.include_request_dumps:
            return

        if not self.sessions_dir.exists():
            return

        pattern = "request_dump_*.json"
        if self.config.session_filter:
            pattern = f"request_dump_{self.config.session_filter}_*.json"

        dump_files = sorted(self.sessions_dir.glob(pattern))

        for dump_file in dump_files:
            try:
                with open(dump_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Add metadata
                data["_extraction_type"] = "request_dump"
                data["_source_file"] = str(dump_file)
                data["_extracted_at"] = datetime.now().isoformat()

                # Extract session ID from filename
                # Format: request_dump_<session_id>_<timestamp>_<random>.json
                parts = dump_file.stem.split('_')
                if len(parts) >= 3:
                    data["_parsed_session_id"] = (
                        "_".join(parts[2:-2]) if len(parts) > 4 else parts[2])

                # Check session filter
                if self.config.session_filter and self.config.session_filter not in dump_file.name:
                    continue

                # Check time filter on file mtime
                mtime = dump_file.stat().st_mtime
                if not self._matches_time_filter(mtime):
                    continue

                self.stats["request_dumps"] += 1
                yield data

            except (json.JSONDecodeError, OSError) as e:
                yield {
                    "_extraction_type": "request_dump_error",
                    "_source_file": str(dump_file),
                    "_extracted_at": datetime.now().isoformat(),
                    "error": str(e),
                }

    def extract_logs(self) -> Generator[Dict[str, Any], None, None]:
        """Extract structured log entries from log files"""
        if not self.config.include_logs:
            return

        if not self.logs_dir.exists():
            return

        log_files = ["agent.log", "errors.log", "gateway.log", "gui.log"]

        for log_file in log_files:
            log_path = self.logs_dir / log_file
            if not log_path.exists():
                continue

            component = log_file.replace('.log', '')

            try:
                with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue

                        # Parse Hermes log format: timestamp LEVEL[session_tag] logger: message
                        # Example: 2026-10-05 13:34:22,460 INFO hermes_cli.main: message
                        parsed = self._parse_log_line(line, component)
                        if parsed:
                            parsed["_source_file"] = str(log_path)
                            parsed["_line_number"] = line_num
                            parsed["_extracted_at"] = datetime.now().isoformat()

                            # Check time filter
                            if not self._matches_time_filter(parsed.get("_timestamp")):
                                continue

                            self.stats["log_entries"] += 1
                            yield parsed

            except OSError as e:
                yield {
                    "_extraction_type": "log_error",
                    "_source_file": str(log_path),
                    "_extracted_at": datetime.now().isoformat(),
                    "error": str(e),
                }

    def _parse_log_line(self, line: str, component: str) -> Optional[Dict[str, Any]]:
        """Parse a single Hermes log line into structured data"""
        # Format: 2026-10-05 13:34:22,460 INFO[session_id] logger.name: message
        # Or:     2026-10-05 13:34:22,460 INFO logger.name: message (no session tag)
        # Regex for Hermes log format
        pattern = (r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+(\w+)'
                   r'(?:\s*\[([^\]]+)\])?\s+([^:]+):\s*(.*)$')
        match = re.match(pattern, line)

        if not match:
            # Fallback: return raw line
            return {
                "_extraction_type": "log_entry",
                "component": component,
                "raw_line": line,
                "parse_error": "format_mismatch",
            }

        timestamp_str, level, session_tag, logger_name, message = match.groups()

        # Parse timestamp
        try:
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
            timestamp = dt.timestamp()
            timestamp_iso = dt.isoformat()
        except ValueError:
            timestamp = None
            timestamp_iso = None

        return {
            "_extraction_type": "log_entry",
            "component": component,
            "timestamp": timestamp,
            "timestamp_iso": timestamp_iso,
            "level": level,
            "session_id": session_tag if session_tag else None,
            "logger": logger_name.strip(),
            "message": message,
            "raw_line": line,
        }

    def extract_all(self) -> Iterator[Dict[str, Any]]:
        """Extract all enabled data sources in order"""
        # Order matters for forensic timeline reconstruction
        yield from self.extract_sessions()
        yield from self.extract_messages()
        yield from self.extract_model_usage()
        yield from self.extract_request_dumps()
        yield from self.extract_logs()

    def list_sessions(self) -> list:
        """List all sessions with basic info for --list mode"""
        conn = self._connect_db()
        try:
            query = """
                SELECT s.id, s.source, s.model, s.started_at, s.ended_at,
                       COUNT(m.id) as message_count
                FROM sessions s
                LEFT JOIN messages m ON m.session_id = s.id
                WHERE 1=1
            """
            params = []

            if self.config.session_filter:
                query += " AND s.id LIKE ?"
                params.append(f"%{self.config.session_filter}%")

            if self.config.source_filter:
                query += " AND s.source = ?"
                params.append(self.config.source_filter)

            query += " GROUP BY s.id ORDER BY s.started_at DESC"

            if self.config.limit:
                query += f" LIMIT {self.config.limit}"

            cursor = conn.execute(query, params)
            sessions = []
            for row in cursor:
                session = {
                    "id": row["id"],
                    "source": row["source"],
                    "model": row["model"],
                    "started_at": row["started_at"],
                    "ended_at": row["ended_at"],
                    "message_count": row["message_count"],
                }
                # Convert timestamps to ISO format
                if session["started_at"]:
                    session["started_iso"] = self._format_timestamp(session["started_at"])
                if session["ended_at"]:
                    session["ended_iso"] = self._format_timestamp(session["ended_at"])
                sessions.append(session)
            return sessions
        finally:
            conn.close()

    def _write_records(self, output_handle) -> None:
        """Write all extracted records to a handle as JSON lines"""
        indent = 2 if self.config.pretty else None
        for record in self.extract_all():
            json.dump(record, output_handle, indent=indent, ensure_ascii=False)
            output_handle.write('\n')
            # Flush for pipeline use
            output_handle.flush()

    def run(self) -> Dict[str, int]:
        """Run extraction and write output"""
        if self.config.output_file:
            with open(self.config.output_file, 'w', encoding='utf-8') as output_handle:
                self._write_records(output_handle)
        else:
            self._write_records(sys.stdout)

        return self.stats


def parse_args() -> argparse.Namespace:
    """Build the argument parser and parse the command line"""
    parser = argparse.ArgumentParser(
        description="Extract forensic logs from Hermes Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract all data to JSONL file
  %(prog)s -o evidence.jsonl

  # Extract only sessions and messages for a specific session
  %(prog)s --session 20261005_140841_b266b9 -o session_evidence.jsonl

  # Extract last 24 hours (since epoch)
  %(prog)s --start-time 1728086400 -o last_24h.jsonl

  # Extract only CLI sessions with messages
  %(prog)s --source cli --include-sessions --include-messages -o cli_only.jsonl

  # Pretty-print for human review
  %(prog)s --pretty -o review.jsonl

  # Run against a mounted disk image (looks in <dir>/.hermes)
  %(prog)s -d /mnt/image/home/user -o evidence.jsonl

  # Point at a state.db directly (sessions/ and logs/ are read from its directory)
  %(prog)s -f /evidence/state.db -o evidence.jsonl
        """
    )

    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--hermes-home",
        type=Path,
        default=Path.home() / ".hermes",
        help="Hermes home directory (default: ~/.hermes)"
    )
    source.add_argument(
        "-d", "--dir",
        type=Path,
        metavar="HOME",
        help="User home directory containing .hermes (e.g. on a mounted disk image)"
    )
    source.add_argument(
        "-f", "--file",
        type=Path,
        metavar="STATE_DB",
        help="Path to a state.db file; sessions/ and logs/ are read from its directory"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--session",
        dest="session_filter",
        help="Filter by session ID (substring match)"
    )
    parser.add_argument(
        "--source",
        dest="source_filter",
        help="Filter by source (cli, telegram, discord, slack, gateway, etc.)"
    )
    parser.add_argument(
        "--start-time",
        type=parse_timestamp,
        help="Start time filter (YYYY-MM-DD HH:MM:SS, time optional, 24-hour; or Unix timestamp)"
    )
    parser.add_argument(
        "--end-time",
        type=parse_timestamp,
        help="End time filter (YYYY-MM-DD HH:MM:SS, time optional, 24-hour; or Unix timestamp)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit records per source"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON (default: compact NDJSON)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List sessions (id, source, model, started, message count) and exit"
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version and exit"
    )

    # Source toggles
    parser.add_argument("--no-sessions", action="store_true", help="Skip sessions table")
    parser.add_argument("--no-messages", action="store_true", help="Skip messages table")
    parser.add_argument("--no-model-usage", action="store_true", help="Skip model usage table")
    parser.add_argument("--no-request-dumps", action="store_true", help="Skip request dump files")
    parser.add_argument("--no-logs", action="store_true", help="Skip log files")

    # Quick presets
    parser.add_argument(
        "--only-sessions",
        action="store_true",
        help="Only extract sessions (disables other sources)"
    )
    parser.add_argument(
        "--only-messages",
        action="store_true",
        help="Only extract messages (disables other sources)"
    )
    parser.add_argument(
        "--only-dumps",
        action="store_true",
        help="Only extract request dumps (disables other sources)"
    )
    parser.add_argument(
        "--only-logs",
        action="store_true",
        help="Only extract log files (disables other sources)"
    )

    return parser.parse_args()


def main():
    """Entry point: validate paths, build config, run extraction"""
    args = parse_args()

    # Resolve hermes home / state.db from --file, --dir or --hermes-home
    if args.file:
        state_db = args.file.expanduser().resolve()
        hermes_home = state_db.parent
    else:
        if args.dir:
            hermes_home = (args.dir.expanduser() / ".hermes").resolve()
        else:
            hermes_home = args.hermes_home.expanduser().resolve()
        state_db = hermes_home / "state.db"
        if not hermes_home.exists():
            print(f"Error: Hermes home not found: {hermes_home}", file=sys.stderr)
            sys.exit(1)
    if not state_db.exists():
        print(f"Error: state.db not found: {state_db}", file=sys.stderr)
        sys.exit(1)

    # Handle --list mode
    if args.list:
        config = ExtractionConfig(
            hermes_home=hermes_home,
            output_file=None,
            include_sessions=True,
            include_messages=False,
            include_model_usage=False,
            include_request_dumps=False,
            include_logs=False,
            session_filter=args.session_filter,
            source_filter=args.source_filter,
            start_time=args.start_time,
            end_time=args.end_time,
            limit=args.limit,
            pretty=args.pretty,
            state_db=state_db,
        )
        extractor = HermesForensicExtractor(config)
        try:
            sessions = extractor.list_sessions()
        finally:
            extractor.close()
        if not sessions:
            print("No sessions found", file=sys.stderr)
            return
        # Print as table
        print(f"{'SESSION ID':<50} {'SOURCE':<12} {'MODEL':<30} {'STARTED':<20} {'MESSAGES':>8}")
        print("-" * 130)
        for s in sessions:
            started = s.get("started_iso", "unknown")[:19] if s.get("started_iso") else "unknown"
            model = (s["model"] or "unknown")[:29]
            print(f"{s['id']:<50} {s['source']:<12} {model:<30} {started:<20} {s['message_count']:>8}")
        return

    # Handle presets
    include_sessions = not args.no_sessions
    include_messages = not args.no_messages
    include_model_usage = not args.no_model_usage
    include_request_dumps = not args.no_request_dumps
    include_logs = not args.no_logs

    if args.only_sessions:
        include_messages = include_model_usage = include_request_dumps = include_logs = False
    elif args.only_messages:
        include_sessions = include_model_usage = include_request_dumps = include_logs = False
    elif args.only_dumps:
        include_sessions = include_messages = include_model_usage = include_logs = False
    elif args.only_logs:
        include_sessions = include_messages = include_model_usage = include_request_dumps = False

    config = ExtractionConfig(
        hermes_home=hermes_home,
        output_file=args.output,
        include_sessions=include_sessions,
        include_messages=include_messages,
        include_model_usage=include_model_usage,
        include_request_dumps=include_request_dumps,
        include_logs=include_logs,
        session_filter=args.session_filter,
        source_filter=args.source_filter,
        start_time=args.start_time,
        end_time=args.end_time,
        limit=args.limit,
        pretty=args.pretty,
        state_db=state_db,
    )

    extractor = HermesForensicExtractor(config)
    try:
        stats = extractor.run()
    finally:
        extractor.close()

    # Print summary to stderr
    print("\nExtraction complete:", file=sys.stderr)
    for key, count in stats.items():
        print(f"  {key}: {count}", file=sys.stderr)
    print(f"  total: {sum(stats.values())}", file=sys.stderr)


if __name__ == "__main__":
    main()
