# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A collection of security/forensics scripts by Jim Clausing (SANS Internet Storm Center Handler). Scripts are standalone CLI tools — no build system, package structure, or test suite.

## Linting

Python scripts are linted with pylint using the project `pylintrc`:

```bash
pylint <script.py>
```

## Script Conventions

**Python scripts follow this header pattern:**
```python
__description__ = 'Short description'
__author__ = 'Jim Clausing'
__version__ = 'X.Y.Z'
__date__ = 'YYYY-MM-DD'
```

- Use `argparse` with `-V/--version` flag (always present)
- Version tuple pattern: `__version_info__ = (X, Y, Z)` then `__version__ = ".".join(map(str, __version_info__))`
- Scripts flush stdout explicitly (`sys.stdout.flush()`) for pipeline use
- Pipe-separated values (PSV) is the preferred output format for structured data

## Key Scripts

- **`sigs.py`** — Hash calculator (MD5, SHA1, SHA256, SHA512, SHA3-224, SHA3-384). Requires `pysha3` or Python ≥ 3.6.
- **`ficheck.py`** — File integrity checker. Uses `&`-delimited CSV database at `/var/lib/ficheck/ficheck.db`. Config at `/etc/ficheck/ficheck.cfg`. Optionally uses `statx` module for birth time. Install via `ficheck-install.sh`.
- **`convert-ts-bash-history.py`** — Converts `.bash_history` files (with `#<epoch>` timestamps) to `filename|ISO-8601|command` format. Use `-f` to suppress filename column.
- **`mail_stuff.py`** — Email helper used by ficheck cron job.

## ficheck Architecture

`ficheck.py` operates in two modes controlled by flags:
- `-u` (update): walks directories per config, writes new DB to `/run/ficheck.db.new`, moves to `/var/lib/ficheck/ficheck.db`
- `-r` (report): compares old vs new DB and prints additions/deletions/modifications

Config (`ficheck.cfg`) uses `Directory=` and `Exclusion=` keys; if a path appears in both, `Exclusion=` takes precedence.
