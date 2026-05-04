#!/usr/bin/env python3
"""Calculate MD5, SHA1, SHA256, SHA512, SHA3-224, and SHA3-384 hashes of files."""
#
# Rewrite of my perl sigs script in python.
# Calculate hashes of files
#
# Author: Jim Clausing
# Date: 2026-03-17
# Version: 1.8.0

from __future__ import print_function
import sys
import os
import argparse
import hashlib
import base64
import contextlib
import codecs
import signal
from collections import namedtuple

if sys.version_info < (3, 6):
    import sha3  # pylint: disable=import-error,unused-import

__version_info__ = (1, 9, 1)
__version__ = ".".join(map(str, __version_info__))

# Single source of truth for supported hash algorithms.
# digest_len is the length of the formatted (hex or base64) digest string,
# used by check_hashes() to identify the algorithm from a hash-file line.
HashSpec = namedtuple(
    "HashSpec",
    "arg_attr psv_header verbose_label factory format_fn digest_len",
)


def _hex(h):
    """Return hex digest of a hashlib object."""
    return h.hexdigest()


def _b64(h):
    """Return base64-encoded digest of a hashlib object (used for SHA512)."""
    return codecs.decode(base64.b64encode(h.digest()))


HASH_SPECS = (
    HashSpec("md5",      "md5",      "  MD5:  ",     hashlib.md5,      _hex, 32),
    HashSpec("sha1",     "sha1",     "  SHA1: ",     hashlib.sha1,     _hex, 40),
    HashSpec("sha256",   "sha256",   "  SHA256: ",   hashlib.sha256,   _hex, 64),
    HashSpec("sha512",   "sha512",   "  SHA512: ",   hashlib.sha512,   _b64, 88),
    HashSpec("sha3_224", "sha3-224", "  SHA3-224: ", hashlib.sha3_224, _hex, 56),
    HashSpec("sha3",     "sha3-384", "  SHA3-384: ", hashlib.sha3_384, _hex, 96),
)

args = None  # pylint: disable=invalid-name


@contextlib.contextmanager
def smart_open(filepath=None):
    """Open a file for binary reading, or yield stdin.buffer if no path given."""
    if filepath and filepath != "-":
        fh = open(filepath, "rb")
    else:
        fh = sys.stdin.buffer

    try:
        yield fh
    finally:
        if fh is not sys.stdin.buffer:
            fh.close()


def selected_specs():
    """Return the list of HASH_SPECS the user has selected via args."""
    return [s for s in HASH_SPECS if getattr(args, s.arg_attr) or args.all]


def print_header():
    """Print PSV column headers for selected hash types."""
    for spec in selected_specs():
        sys.stdout.write(spec.psv_header + "|")
    print("filename")
    sys.stdout.flush()


def hash_file(fname):  # pylint: disable=redefined-outer-name
    """Compute selected hashes for fname (or '-' for stdin).

    Returns a dict {arg_attr: hash_obj} on success, or None on IO/permission
    error. For regular files, stat() is captured before and after reading;
    a warning is printed to stderr if size or mtime changed mid-read.
    """
    hashes = {spec.arg_attr: spec.factory() for spec in selected_specs()}
    stat_before = None
    if fname and fname != "-":
        try:
            stat_before = os.stat(fname)
        except OSError:
            pass
    try:
        with smart_open(fname) as f:
            for block in iter(lambda: f.read(args.block), b""):
                for h in hashes.values():
                    h.update(block)
    except (IOError, PermissionError):
        return None
    if stat_before is not None:
        try:
            stat_after = os.stat(fname)
            if (stat_before.st_size != stat_after.st_size
                    or stat_before.st_mtime_ns != stat_after.st_mtime_ns):
                print(
                    f"{sys.argv[0]}: {fname}: file changed during hashing "
                    f"(size {stat_before.st_size} -> {stat_after.st_size}, "
                    f"mtime {stat_before.st_mtime_ns} -> {stat_after.st_mtime_ns})",
                    file=sys.stderr,
                )
        except OSError:
            pass
    return hashes

def print_hashes(fname, hashes):  # pylint: disable=redefined-outer-name
    """Print computed hashes for fname in the selected output format.

    `hashes` is the dict returned by hash_file(), or None on permission/IO error
    (in which case "(Permission Problem)" is substituted for each digest).
    """
    specs = selected_specs()
    perm_fail = hashes is None

    def digest(spec):
        return "(Permission Problem)" if perm_fail else spec.format_fn(hashes[spec.arg_attr])

    if len(specs) == 1:
        spec = specs[0]
        suffix = fname if fname != "-" else ""
        print(f"{digest(spec)}  {suffix}")
    elif args.psv:
        for spec in specs:
            sys.stdout.write(digest(spec) + "|")
        print(fname)
    else:
        if fname != "-":
            print(fname + ":")
        for spec in specs:
            print(spec.verbose_label + digest(spec))
    sys.stdout.flush()


def count_hashes():
    """Return how many hash types are selected."""
    return len(selected_specs())

def check_hashes():
    """Read hash-file(s) from args.files and verify each listed file.

    Algorithm is inferred from digest length. Lengths are unambiguous within
    the set this script supports; SHA3-256/SHA3-512 are not supported, so
    SHA3-224 (56) and SHA3-384 (96) are the only SHA3 variants in play.
    """
    failures = 0
    for fpath in args.files:
        if os.path.isfile(fpath) or fpath == "-":
            with smart_open(fpath) as f:
                for line in f:
                    try:
                        line = line.decode('utf-8')
                    except UnicodeDecodeError as exc:
                        print(
                            f"{sys.argv[0]}: skipping line with encoding error: {exc}",
                            file=sys.stderr,
                        )
                        continue
                    line = line.strip('\n')
                    parts = str(line).split("  ")
                    if len(parts) < 2 or not parts[1].strip():
                        continue
                    spec = next(
                        (s for s in HASH_SPECS if s.digest_len == len(parts[0])),
                        None,
                    )
                    if spec is None:
                        continue
                    if not os.path.isfile(parts[1]):
                        print(parts[1], ": File not found")
                        failures += 1
                        continue
                    setattr(args, spec.arg_attr, True)
                    hashes = hash_file(parts[1])
                    if hashes is None or parts[0] != spec.format_fn(hashes[spec.arg_attr]):
                        print(parts[1] + ": FAILED")
                        failures += 1
                    else:
                        print(parts[1] + ": OK")
        sys.stdout.flush()
    if failures > 0:
        print(sys.argv[0] + ": WARNING: " + str(failures) + " checksums did not match")
        sys.exit(255)


if __name__ == "__main__":
    # restore default SIGPIPE behavior so piping to head/less doesn't traceback
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    # define switches and commandline arguments
    parser = argparse.ArgumentParser(description="Calculate hashes")
    parser.add_argument("files", metavar="FILE", nargs="*", default=["-"], help="files to hash")
    parser.add_argument(
        "-V", "--version", action="version",
        help="print version number", version="%(prog)s v" + __version__
    )
    parser.add_argument(
        "-r", "--recursive", action="store_true",
        help="recursive mode. All subdirectories are traversed"
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="All (MD5, SHA1, SHA256, SHA512, and SHA3-384), default if no other options chosen",
    )
    parser.add_argument(
        "-m", "--md5", action="store_true", help="MD5 signature (md5sum equivalent output)"
    )
    parser.add_argument(
        "-s", "--sha1", action="store_true", help="SHA1 signature (sha1sum equivalent output)"
    )
    parser.add_argument(
        "-2", "--sha256", action="store_true",
        help="SHA2 (aka SHA2-256) signature (sha256sum equivalent output)"
    )
    parser.add_argument("-3", "--sha3", action="store_true", help="SHA3-384 signature")
    parser.add_argument("-t", "--sha3_224", action="store_true", help="SHA3-224 signature")
    parser.add_argument(
        "-5",
        "--sha512",
        action="store_true",
        help="SHA512 (aka SHA2-512) signature (note: base64 encoded rather than hex)",
    )
    parser.add_argument(
        "-f", "--fullpath", action="store_true", help="print full path rather than relative"
    )
    parser.add_argument(
        "-B", "--block", metavar="blk", type=int, default=65536,
        help="block size to read file, default = 65536"
    )
    parser.add_argument(
        "-c", "--check", action="store_true", help="read sums from FILE and check them"
    )
    #parser.add_argument("-b", "--base", action="store_true",
    #                    help="match only basename, only valid with -c")
    parser.add_argument(
        "-p", "--psv", action="store_true", help="write output as pipe separated values"
    )
    args = parser.parse_args()

    if args.block <= 0:
        parser.error("block size must be > 0")

    # default to --all only when no specific hash switch and not in check mode
    any_hash = args.md5 or args.sha1 or args.sha256 or args.sha3 or args.sha3_224 or args.sha512
    if any_hash or args.check:
        args.all = False
    elif not args.all:
        args.all = True
    #if args.base and not args.check:
    #    print("-b not valid without -c")
    #    sys.exit(255)

    if args.psv:
        print_header()

    if args.check:
        check_hashes()
        sys.exit(0)

    # process commandline arguments
    # pylint: disable=invalid-name
    had_error = False
    for path in args.files:
        if os.path.isdir(os.path.abspath(path)) and args.recursive:
            if args.fullpath:
                path = os.path.abspath(path)
            for root, directories, filenames in os.walk(path):
                for filename in filenames:
                    fname = os.path.join(root, filename)
                    if os.path.isfile(fname):
                        result = hash_file(fname)
                        if result is None:
                            had_error = True
                        print_hashes(fname, result)
        else:
            if os.path.isfile(path) or path == "-":
                result = hash_file(path)
                if result is None:
                    had_error = True
                print_hashes(path, result)
            else:
                print(f"{sys.argv[0]}: {path}: No such file or directory", file=sys.stderr)
                had_error = True

    sys.exit(1 if had_error else 0)
