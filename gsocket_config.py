#!/usr/bin/env python3
"""Extract the gsocket / gs-netcat configuration embedded in an ELF.

gs-netcat (beta branch of https://github.com/hackerschoice/gsocket) can store a
664-byte `struct gsnc_config` in the last bytes of its own executable.  At run
time `GSNC_config_read()` seeks to `SEEK_END - sizeof(cfg)`, XORs the block with
0xAB and validates an 8-byte magic.

The blob carries the operator's relay host, port, secret and the process name the
implant masquerades as -- the highest-value indicators in a gsocket intrusion.

Note the config is appended *after* UPX packing, so it lives at the end of the
packed file.  Unpacking first will lose it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys

__version__ = "1.0.0"

# tools/gsnc-utils.h
MAGIC_STR = b"8xKd12TX"
MAGIC_XOR = 0x1F
BLOB_XOR = 0xAB
CONFIG_SIZE = 0x298                      # sizeof(struct gsnc_config) == 664
MAGIC_OFF = 0x290
# What the magic looks like on disk: MAGIC_STR ^ MAGIC_XOR ^ BLOB_XOR
MAGIC_ON_DISK = bytes(b ^ MAGIC_XOR ^ BLOB_XOR for b in MAGIC_STR)

# (offset, size) of each char[] field, in declaration order.
STR_FIELDS = [
    ("host", 0x000, 128),
    ("proc_hiddenname", 0x080, 64),
    ("sec_str", 0x0D0, 64),
    ("shell", 0x110, 64),
    ("domain", 0x150, 64),
    ("workdir", 0x190, 64),
    ("systemd_argv_match", 0x1D0, 64),
    ("bail", 0x210, 128),
]

# tools/common.h -- GSC_FL_*
FLAGS = [
    (0x000001, "IS_SERVER"),            (0x000002, "IS_STEALTH"),
    (0x000004, "SELF_WATCHDOG"),        (0x000008, "OPT_G"),
    (0x000010, "OPT_SEC"),              (0x000020, "OPT_TOR"),
    (0x000040, "OPT_DAEMON"),           (0x000080, "OPT_WATCHDOG_INTERNAL"),
    (0x000100, "OPT_QUIET"),            (0x000200, "OPT_SOCKS_SERVER"),
    (0x000400, "WANT_CONFIG_READ"),     (0x000800, "CONFIG_CHECK"),
    (0x001000, "FFPID"),                (0x002000, "CONFIG_READ_OK"),
    (0x004000, "CHANGE_CGROUP"),        (0x008000, "DELME"),
    (0x010000, "USEHOSTID"),            (0x020000, "STARTED_BY_SWD"),
    (0x040000, "SWD_SURVIVED_SIGTERM"), (0x080000, "REEXEC"),
    (0x100000, "OPT_WAITFOR_SERVER"),   (0x200000, "DAEMONIZE"),
    (0x400000, "MEMEXEC"),
]


class NotFound(Exception):
    pass


def _cstr(blob: bytes, off: int, size: int) -> str:
    return blob[off:off + size].split(b"\x00")[0].decode("utf-8", "replace")


def decode_flags(value: int):
    names = [name for bit, name in FLAGS if value & bit]
    unknown = value & ~sum(bit for bit, _ in FLAGS)
    if unknown:
        names.append(f"UNKNOWN_0x{unknown:x}")
    return names


def find_config(data: bytes) -> tuple[bytes, int]:
    """Return (decoded 664-byte blob, file offset). Tail first, then a full scan."""
    candidates = []
    if len(data) >= CONFIG_SIZE:
        candidates.append(len(data) - CONFIG_SIZE)
    pos = 0
    while True:
        hit = data.find(MAGIC_ON_DISK, pos)
        if hit < 0:
            break
        start = hit - MAGIC_OFF
        if start >= 0 and start not in candidates:
            candidates.append(start)
        pos = hit + 1

    for start in candidates:
        blob = bytes(b ^ BLOB_XOR for b in data[start:start + CONFIG_SIZE])
        if len(blob) == CONFIG_SIZE and \
           blob[MAGIC_OFF:MAGIC_OFF + 8] == bytes(b ^ MAGIC_XOR for b in MAGIC_STR):
            return blob, start
    raise NotFound("no valid gsocket config blob found")


def parse_config(blob: bytes, offset: int) -> dict:
    port, = struct.unpack_from("<H", blob, 0x0C0)
    callhome, delay, flags = struct.unpack_from("<iiI", blob, 0x0C4)
    cfg = {"_offset": offset, "port": port, "callhome_sec": callhome,
           "start_delay_sec": delay, "flags": flags,
           "flags_decoded": decode_flags(flags)}
    for name, off, size in STR_FIELDS:
        cfg[name] = _cstr(blob, off, size)
    return cfg


def report(cfg: dict, path: str, sha: str) -> str:
    lines = [f"[*] {path}", f"    sha256 {sha}",
             f"[+] config found at offset 0x{cfg['_offset']:X}", ""]
    order = [("host (GSRN relay)", "host"), ("port", "port"),
             ("secret", "sec_str"), ("proc_hiddenname", "proc_hiddenname"),
             ("shell", "shell"), ("domain", "domain"), ("workdir", "workdir"),
             ("systemd_argv_match", "systemd_argv_match"), ("bail", "bail"),
             ("callhome_sec", "callhome_sec"), ("start_delay_sec", "start_delay_sec")]
    for label, key in order:
        value = cfg[key]
        if value in ("", 0):
            continue
        lines.append(f"    {label:<20} {value}")
    lines.append(f"    {'flags':<20} 0x{cfg['flags']:08x}"
                 f"  {' | '.join(cfg['flags_decoded']) or '(none)'}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract the gsocket/gs-netcat config embedded in an ELF.")
    ap.add_argument("file", help="ELF to inspect (use the UPX-packed file, not the unpacked one)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--raw", metavar="PATH", help="also dump the decoded 664-byte blob")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    try:
        data = open(args.file, "rb").read()
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        blob, offset = find_config(data)
    except NotFound as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    cfg = parse_config(blob, offset)
    if args.raw:
        with open(args.raw, "wb") as fh:
            fh.write(blob)

    if args.json:
        cfg["_file"] = args.file
        cfg["_sha256"] = hashlib.sha256(data).hexdigest()
        print(json.dumps(cfg, indent=2))
    else:
        print(report(cfg, args.file, hashlib.sha256(data).hexdigest()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
