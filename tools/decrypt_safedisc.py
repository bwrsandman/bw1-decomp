#!/usr/bin/env python3
"""Produce the decompilation's source-of-truth executable from the SafeDisc
image shipped on the retail disc.

The disc ships runblack.exe wrapped in SafeDisc 2.x, which encrypts .text and
.data, hides the import directory and repoints the PE entry at its own stub.
This script unwraps it with sd2unpack and then restores the pristine MSVC 6.0
link.exe header shape, so dtk and lld only ever see linker output:

    orig/<ver>/runblack.exe               the disc image, SafeDisc-wrapped
      │  sd2unpack   (section cipher, import recovery, entry point, section drop)
      ▼
      │  restore_link_shape()   (exestr comments flush after the section table)
      ▼
    build/<ver>/runblack-decrypted.exe    the target the build must reproduce

Everything that varies per build is either derived from the inputs already in
this repository or read from the `safedisc:` block in config/<ver>/config.yml:

  * the real entry point comes from config/<ver>/symbols.txt (_WinMainCRTStartup)
    -- the decomp already knows where the program starts, so it is not key
    material and is not duplicated in the key file;
  * the image base, section layout and which sections are encrypted come from
    the encrypted executable's own headers;
  * the section cipher keys come from the `safedisc:` block in
    config/<ver>/config.yml, which pins the SHA-1 of the executable they belong
    to. tools/project.py strips that block from the copy of config.yml it
    generates for dtk, which has no field for it.

This replaces the old tools/pre_dtk_patch.py. That script existed to undo a
third-party decryptor's vandalism of the header padding -- removed SafeDisc
section headers, a cracker signature written into the freed space, and 24 bytes
zeroed off the front of the first exestr comment. Working from the encrypted
image there is no vandalism to undo: the comments are intact and complete, and
the hardcoded prefix that script carried is no longer needed.
"""

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import yaml

# Substring present in every Intel exestr comment ("Intel(R) C++ Compiler for
# 32-bit applications ..."). Used to pick the comment runs out of the header
# padding while leaving SafeDisc's own markers (the "BoG_" stamp near
# SizeOfHeaders) untouched.
COMMENT_CONTENT_MARKER = b"32-bit applications"

# The symbol whose address is the program's real entry point. SafeDisc repoints
# the PE entry at its own stub and records the real one nowhere in the file, but
# the decomp's symbol table has always known it.
ENTRY_SYMBOL = "_WinMainCRTStartup"

SD2UNPACK_ENV = "SD2UNPACK"


# --------------------------------------------------------------------------
# PE poking. Deliberately minimal -- just enough to find the header padding and
# the image base; sd2unpack does the real PE work.
# --------------------------------------------------------------------------

def _e_lfanew(data: bytes) -> int:
    return struct.unpack_from("<I", data, 0x3C)[0]


def image_base(data: bytes) -> int:
    """IMAGE_OPTIONAL_HEADER32.ImageBase."""
    return struct.unpack_from("<I", data, _e_lfanew(data) + 24 + 28)[0]


def section_table_end(data: bytes) -> int:
    """File offset just past the last section header."""
    e_lfanew = _e_lfanew(data)
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    return e_lfanew + 4 + 20 + size_opt + num_sections * 40


def size_of_headers(data: bytes) -> int:
    return struct.unpack_from("<I", data, _e_lfanew(data) + 24 + 60)[0]


def scan_runs(data: bytes, start: int, end: int):
    """Yield (offset, bytes) for each NUL-delimited printable run in [start,end)."""
    run_start = None
    for pos in range(start, end):
        printable = 0x20 <= data[pos] < 0x7F
        if printable and run_start is None:
            run_start = pos
        elif not printable and run_start is not None:
            yield run_start, data[run_start:pos]
            run_start = None
    if run_start is not None:
        yield run_start, data[run_start:end]


def section_alignment(data: bytes) -> int:
    return struct.unpack_from("<I", data, _e_lfanew(data) + 24 + 32)[0]


def file_alignment(data: bytes) -> int:
    return struct.unpack_from("<I", data, _e_lfanew(data) + 24 + 36)[0]


def sections(data: bytes):
    """The section table as a list of dicts, in table order."""
    e_lfanew = _e_lfanew(data)
    count = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    table = e_lfanew + 4 + 20 + struct.unpack_from("<H", data, e_lfanew + 20)[0]
    out = []
    for i in range(count):
        header = table + i * 40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, header + 8)
        out.append({
            "header": header,
            "name": data[header:header + 8].rstrip(b"\x00").decode("ascii", "replace"),
            "vsize": vsize,
            "va": va,
            "rawsize": rawsize,
            "rawptr": rawptr,
        })
    return out


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def compact_dropped_sections(data: bytes) -> bytes:
    """Close the holes SafeDisc's own sections left behind.

    SafeDisc does not append its sections, it *inserts* them: `.data1` and
    `SELFMOD` sit between `.data` and `.rsrc`, which pushes `.rsrc` up by one
    page per inserted section in both the virtual and the file layout. The
    counts differ per build -- 1.0 got only `SELFMOD` (0x1000), 1.1 and 1.2 got
    both (0x2000) -- which is how we know the shift is SafeDisc's and not
    link.exe's: one linker does not place the same section three different ways
    in three builds of the same program.

    sd2unpack drops the inserted section *headers* but leaves the file alone, so
    its output has `.rsrc` still sitting at SafeDisc's address with a zeroed,
    unreferenced hole in front of it. link.exe never emits such a hole and lld
    cannot reproduce one, so the hole has to go: every section is repacked
    contiguously at its alignment, exactly where link.exe would have put it.

    Only trailing sections may move. If compaction would shift a section that
    holds code or relocatable data we bail instead, because there is no `.reloc`
    left to fix up the references.
    """
    sec_align = section_alignment(data)
    file_align = file_alignment(data)
    old = sections(data)
    if not old:
        return data

    # Repack: each section lands immediately after its predecessor, aligned.
    moves = []
    next_va, next_rawptr = old[0]["va"], old[0]["rawptr"]
    for sec in old:
        new_va = _align(next_va, sec_align)
        new_rawptr = _align(next_rawptr, file_align)
        moves.append({
            "sec": sec,
            "new_va": new_va,
            "new_rawptr": new_rawptr,
            "va_delta": sec["va"] - new_va,
            "raw_delta": sec["rawptr"] - new_rawptr,
        })
        next_va = new_va + sec["vsize"]
        next_rawptr = new_rawptr + sec["rawsize"]

    if all(m["va_delta"] == 0 and m["raw_delta"] == 0 for m in moves):
        return data

    for move in moves:
        if move["va_delta"] and move["sec"]["name"] in (".text", ".rdata", ".data"):
            raise SystemExit(
                f"refusing to move {move['sec']['name']} by {move['va_delta']:#x}: "
                f"code and relocatable data must stay put, and there is no .reloc "
                f"to fix up the references"
            )

    # Rebuild the file from the section payloads, which drops the holes between
    # them. Whatever trails the last section (link.exe's CodeView record) is kept.
    old_end = old[-1]["rawptr"] + old[-1]["rawsize"]
    out = bytearray(data[:old[0]["rawptr"]])
    for move in moves:
        sec = move["sec"]
        assert len(out) == move["new_rawptr"], "section repack lost alignment"
        out += data[sec["rawptr"]:sec["rawptr"] + sec["rawsize"]]
    tail_delta = old_end - len(out)
    out += data[old_end:]

    def remap_rva(rva: int) -> int:
        for move in moves:
            sec = move["sec"]
            span = _align(max(sec["vsize"], sec["rawsize"]), sec_align)
            if sec["va"] <= rva < sec["va"] + span:
                return rva - move["va_delta"]
        return rva

    def remap_file_offset(offset: int) -> int:
        for move in moves:
            sec = move["sec"]
            if sec["rawptr"] <= offset < sec["rawptr"] + sec["rawsize"]:
                return offset - move["raw_delta"]
        return offset - tail_delta if offset >= old_end else offset

    def file_offset_of(rva: int) -> "int | None":
        for move in moves:
            sec = move["sec"]
            if move["new_va"] <= rva < move["new_va"] + sec["rawsize"]:
                return move["new_rawptr"] + (rva - move["new_va"])
        return None

    for move in moves:
        struct.pack_into("<I", out, move["sec"]["header"] + 12, move["new_va"])
        struct.pack_into("<I", out, move["sec"]["header"] + 20, move["new_rawptr"])

    e_lfanew = _e_lfanew(out)
    last = moves[-1]
    struct.pack_into("<I", out, e_lfanew + 24 + 56,
                     _align(last["new_va"] + last["sec"]["vsize"], sec_align))

    # Data directories. Index 4 (certificate) is a file offset, not an RVA.
    dir_count = struct.unpack_from("<I", out, e_lfanew + 24 + 92)[0]
    dirs = e_lfanew + 24 + 96
    for i in range(dir_count):
        rva = struct.unpack_from("<I", out, dirs + i * 8)[0]
        if rva and i != 4:
            struct.pack_into("<I", out, dirs + i * 8, remap_rva(rva))

    _remap_resource_rvas(out, moves, remap_rva, file_offset_of)
    _remap_debug_records(out, dirs, remap_rva, remap_file_offset, file_offset_of)
    return bytes(out)


def _remap_resource_rvas(out: bytearray, moves, remap_rva, file_offset_of) -> None:
    """Rewrite every IMAGE_RESOURCE_DATA_ENTRY.OffsetToData, which is an RVA."""
    rsrc = next((m for m in moves if m["sec"]["name"] == ".rsrc"), None)
    if rsrc is None or rsrc["va_delta"] == 0:
        return
    base = rsrc["new_rawptr"]

    def walk(offset: int, depth: int = 0) -> None:
        if depth > 3:
            return
        named, ids = struct.unpack_from("<HH", out, base + offset + 12)
        for i in range(named + ids):
            entry = base + offset + 16 + i * 8
            _name, child = struct.unpack_from("<II", out, entry)
            if child & 0x80000000:
                walk(child & 0x7FFFFFFF, depth + 1)
            else:
                slot = base + child
                struct.pack_into("<I", out, slot,
                                 remap_rva(struct.unpack_from("<I", out, slot)[0]))

    walk(0)


def _remap_debug_records(out: bytearray, dirs: int, remap_rva, remap_file_offset,
                         file_offset_of) -> None:
    """Fix the debug records' pointers at the CodeView blob after the sections."""
    rva, size = struct.unpack_from("<II", out, dirs + 6 * 8)
    if not rva or not size:
        return
    start = file_offset_of(rva)
    if start is None:
        raise SystemExit(f"debug directory RVA {rva:#x} is not inside any section")
    for record in range(start, start + size, 28):
        address = struct.unpack_from("<I", out, record + 20)[0]
        pointer = struct.unpack_from("<I", out, record + 24)[0]
        if address:
            struct.pack_into("<I", out, record + 20, remap_rva(address))
        if pointer:
            struct.pack_into("<I", out, record + 24, remap_file_offset(pointer))


def restore_link_shape(data: bytes) -> bytes:
    """Put the exestr comments back where link.exe emitted them.

    MSVC's Intel-compiled objects carry `#pragma comment(exestr, "...")`, which
    link.exe embeds flush after the section table in the header padding (gap 0,
    verified against link.exe output). Nothing in the PE references it.

    SafeDisc inserted two section headers (stxt774, stxt371) after the section
    table, shoving the comments forward by 2 * 40 = 0x50. sd2unpack drops those
    two headers but leaves the padding bytes where they lay, so its output has
    the comments stranded 0x50 past the shortened table -- neither where the
    linker put them nor where SafeDisc did. Move them back and zero the rest.

    1.0 has no exestr comments at all: its header padding held nothing but
    SafeDisc's own stamp, which sd2unpack already strips, leaving the padding
    zeroed. Nothing to move, so the image is returned untouched.
    """
    ste = section_table_end(data)
    soh = size_of_headers(data)

    comments = [
        run for _, run in scan_runs(data, ste, soh) if COMMENT_CONTENT_MARKER in run
    ]
    if not comments:
        return data

    block = b"".join(c + b"\x00" for c in comments)
    if ste + len(block) > soh:
        raise SystemExit(f"exestr comments ({len(block)} bytes) overflow SizeOfHeaders")

    out = bytearray(data)
    out[ste:soh] = b"\x00" * (soh - ste)
    out[ste:ste + len(block)] = block
    return bytes(out)


# --------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------

def read_entry_point(symbols: Path, base: int) -> int:
    """The real entry-point RVA, from the decomp's own symbol table."""
    pattern = re.compile(
        r"^" + re.escape(ENTRY_SYMBOL) + r"\s*=\s*\.\w+:0x([0-9A-Fa-f]+)\s*;"
    )
    with symbols.open() as fh:
        for line in fh:
            match = pattern.match(line)
            if match:
                va = int(match.group(1), 16)
                if va < base:
                    raise SystemExit(
                        f"{symbols}: {ENTRY_SYMBOL} at {va:#x} is below the image "
                        f"base {base:#x}"
                    )
                return va - base
    raise SystemExit(f"{symbols}: no {ENTRY_SYMBOL} symbol -- cannot derive the entry point")


def find_sd2unpack(explicit: "str | None") -> str:
    """Locate the sd2unpack binary.

    Checked in order: --sd2unpack, $SD2UNPACK, PATH, then a sibling checkout of
    the Safedisc2Cleaner repository next to this one.
    """
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get(SD2UNPACK_ENV):
        candidates.append(Path(os.environ[SD2UNPACK_ENV]))

    found = shutil.which("sd2unpack")
    if found:
        candidates.append(Path(found))

    repo_root = Path(__file__).resolve().parent.parent
    for profile in ("release", "debug"):
        candidates.append(
            repo_root.parent / "Safedisc2Cleaner" / "sd2unpack" / "target" / profile / "sd2unpack"
        )

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    raise SystemExit(
        "sd2unpack not found. Build it from the Safedisc2Cleaner repository\n"
        "  (cd sd2unpack && cargo build --release)\n"
        f"then put it on PATH or point ${SD2UNPACK_ENV} at the binary.\n"
        "Tried: " + ", ".join(str(c) for c in candidates)
    )


def key_flags(cfg: dict, version: str) -> "list[str]":
    """Translate the config.yml `safedisc:` block into sd2unpack's key flags."""
    profile = cfg.get("profile")
    keys = cfg.get("keys") or {}
    flags = ["--profile", profile]

    if profile == "sd2tea":
        # 2.1x / 2.3x: one 16-byte section key, and the import scheme derives
        # its own keystream from the file.
        if "tea" not in keys:
            raise SystemExit(f"{version}: profile sd2tea needs keys.tea")
        flags += ["--tea-key", keys["tea"]]
    elif profile == "sd260":
        # 2.60: three session keys per encrypted section plus a shared register.
        if "iv" not in keys:
            raise SystemExit(f"{version}: profile sd260 needs keys.iv")
        flags += ["--iv", keys["iv"]]
        sections = keys.get("sections") or {}
        if not sections:
            raise SystemExit(f"{version}: profile sd260 needs keys.sections")
        for name, trio in sections.items():
            if len(trio) != 3:
                raise SystemExit(
                    f"{version}: keys.sections.{name} needs exactly three keys, got {len(trio)}"
                )
            flags += ["--section-keys", name, *trio]
    else:
        raise SystemExit(f"{version}: unknown SafeDisc profile {profile!r}")

    return flags


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", required=True, help="e.g. BW1W120")
    ap.add_argument("--sd2unpack", help="path to the sd2unpack binary")
    ap.add_argument("input", type=Path, help="orig/<ver>/runblack.exe")
    ap.add_argument("output", type=Path, help="build/<ver>/runblack-decrypted.exe")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show sd2unpack's report")
    args = ap.parse_args()

    config_dir = Path("config") / args.version
    config_file = config_dir / "config.yml"
    if not config_file.is_file():
        raise SystemExit(f"{config_file}: not found (run from the repository root)")
    cfg = (yaml.safe_load(config_file.read_text()) or {}).get("safedisc")
    if not cfg:
        raise SystemExit(
            f"{config_file}: no `safedisc:` block -- no SafeDisc key material for "
            f"{args.version}"
        )

    if not args.input.is_file():
        raise SystemExit(
            f"{args.input}: not found. Copy the SafeDisc-protected runblack.exe from\n"
            f"your own disc or install into orig/{args.version}/. See docs/getting_started.md."
        )

    encrypted = args.input.read_bytes()
    base = image_base(encrypted)
    oep = read_entry_point(config_dir / "symbols.txt", base)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw = args.output.with_suffix(".sd2unpack.exe")

    cmd = [
        find_sd2unpack(args.sd2unpack),
        str(args.input),
        "--expect-sha1", cfg["expect_sha1"],
        "--oep", hex(oep),
        *key_flags(cfg, args.version),
        "-o", str(raw),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    report = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        # sd2unpack still writes the file when it is unusable ("UNUSABLE" plus a
        # nonzero exit), so make sure a bad decryption cannot be mistaken for a
        # good one by a later build step.
        sys.stderr.write(report)
        raw.unlink(missing_ok=True)
        return result.returncode

    if args.verbose:
        sys.stderr.write(report)
    else:
        # Keep build logs short, but never swallow a warning -- the head import
        # of a single-entry stolen DLL can only be assigned by position, and
        # sd2unpack says so rather than pretending it is proven. (It repeats
        # each warning in its closing summary; print it once.)
        for line in report.splitlines():
            if line.startswith("warning:"):
                sys.stderr.write(line + "\n")

    try:
        unpacked = raw.read_bytes()
        args.output.write_bytes(restore_link_shape(compact_dropped_sections(unpacked)))
    finally:
        raw.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
