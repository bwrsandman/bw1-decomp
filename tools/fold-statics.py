#!/usr/bin/env python3
"""Fold a recompiled unit's static (file-local) functions the way an /OPT:ICF link did.

Built with /Gy, a static function is a COMDAT like any other, and link.exe's /OPT:ICF folds
identical ones across units onto one copy. Creature Isle's LHaudiodllR.dll keeps one
`LHLogDebugBreak` (the static of the LHFile and LHAudio log macro headers), LHOSFile's; every
other unit calls that one. The split names it with `scope:global`, so the split objects reference
it by name. `dtk coff fold` runs first and folds COMDATs onto the image's global aliases only. It
also makes nothing global, so a compiled unit that holds the kept copy defines it as static. This
pass, run after it on the units of an ICF link (config.icf_links), finishes the job for the
functions configure.py lists in config.icf_static_folds: the name alone does not tell such a fold
from a static that merely shares the name of another unit's global function. Take a listed static
function whose name the module's symbols.txt gives a global function:

- if that function lies in this unit's split ranges, this unit holds the kept copy: make it
  external, so the other units' references resolve to it;
- otherwise drop this unit's copy onto it, as `dtk coff fold` does (the symbol becomes an
  undefined external, its section a non-COMDAT LNK_REMOVE section that is not linked).

    python tools/fold-statics.py OBJ --symbols config/V/M/symbols.txt --splits config/V/M/splits.txt --unit U \
        --function NAME [--function NAME ...]
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import symbols_txt  # noqa: E402

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_DTYPE_FUNCTION = 0x20
IMAGE_SCN_LNK_REMOVE = 0x800
IMAGE_SCN_LNK_COMDAT = 0x1000

RANGE_RE = re.compile(r"^\s+(\S+)\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)")


def unit_ranges(splits_path, unit):
    ranges = []
    current = None
    for line in Path(splits_path).read_text().splitlines():
        if line and not line[0].isspace():
            current = line.rstrip(":")
            continue
        m = RANGE_RE.match(line)
        if m and current == unit:
            ranges.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16)))
    return ranges


def global_functions(symbols_path, names):
    functions = {}
    for sym in symbols_txt.parse(Path(symbols_path).read_text()):
        if sym.name not in names:
            continue
        fields = symbols_txt.split_attrs(sym.attrs) or {}
        if sym.is_extern or sym.is_alias or fields.get("type") != "function" or fields.get("scope") != "global":
            continue
        functions.setdefault(sym.name, []).append((sym.section, sym.addr))
    return functions


def fold(path, functions, ranges):
    data = bytearray(Path(path).read_bytes())
    nsections = struct.unpack_from("<H", data, 2)[0]
    symoff, nsyms = struct.unpack_from("<II", data, 8)
    section_headers = 20 + struct.unpack_from("<H", data, 16)[0]
    strings = symoff + nsyms * 18
    globalized = dropped = 0
    i = 0
    while i < nsyms:
        offset = symoff + i * 18
        if data[offset : offset + 4] == b"\0\0\0\0":
            start = strings + struct.unpack_from("<I", data, offset + 4)[0]
            name = data[start : data.index(b"\0", start)].decode()
        else:
            name = bytes(data[offset : offset + 8]).rstrip(b"\0").decode()
        _, section, sym_type, sym_class, naux = struct.unpack_from("<IhHBB", data, offset + 8)
        if (
            sym_class == IMAGE_SYM_CLASS_STATIC
            and sym_type == IMAGE_SYM_DTYPE_FUNCTION
            and 0 < section <= nsections
            and len(functions.get(name, ())) == 1
        ):
            header = section_headers + (section - 1) * 40
            flags = struct.unpack_from("<I", data, header + 36)[0]
            if flags & IMAGE_SCN_LNK_COMDAT:
                image_section, addr = functions[name][0]
                if any(s == image_section and start <= addr < end for s, start, end in ranges):
                    data[offset + 16] = IMAGE_SYM_CLASS_EXTERNAL
                    globalized += 1
                else:
                    struct.pack_into("<IhHB", data, offset + 8, 0, 0, sym_type, IMAGE_SYM_CLASS_EXTERNAL)
                    flags = (flags & ~IMAGE_SCN_LNK_COMDAT) | IMAGE_SCN_LNK_REMOVE
                    struct.pack_into("<I", data, header + 36, flags)
                    dropped += 1
        i += 1 + naux
    if globalized or dropped:
        Path(path).write_bytes(data)
    return globalized, dropped


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("object", help="folded COFF object, rewritten in place")
    parser.add_argument("--symbols", required=True, help="the module's symbols.txt")
    parser.add_argument("--splits", required=True, help="the module's splits.txt")
    parser.add_argument("--unit", required=True, help="splits.txt unit the object was compiled from")
    parser.add_argument(
        "--function", action="append", required=True, help="mangled name of a static function to fold (repeatable)"
    )
    args = parser.parse_args()
    functions = global_functions(args.symbols, set(args.function))
    globalized, dropped = fold(args.object, functions, unit_ranges(args.splits, args.unit))
    if globalized or dropped:
        print(f"{args.object}: made {globalized} static function(s) global, dropped {dropped} onto the image's copy")


if __name__ == "__main__":
    main()
