#!/usr/bin/env python3

"""
Post-link patch script.
Applies version-specific binary fixups to the relinked executable,
producing the final output that is verified against build.sha1.

Usage (called by ninja automatically):
  python3 tools/post_link_patch.py --version BW1W100 <input.exe> <output.exe>
"""

import argparse
import json
import struct
import yaml
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import NamedTuple

import pefile


class RichProductID(IntEnum):
    IMPORT_OLD   = 0x0000  # pre-VC97 object with no product info
    IMPORT       = 0x0001  # object with no product info
    LINKER510    = 0x0002  # link.exe 5.10
    CVTOMF510    = 0x0003  # cvtomf.exe 5.10
    LINKER600    = 0x0004  # link.exe 6.00 (VS98)
    CVTOMF600    = 0x0005  # cvtomf.exe 6.00
    CVTRES       = 0x0006  # cvtres.exe (VS97/VS98)
    UTC11_BASIC  = 0x0007
    UTC11_C      = 0x0008
    UTC12_BASIC  = 0x0009
    UTC12_C      = 0x000A  # cl.exe C (VS98)
    UTC12_CPP    = 0x000B  # cl.exe C++ (VS98)
    ALIAS_OBJ    = 0x000C  # aliasobj.exe
    VBSCRIPT     = 0x000D
    MASM613      = 0x000E  # masm.exe 6.13
    MASM710      = 0x000F
    LINKER700    = 0x0010
    CVTOMF700    = 0x0011
    MASM614      = 0x0012
    LINKER600SP5 = 0x0013  # link.exe 6.00 SP5
    IMPORT_VS2002 = 0x0019  # VS2002 (7.0) import library record
    UTC70_C      = 0x001C  # cl.exe C (VS2002 .NET, build 9466)
    UTC70_CPP    = 0x001D  # cl.exe C++ (VS2002 .NET, build 9466)
    ALIASOBJ70   = 0x0027  # aliasobj.exe (VS2002 7.0)
    LINKER70     = 0x003D  # link.exe (VS2002 .NET, build 9466)
    EXP70        = 0x003F  # export record (VS2002 .NET, build 9466)
    MASM70       = 0x0040  # ml.exe (VS2002 .NET, build 9466)
    CVTRES70     = 0x0045  # cvtres.exe (VS2002 .NET, build 9466)


class RichRecord(NamedTuple):
    product: RichProductID
    build: int   # tool internal build number
    count: int   # number of object files compiled with this tool version


# Rich header structure.
# link.exe writes it between the DOS stub and IMAGE_NT_HEADERS.
# lld-link never emits one, so we inject it as a post-link patch.
#
# Every 32-bit field is XOR'd with the key, except 'Rich' and the key itself.
#
RICH_PREAMBLE     = b'DanS' + b'\x00' * 12  # DanS + three zero padding dwords (before XOR)
RICH_TRAILER      = b'Rich' + b'\x00' * 4   # 'Rich' + key placeholder (key filled in at write time)
RICH_RECORD_SIZE  = struct.calcsize('<II')   # two u32: (product << 16 | build) and use_count

# link.exe always adds 3 reserved record-slots of zero padding after the trailer
# before IMAGE_NT_HEADERS (observed consistently across BW1W100 and BW1W120).
RICH_HEADER_RESERVED_SLOTS = 3
RICH_HEADER_PAD  = RICH_HEADER_RESERVED_SLOTS * RICH_RECORD_SIZE  # = 0x18

# lld-link places IMAGE_NT_HEADERS here when it has no Rich header to emit.
# pe.DOS_HEADER.e_lfanew will equal this value on any lld-link output.
LLDLINK_STUB_SIZE = 0x80

# MZ header fields from MSVC 6.0's pre-compiled DOS stub binary.
# lld-link sets these to different values for its own shorter stub.
# e_cblp and e_cp describe the DOS program size in 512-byte pages; e_cp and
# e_sp are hardcoded constants in the stub binary with no derivable formula.
MSVC6_E_CP       = 3       # hardcoded in MSVC 6.0 pre-compiled DOS stub binary
MSVC6_E_MAXALLOC = 0xFFFF  # max heap paragraphs; MSVC sets to the maximum
MSVC6_E_SP       = 0x00B8  # hardcoded in MSVC 6.0 pre-compiled DOS stub binary

# Two timestamps per shipped image: the link time the debug directory records,
# and the .pdb creation time in the CodeView record it names. Both are now also
# in config.yml's timestamp, recovered from the disc image -- SafeDisc2Cleaner
# used to overwrite the PE header's copy of 1.00's and 1.10's link time with its
# author handle, leaving the debug directory as the only place 1.10's survived.
BW1W110_LINK_TIME = datetime.fromisoformat('2001-06-26T15:07:58+00:00')
BW1W110_PDB_TIME = datetime.fromisoformat('2001-06-04T14:50:17+00:00')
BW1W120_LINK_TIME = datetime.fromisoformat('2002-06-18T06:13:22+00:00')
BW1W120_PDB_TIME = datetime.fromisoformat('2002-05-27T11:24:14+00:00')

# The CodeView record an IMAGE_DEBUG_DIRECTORY of type IMAGE_DEBUG_TYPE_CODEVIEW
# points at: a reference to the (unshipped) .pdb rather than debug info itself.
# MSVC 6 leaves it at the end of the file, outside any section; lld-link emits
# the newer RSDS / CV_INFO_PDB70 form instead, so we write this one ourselves.
# Followed by PdbFileName, a NUL-terminated ASCII path.
__CV_INFO_PDB20_format__ = ('CV_INFO_PDB20', [
    '4s,CvSignature',  # always b'NB10'
    'I,Offset',        # 0 when the debug info lives in a separate .pdb
    'I,Signature',     # the .pdb's creation time, as time_t
    'I,Age',           # bumped by every incremental link
])


def rich_header_size(records):
    return len(RICH_PREAMBLE) + len(records) * RICH_RECORD_SIZE + len(RICH_TRAILER)


# Version-specific Rich header data, decoded from each original exe.
# The key is a checksum link.exe computes from the binary content at link time.

BW1W100_RICH_KEY = 0x1B5AC95C   # extracted from original exe at offset 0x11c

BW1W100_RICH_RECORDS = [
    RichRecord(RichProductID.UTC12_C,      8447,  23),
    RichRecord(RichProductID.LINKER600SP5, 9049,  11),
    RichRecord(RichProductID.ALIAS_OBJ,    7291,  14),
    RichRecord(RichProductID.MASM613,      7299,  42),
    RichRecord(RichProductID.UTC12_CPP,    8797,  13),
    RichRecord(RichProductID.UTC12_C,      8797, 195),
    RichRecord(RichProductID.IMPORT_OLD,      0,   6),
    RichRecord(RichProductID.UTC12_C,      8799,  35),
    RichRecord(RichProductID.UTC12_C,      8168,   7),
    RichRecord(RichProductID.UTC12_CPP,    8168,  24),
    RichRecord(RichProductID.LINKER600,    8168,   2),
    RichRecord(RichProductID.LINKER600SP5, 8034,  21),
    RichRecord(RichProductID.IMPORT,          0, 565),
    RichRecord(RichProductID.UTC12_CPP,    8447,   2),
    RichRecord(RichProductID.CVTRES,       1735,   1),
    RichRecord(RichProductID.UTC12_CPP,    8799, 643),
    RichRecord(RichProductID.LINKER600,    8447,  26),
]

BW1W110_RICH_KEY = 0xEA105BED   # extracted from original exe at offset 0x124
BW1W110_RICH_RECORDS = [
    RichRecord(RichProductID.UTC12_C,      8447,  23),
    RichRecord(RichProductID.UTC12_CPP,    8966,  62),
    RichRecord(RichProductID.ALIAS_OBJ,    7291,  14),
    RichRecord(RichProductID.UTC12_CPP,    8797,  13),
    RichRecord(RichProductID.MASM613,      7299,  43),
    RichRecord(RichProductID.UTC12_C,      8797, 196),
    RichRecord(RichProductID.LINKER600SP5, 9049,  11),
    RichRecord(RichProductID.UTC12_C,      8799,  35),
    RichRecord(RichProductID.UTC12_C,      8168,   7),
    RichRecord(RichProductID.UTC12_CPP,    8168,  24),
    RichRecord(RichProductID.LINKER600,    8168,   2),
    RichRecord(RichProductID.LINKER600SP5, 8034,  21),
    RichRecord(RichProductID.IMPORT,          0, 578),
    RichRecord(RichProductID.UTC12_CPP,    8447,   2),
    RichRecord(RichProductID.CVTRES,       1735,   1),
    RichRecord(RichProductID.UTC12_CPP,    8799, 585),
    RichRecord(RichProductID.IMPORT_OLD,      0,   9),
    RichRecord(RichProductID.LINKER600,    8447,  26),
]

BW1W120_RICH_KEY = 0x0A8EE120   # extracted from original exe at offset 0x124
BW1W120_RICH_RECORDS = [
    RichRecord(RichProductID.UTC12_C,      8168,   1),
    RichRecord(RichProductID.UTC12_C,      8447,  23),
    RichRecord(RichProductID.ALIAS_OBJ,    7291,  14),
    RichRecord(RichProductID.MASM613,      7299,  43),
    RichRecord(RichProductID.LINKER600SP5, 9049,  11),
    RichRecord(RichProductID.UTC12_C,      8799,  35),
    RichRecord(RichProductID.UTC12_CPP,    8799,  30),
    RichRecord(RichProductID.UTC12_CPP,    8047,  26),
    RichRecord(RichProductID.UTC12_C,      8047, 202),
    RichRecord(RichProductID.UTC12_CPP,    8168,  12),
    RichRecord(RichProductID.LINKER600,    8168,   2),
    RichRecord(RichProductID.LINKER600SP5, 8034,  21),
    RichRecord(RichProductID.IMPORT,          0, 578),
    RichRecord(RichProductID.UTC12_CPP,    8447,   2),
    RichRecord(RichProductID.CVTRES,       1735,   1),
    RichRecord(RichProductID.UTC12_CPP,    8966, 620),
    RichRecord(RichProductID.IMPORT_OLD,      0,   9),
    RichRecord(RichProductID.LINKER600,    8447,  26),
]


BW1W100_LHAUDIO_RICH_KEY = 0x52ED8B05   # extracted from original dll at offset 0xec
BW1W100_LHAUDIO_RICH_SLOTS = 2
BW1W100_LHAUDIO_RICH_RECORDS = [
    RichRecord(RichProductID.ALIAS_OBJ,    7291,   2),
    RichRecord(RichProductID.UTC12_CPP,    8797,   8),
    RichRecord(RichProductID.MASM613,      7299,  30),
    RichRecord(RichProductID.UTC12_C,      8797, 119),
    RichRecord(RichProductID.UTC12_C,      8799,   9),
    RichRecord(RichProductID.IMPORT_OLD,      0,   2),
    RichRecord(RichProductID.LINKER600SP5, 8034,  11),
    RichRecord(RichProductID.IMPORT,          0, 140),
    RichRecord(RichProductID.UTC12_CPP,    8799,  19),
    RichRecord(RichProductID.CVTRES,       1735,   1),
    RichRecord(RichProductID.LINKER600,    8447,  37),
]

BW1W100_LHLOG_RICH_KEY = 0xF22BBA49   # extracted from original dll at offset 0xdc
BW1W100_LHLOG_RICH_SLOTS = 3
BW1W100_LHLOG_RICH_RECORDS = [
    RichRecord(RichProductID.ALIAS_OBJ,    7291,   2),
    RichRecord(RichProductID.UTC12_CPP,    8797,  10),
    RichRecord(RichProductID.MASM613,      7299,  23),
    RichRecord(RichProductID.UTC12_C,      8797, 120),
    RichRecord(RichProductID.LINKER600SP5, 8034,  11),
    RichRecord(RichProductID.IMPORT,          0, 129),
    RichRecord(RichProductID.UTC12_CPP,    8799,   7),
    RichRecord(RichProductID.CVTRES,       1735,   1),
    RichRecord(RichProductID.LINKER600,    8447,   1),
]

BW1W100_LHMULTIPLAYER_RICH_KEY = 0x741C518F   # extracted from original dll at offset 0xec
BW1W100_LHMULTIPLAYER_RICH_SLOTS = 2
BW1W100_LHMULTIPLAYER_RICH_RECORDS = [
    RichRecord(RichProductID.UTC12_C,      8799,  23),
    RichRecord(RichProductID.ALIAS_OBJ,    7291,   3),
    RichRecord(RichProductID.UTC12_CPP,    8797,  10),
    RichRecord(RichProductID.MASM613,      7299,  23),
    RichRecord(RichProductID.UTC12_C,      8797, 144),
    RichRecord(RichProductID.UTC12_C,      8447,  12),
    RichRecord(RichProductID.UTC12_CPP,    8168,   3),
    RichRecord(RichProductID.LINKER600SP5, 8034,  11),
    RichRecord(RichProductID.IMPORT,          0, 180),
    RichRecord(RichProductID.UTC12_CPP,    8799,  28),
    RichRecord(RichProductID.LINKER600,    8447,   3),
]

BW1W100_LHDIALOG_RICH_KEY = 0xEEAE27EE   # extracted from original dll at offset 0xcc
BW1W100_LHDIALOG_RICH_SLOTS = 1
BW1W100_LHDIALOG_RICH_RECORDS = [
    RichRecord(RichProductID.LINKER600SP5, 8034,   2),
    RichRecord(RichProductID.MASM613,      7299,   1),
    RichRecord(RichProductID.UTC12_C,      8447,   4),
    RichRecord(RichProductID.IMPORT,          0, 165),
    RichRecord(RichProductID.UTC12_CPP,    8447,  13),
    RichRecord(RichProductID.CVTRES,       1735,   1),
    RichRecord(RichProductID.LINKER600,    8447,   6),
]

BW1W110_LHAUDIO_RICH_KEY = BW1W100_LHAUDIO_RICH_KEY
BW1W110_LHAUDIO_RICH_SLOTS = BW1W100_LHAUDIO_RICH_SLOTS
BW1W110_LHAUDIO_RICH_RECORDS = BW1W100_LHAUDIO_RICH_RECORDS

BW1W110_LHLOG_RICH_KEY = BW1W100_LHLOG_RICH_KEY
BW1W110_LHLOG_RICH_SLOTS = BW1W100_LHLOG_RICH_SLOTS
BW1W110_LHLOG_RICH_RECORDS = BW1W100_LHLOG_RICH_RECORDS

BW1W110_LHMULTIPLAYER_RICH_KEY = BW1W100_LHMULTIPLAYER_RICH_KEY
BW1W110_LHMULTIPLAYER_RICH_SLOTS = BW1W100_LHMULTIPLAYER_RICH_SLOTS
BW1W110_LHMULTIPLAYER_RICH_RECORDS = BW1W100_LHMULTIPLAYER_RICH_RECORDS

BW1W110_LHDIALOG_RICH_KEY = BW1W100_LHDIALOG_RICH_KEY
BW1W110_LHDIALOG_RICH_SLOTS = BW1W100_LHDIALOG_RICH_SLOTS
BW1W110_LHDIALOG_RICH_RECORDS = BW1W100_LHDIALOG_RICH_RECORDS

BW1W120_LHAUDIO_RICH_KEY = BW1W100_LHAUDIO_RICH_KEY
BW1W120_LHAUDIO_RICH_SLOTS = BW1W100_LHAUDIO_RICH_SLOTS
BW1W120_LHAUDIO_RICH_RECORDS = BW1W100_LHAUDIO_RICH_RECORDS

BW1W120_LHLOG_RICH_KEY = 0xE4859AE9   # extracted from original dll at offset 0xdc
BW1W120_LHLOG_RICH_SLOTS = 3
BW1W120_LHLOG_RICH_RECORDS = [
    RichRecord(RichProductID.ALIASOBJ70,    9162,   2),
    RichRecord(RichProductID.MASM70,        9466,  23),
    RichRecord(RichProductID.UTC70_C,       9466, 126),
    RichRecord(RichProductID.IMPORT_VS2002, 9210,  11),
    RichRecord(RichProductID.IMPORT,           0, 131),
    RichRecord(RichProductID.UTC70_CPP,     9466,  18),
    RichRecord(RichProductID.EXP70,         9466,   1),
    RichRecord(RichProductID.CVTRES70,      9466,   1),
    RichRecord(RichProductID.LINKER70,      9466,   1),
]

BW1W120_LHMULTIPLAYER_RICH_KEY = 0x40924540   # extracted from original dll at offset 0xec
BW1W120_LHMULTIPLAYER_RICH_SLOTS = 3
BW1W120_LHMULTIPLAYER_RICH_RECORDS = [
    RichRecord(RichProductID.UTC12_C,      8799,  23),
    RichRecord(RichProductID.ALIAS_OBJ,    7291,   5),
    RichRecord(RichProductID.UTC12_CPP,    8047,  10),
    RichRecord(RichProductID.MASM613,      7299,  23),
    RichRecord(RichProductID.UTC12_C,      8047, 146),
    RichRecord(RichProductID.UTC12_C,      8447,  12),
    RichRecord(RichProductID.UTC12_CPP,    8168,   3),
    RichRecord(RichProductID.LINKER600SP5, 8034,  11),
    RichRecord(RichProductID.IMPORT,          0, 180),
    RichRecord(RichProductID.UTC12_CPP,    8966,  28),
    RichRecord(RichProductID.LINKER600,    8447,   3),
]

BW1W120_LHDIALOG_RICH_KEY = BW1W100_LHDIALOG_RICH_KEY
BW1W120_LHDIALOG_RICH_SLOTS = BW1W100_LHDIALOG_RICH_SLOTS
BW1W120_LHDIALOG_RICH_RECORDS = BW1W100_LHDIALOG_RICH_RECORDS


# Rich header write helpers

def write_bytes(pe, offset, data):
    pe.__data__[offset:offset + len(data)] = data


def xor_dword(key, value):
    return struct.pack('<I', value ^ key)


def find_section_header(pe, name: str):
    return next(s for s in pe.__structures__ if s.name == 'IMAGE_SECTION_HEADER' and s.Name.startswith(bytearray(name, 'ascii')))


def find_directory(pe, name: str):
    return next(s for s in pe.__structures__ if s.name == name)


def patch_directory(pe, name: str, address: int|None=None, size: int|None=None):
    directory = find_directory(pe, name)
    if address is not None:
        directory.VirtualAddress = address - pe.OPTIONAL_HEADER.ImageBase
    if size is not None:
        directory.Size = size


def write_rich_header(pe, addr, key, records):
    # XOR-encode and write preamble (DanS + 3 zero dwords)
    off = addr
    for i in range(0, len(RICH_PREAMBLE), 4):
        val = struct.unpack_from('<I', RICH_PREAMBLE, i)[0]
        write_bytes(pe, off, xor_dword(key, val))
        off += 4
    # Write records
    for record in records:
        write_bytes(pe, off,     xor_dword(key, (record.product << 16) | record.build))
        write_bytes(pe, off + 4, xor_dword(key, record.count))
        off += RICH_RECORD_SIZE
    # Write trailer: 'Rich' (plain) + key (plain)
    write_bytes(pe, off,     b'Rich')
    write_bytes(pe, off + 4, struct.pack('<I', key))


def insert_rich_header(pe, key, records, reserved_slots=RICH_HEADER_RESERVED_SLOTS):
    # pefile gives us the current stub end (lld-link always sets e_lfanew = LLDLINK_STUB_SIZE)
    rich_start = pe.DOS_HEADER.e_lfanew
    gap = rich_header_size(records) + reserved_slots * RICH_RECORD_SIZE

    # Shift IMAGE_NT_HEADERS back to make room. pefile's set_file_offset
    # updates section PointerToRawData, data directories, etc. automatically;
    # insert_header_padding moves the free-floating header bytes pefile does not
    # track (e.g. exestr comments).
    pe.DOS_HEADER.e_lfanew += gap
    for structure in pe.__structures__:
        if 0 < structure.get_file_offset() < 0x1000:
            structure.set_file_offset(structure.get_file_offset() + gap)
    insert_header_padding(pe, rich_start, gap)

    # e_cblp: bytes on the last DOS page. The MSVC stub ends at rich_start + preamble.
    pe.DOS_HEADER.e_cblp     = rich_start + len(RICH_PREAMBLE)
    pe.DOS_HEADER.e_cp       = MSVC6_E_CP
    pe.DOS_HEADER.e_maxalloc = MSVC6_E_MAXALLOC
    pe.DOS_HEADER.e_sp       = MSVC6_E_SP

    write_rich_header(pe, rich_start, key, records)


def zero_code_section_padding(pe):
    """Zero out the gap between VirtualSize and SizeOfRawData in code sections.

    lld-link fills this trailing padding with 0x90 (NOP); MSVC link.exe uses zeros.
    """
    IMAGE_SCN_CNT_CODE = 0x00000020
    for section in pe.sections:
        if not (section.Characteristics & IMAGE_SCN_CNT_CODE):
            continue
        pad_start = section.PointerToRawData + section.Misc_VirtualSize
        pad_end   = section.PointerToRawData + section.SizeOfRawData
        if pad_end > pad_start:
            write_bytes(pe, pad_start, b'\x00' * (pad_end - pad_start))


def apply_link_time(pe, cfg):
    # The original compilation date. lld-link stamps its own; config.yml carries
    # the one the disc image holds.
    timestamp = cfg.get("timestamp")
    if timestamp:
        pe.FILE_HEADER.TimeDateStamp = int(datetime.fromisoformat(timestamp).timestamp())


def apply_BW1_common_patch(pe, cfg):
    # Don't put anything in DllCharacteristics
    pe.OPTIONAL_HEADER.DllCharacteristics = 0
    # Striping characteristics are removed, probably by safedisc 2
    pe.FILE_HEADER.Characteristics |= pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_LINE_NUMS_STRIPPED']
    pe.FILE_HEADER.Characteristics |= pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_LOCAL_SYMS_STRIPPED']

    # Override the linker version to the original one (we're using lld-link)
    linker_version = cfg.get("linker_version")
    if linker_version:
        pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion = map(int, linker_version.split("."))
    
    # Size of code and size of Initialized Data might not match
    # TODO: Is this a sign of bad objs or link arguments or something missing from the linker?
    size_of_code = cfg.get("size_of_code")
    if size_of_code:
        pe.OPTIONAL_HEADER.SizeOfCode = size_of_code
    size_of_initialized_data = cfg.get("size_of_initialized_data")
    if size_of_initialized_data:
        pe.OPTIONAL_HEADER.SizeOfInitializedData = size_of_initialized_data
    size_of_image = cfg.get("size_of_image")
    if size_of_image:
        pe.OPTIONAL_HEADER.SizeOfImage = size_of_image
    # Patch directories which aren't set to the same place with this linker
    # TODO: Why are these bad?
    patch_directory(pe, 'IMAGE_DIRECTORY_ENTRY_EXPORT', cfg.get("entry_export_addr"), cfg.get("entry_export_size"))
    patch_directory(pe, 'IMAGE_DIRECTORY_ENTRY_IMPORT', cfg.get("entry_import_addr"), cfg.get("entry_import_size"))
    patch_directory(pe, 'IMAGE_DIRECTORY_ENTRY_RESOURCE', cfg.get("entry_resource_addr"), cfg.get("entry_resource_size"))

    # Once the import table is carved into real .idata$N sub-sections, lld-link's
    # locateImportTables() sets DataDirectory[IAT] from our .idata$5 chunk. The
    # shipped image leaves this directory zero, so re-zero it here. (No-op for
    # versions not yet carved.)
    iat_dir = find_directory(pe, 'IMAGE_DIRECTORY_ENTRY_IAT')
    iat_dir.VirtualAddress = 0
    iat_dir.Size = 0

    # Point to .rdata
    # TODO: Why is this set to 0?
    pe.OPTIONAL_HEADER.BaseOfData = find_section_header(pe, '.rdata').get_PointerToRawData_adj()


def section_table_end(pe):
    return (pe.DOS_HEADER.e_lfanew + 4 + 20
            + pe.FILE_HEADER.SizeOfOptionalHeader
            + pe.FILE_HEADER.NumberOfSections * 40)


def insert_header_padding(pe, at, count):
    # Shift the free-floating header bytes forward within SizeOfHeaders; pefile
    # structures are relocated separately via set_file_offset.
    soh = pe.OPTIONAL_HEADER.SizeOfHeaders
    content = bytes(pe.__data__[at:soh - count])
    pe.__data__[at + count:soh] = content
    pe.__data__[at:at + count] = b'\x00' * count


def write_codeview_record(pe, at, pdb_creation_time: datetime, age, pdb_path):
    """Write the CV_INFO_PDB20 record the debug directory points at.

    MSVC 6 leaves it at the end of the file, outside any section, so `at` is the
    linker's EOF: right after the last section's raw data, and the last thing
    link.exe writes. Returns the record's length, which is what the debug
    directory reports as SizeOfData.
    """
    cv = pefile.Structure(__CV_INFO_PDB20_format__)
    cv.CvSignature = b'NB10'
    cv.Offset      = 0
    cv.Signature   = int(pdb_creation_time.timestamp())
    cv.Age         = age
    record = cv.__pack__() + pdb_path.encode() + b'\x00'
    write_bytes(pe, at, record)
    return len(record)


def restore_debug_directory(pe, at, link_time: datetime, cv_offset, cv_size):
    """Restamp the IMAGE_DEBUG_DIRECTORY entry with the shipped values.

    1.10 and 1.20 were linked with /debug, so lld-link emits this entry itself:
    splits.txt hands it the 0x1C hole just past the IAT that link.exe used, and
    nothing around it shifts. Only the run-dependent fields differ -- lld stamps
    its own link time and points at the RSDS/CV_INFO_PDB70 record it appends to
    .rdata's tail slack, where the shipped image has the older NB10 form sitting
    past the last section (AddressOfRawData 0, since it is in no section).

    Erasing lld's record restores .rdata's slack to the zeros the shipped image
    has there. Both the entry and the record are parsed structures, so they have
    to be edited (and the record dropped) rather than overwritten: pe.write()
    re-serializes everything in pe.__structures__ over the raw bytes.

    `at` is the entry's virtual address; it is asserted rather than used, so a
    layout change that moves the entry fails loudly instead of silently patching
    the wrong bytes.
    """
    expected_rva = at - pe.OPTIONAL_HEADER.ImageBase
    directory = find_directory(pe, 'IMAGE_DIRECTORY_ENTRY_DEBUG')
    assert directory.VirtualAddress == expected_rva, (
        f"debug directory at {directory.VirtualAddress:#x}, expected {expected_rva:#x}: "
        "the linker no longer places it in the hole splits.txt leaves for it")
    debug_entry, = pe.DIRECTORY_ENTRY_DEBUG
    entry = debug_entry.struct

    if debug_entry.entry is not None:
        pe.__structures__.remove(debug_entry.entry)
        debug_entry.entry = None
    write_bytes(pe, entry.PointerToRawData, b'\x00' * entry.SizeOfData)

    entry.TimeDateStamp = int(link_time.timestamp())
    entry.SizeOfData = cv_size
    entry.AddressOfRawData = 0  # the record is past the last section
    entry.PointerToRawData = cv_offset


def apply_BW1W100_patch(pe, cfg, out_dir, modules):
    apply_link_time(pe, cfg)
    apply_BW1_common_patch(pe, cfg)
    apply_modules_patch(out_dir, cfg, modules)


def apply_BW1W110_patch(pe, cfg, out_dir, modules):
    apply_link_time(pe, cfg)
    apply_BW1_common_patch(pe, cfg)

    # CodeView record pointing at the .pdb, and the debug directory naming it.
    cv_size = write_codeview_record(pe, 0x00832000, BW1W110_PDB_TIME, 0x10,
                                    'C:\\dev\\Black\\Gold\\Black.pdb')
    restore_debug_directory(pe, 0x008999c0, BW1W110_LINK_TIME, 0x00832000, cv_size)

    apply_modules_patch(out_dir, cfg, modules)


def apply_BW1W120_patch(pe, cfg, out_dir, modules):
    apply_link_time(pe, cfg)
    apply_BW1_common_patch(pe, cfg)

    # CodeView record pointing at the .pdb, and the debug directory naming it.
    # SafeDisc2Cleaner used to cut the file at 0x843000, orphaning this record;
    # the disc image keeps it, so force_size now runs to its end instead.
    cv_size = write_codeview_record(pe, 0x00843000, BW1W120_PDB_TIME, 0xC,
                                    'C:\\dev\\MP\\Black\\Gold\\Black.pdb')
    restore_debug_directory(pe, 0x008a99c0, BW1W120_LINK_TIME, 0x00843000, cv_size)

    apply_modules_patch(out_dir, cfg, modules)


PATCHES = {
    "BW1W100": (BW1W100_RICH_KEY, BW1W100_RICH_RECORDS, apply_BW1W100_patch, {
        "LHAudio":       (BW1W100_LHAUDIO_RICH_KEY,       BW1W100_LHAUDIO_RICH_RECORDS,       BW1W100_LHAUDIO_RICH_SLOTS),
        "LHLog":         (BW1W100_LHLOG_RICH_KEY,         BW1W100_LHLOG_RICH_RECORDS,         BW1W100_LHLOG_RICH_SLOTS),
        "LHMultiplayer": (BW1W100_LHMULTIPLAYER_RICH_KEY, BW1W100_LHMULTIPLAYER_RICH_RECORDS, BW1W100_LHMULTIPLAYER_RICH_SLOTS),
        "LHDialog":      (BW1W100_LHDIALOG_RICH_KEY,      BW1W100_LHDIALOG_RICH_RECORDS,      BW1W100_LHDIALOG_RICH_SLOTS),
    }),
    "BW1W110": (BW1W110_RICH_KEY, BW1W110_RICH_RECORDS, apply_BW1W110_patch, {
        "LHAudio":       (BW1W110_LHAUDIO_RICH_KEY,       BW1W110_LHAUDIO_RICH_RECORDS,       BW1W110_LHAUDIO_RICH_SLOTS),
        "LHLog":         (BW1W110_LHLOG_RICH_KEY,         BW1W110_LHLOG_RICH_RECORDS,         BW1W110_LHLOG_RICH_SLOTS),
        "LHMultiplayer": (BW1W110_LHMULTIPLAYER_RICH_KEY, BW1W110_LHMULTIPLAYER_RICH_RECORDS, BW1W110_LHMULTIPLAYER_RICH_SLOTS),
        "LHDialog":      (BW1W110_LHDIALOG_RICH_KEY,      BW1W110_LHDIALOG_RICH_RECORDS,      BW1W110_LHDIALOG_RICH_SLOTS),
    }),
    "BW1W120": (BW1W120_RICH_KEY, BW1W120_RICH_RECORDS, apply_BW1W120_patch, {}),
    "BW1W120": (BW1W120_RICH_KEY, BW1W120_RICH_RECORDS, apply_BW1W120_patch, {
        "LHAudio":       (BW1W120_LHAUDIO_RICH_KEY,       BW1W120_LHAUDIO_RICH_RECORDS,       BW1W120_LHAUDIO_RICH_SLOTS),
        "LHLog":         (BW1W120_LHLOG_RICH_KEY,         BW1W120_LHLOG_RICH_RECORDS,         BW1W120_LHLOG_RICH_SLOTS),
        "LHMultiplayer": (BW1W120_LHMULTIPLAYER_RICH_KEY, BW1W120_LHMULTIPLAYER_RICH_RECORDS, BW1W120_LHMULTIPLAYER_RICH_SLOTS),
        "LHDialog":      (BW1W120_LHDIALOG_RICH_KEY,      BW1W120_LHDIALOG_RICH_RECORDS,      BW1W120_LHDIALOG_RICH_SLOTS),
    }),
}


def apply_module_patch(pe, cfg, pe_metadata):
    # Override the linker version to the original one (we're using lld-link)
    linker_version = cfg.get("linker_version")
    if linker_version:
        pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion = map(int, linker_version.split("."))
    # Header fields lld-link reproduces differently, taken from the original PE
    # (captured by dtk at split time into config.json).
    pe.FILE_HEADER.TimeDateStamp = pe_metadata["timestamp"]
    pe.FILE_HEADER.Characteristics = pe_metadata["characteristics"]
    pe.OPTIONAL_HEADER.DllCharacteristics = pe_metadata["dll_characteristics"]
    pe.OPTIONAL_HEADER.BaseOfData = pe_metadata["base_of_data"]
    pe.OPTIONAL_HEADER.SizeOfCode = pe_metadata["size_of_code"]
    pe.OPTIONAL_HEADER.SizeOfInitializedData = pe_metadata["size_of_initialized_data"]
    pe.OPTIONAL_HEADER.SizeOfImage = pe_metadata["size_of_image"]
    # Data directories (lld-link leaves export/import/IAT/debug/delay-import unset)
    for i, (rva, size) in enumerate(pe_metadata["data_directories"]):
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].VirtualAddress = rva
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size = size
    # The original linker's .reloc VirtualSize differs from lld-link's
    find_section_header(pe, '.reloc').Misc_VirtualSize = pe_metadata["reloc_virtual_size"]


def apply_modules_patch(out_dir, cfg, modules):
    build_config = json.loads((out_dir / "config.json").read_text())
    metadata = {m["name"]: m.get("pe_metadata") for m in build_config.get("modules", [])}
    module_cfgs = {m["name"]: m for m in cfg.get("modules", [])}
    for name, (rich_key, rich_records, rich_slots) in modules.items():
        pe_metadata = metadata.get(name)
        module_cfg = {**cfg, **module_cfgs.get(name, {})}

        data = bytearray((out_dir / f"{name}-linked.dll").read_bytes())
        pe   = pefile.PE(data=data)

        insert_rich_header(pe, rich_key, rich_records, rich_slots)
        zero_code_section_padding(pe)
        if pe_metadata:
            apply_module_patch(pe, module_cfg, pe_metadata)

        data[:] = pe.write()
        # Trailing data (e.g. the CodeView debug record) that lld-link drops.
        if pe_metadata:
            data += bytes(pe_metadata["trailing_data"])
        pe.close()

        (out_dir / f"{name}.dll").write_bytes(data)


def main():
    parser = argparse.ArgumentParser(
        description="Apply post-link binary patches to the relinked executable."
    )
    parser.add_argument("input",   type=Path, help="Linked executable produced by lld-link")
    parser.add_argument("output",  type=Path, nargs="?", default=None,
                        help="Patched output path (default: patch input in place)")
    parser.add_argument("--version", required=True, choices=list(PATCHES), help="Game version")
    args = parser.parse_args()

    rich_key, rich_records, apply_version_patch, modules = PATCHES[args.version]

    cfg_path  = Path("config") / args.version / "config.yml"
    cfg       = yaml.safe_load(cfg_path.read_text())
    force_size = cfg.get("force_size")

    out = args.output if args.output is not None else args.input
    out.parent.mkdir(parents=True, exist_ok=True)

    data = bytearray(args.input.read_bytes())
    pe   = pefile.PE(data=data)

    insert_rich_header(pe, rich_key, rich_records)
    zero_code_section_padding(pe)
    apply_version_patch(pe, cfg, out.parent, modules)

    data[:] = pe.write()
    if force_size:
        # Where link.exe stopped writing: the end of the CodeView record on
        # 1.10/1.20, the end of the last section on 1.00.
        print(f"size is {hex(len(data))}, forcing to {hex(force_size)}")
        data = data[:force_size] + b'\0' * (force_size - len(data))
    pe.close()

    out.write_bytes(data)


if __name__ == "__main__":
    main()
