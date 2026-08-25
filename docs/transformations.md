# Binary transformations

The shipped executable is MSVC 6.0 linker output wrapped by SafeDisc. The build
starts from the disc image and unwraps it itself, so nothing that is not linker
output ever reaches dtk or lld-link, and no third-party-decrypted exe is needed.

```
orig/<ver>/runblack.exe                  the disc image, SafeDisc-wrapped
  │  decrypt_safedisc.py   (pre-split step: sd2unpack + header restoration)
  ▼
build/<ver>/runblack-decrypted.exe       pristine linker shape; the target
  │  dtk coff split  →  objs  →  lld-link
  ▼
build/<ver>/runblack-linked.exe          pristine linker output, debuggable
  │  post_link_patch.py   (post-link step)
  ▼
build/<ver>/runblack.exe                 byte-identical to runblack-decrypted.exe
```

Both scripts are wired through the standard `custom_build_steps` hooks in
`configure.py` (`pre-split` and `post-link`).

The build used to start from a `runblack-decrypted.exe` produced by
SafeDisc2Cleaner, and `post_link_patch.py` had to reproduce that tool's
vandalism to match it. Working from the disc image removes all of it: the
graffiti, the truncated exestr comment, the `eYes` timestamp, SafeDisc's
sections and its appended payload. What is left is closer to what link.exe
emitted, so several fields that used to need an override no longer do -- see
*What the disc image recovered* below.

## Header layout

The exestr comments are the crux. MSVC's Intel-compiled objects carry
`#pragma comment(exestr, "…")`, which the compiler emits as an `-?comment:"…"`
directive in the object's `.drectve` section. Real MSVC 6.0 `link.exe` embeds
the string **flush after the section table** in the header padding (verified:
gap 0). Nothing in the PE references it — it is free-floating bytes inside
`SizeOfHeaders`.

SafeDisc rearranges that region:

```
link.exe:   [section table][comment flush]
SafeDisc:   inserts 2 section headers (stxt774, stxt371 = 2*40 = 0x50) after the
            section table, shoving the comment forward 0x50
```

The comment strings themselves are untouched on the disc image. (The old
SafeDisc2Cleaner route also removed those two headers, wrote a cracker signature
into the freed space, and over-zeroed the first 24 bytes of the first comment,
which is why `pre_dtk_patch.py` used to carry that prefix as a hardcoded
constant. None of that survives the move to the disc image.)

1.0 has no exestr comments at all — its header padding held nothing but
SafeDisc's own stamp.

## decrypt_safedisc.py (encrypted → decrypted)

Runs [sd2unpack](https://github.com/openblack/Safedisc2Cleaner) over the disc
image, then restores the pristine linker shape.

sd2unpack decrypts `.text`/`.data`, recovers the hidden (and, on 2.60,
encrypted) import directory, restores the real entry point, drops SafeDisc's own
sections (`.data1`, `SELFMOD`, `stxt774`, `stxt371`), strips the `BoG_` version
stamp and truncates the appended SafeDisc payload.

Everything that varies per build is either derived from inputs already in the
repository or read from the `safedisc:` block in `config/<ver>/config.yml`:

- the real entry point comes from `config/<ver>/symbols.txt`
  (`_WinMainCRTStartup`) — SafeDisc records it nowhere in the file, but the
  decomp has always known where the program starts, so it is not carried as key
  material;
- the image base, section layout and which sections are encrypted come from the
  encrypted executable's own headers;
- the section cipher keys come from that `safedisc:` block, which pins the SHA-1 of the
  executable they belong to. Decrypting one build with another's keys does not
  fail loudly, so that pin is enforced, not advisory.

The header restoration then moves the exestr comments back flush against the
section table. Dropping `.data1` and `SELFMOD` makes the section table two
headers (0x50) shorter, and the comments sit flush against its end, so they land
at `0x4002D8` instead of the `0x400328` the old six-section reference had.
Comments are identified by content (`32-bit applications`), so SafeDisc's markers
are never mistaken for them.

## dtk / lld-link

The comment range is declared in `splits.txt` like any other segment:

```
Sections:
	.drectve    type:comment vaddr:0x004002D8 end:0x00400662
```

dtk reads it (`read_splits_sections`), extracts the bytes from the header
padding, and re-emits them as `-?comment:"…"` directives in a generated
`.drectve` object. lld-link (openblack fork) understands `-?comment` and embeds
each string flush after the section table, matching link.exe.

## post_link_patch.py (linked → decrypted)

Reproduces what link.exe emitted and lld-link does not:

- inserts the Rich header (`insert_rich_header`), shifting the PE header and the
  free-floating comment bytes forward;
- restamps the link time from `config.yml`'s `timestamp`;
- fixes up header fields and data directories lld-link computes differently
  (`apply_BW1_common_patch`);
- writes the CodeView record and debug directory on 1.10/1.20.

The Intel comment strings are not hardcoded here — they flow from the objects
through lld-link. Nothing SafeDisc- or cracker-related is written any more: the
0x50 bump, the 24-byte prefix erasure, the `BoG_` stamp, the version dwords, the
`0x2BAD` marker, the `Safedisc2Cleaner …` and ` crazy bad bwoy ` strings and the
45-byte mastering tail tag are all gone, along with the `eYes` timestamp.

## Debug directory

1.10 and 1.20 were linked with `/debug`: link.exe put an `IMAGE_DEBUG_DIRECTORY`
in `.rdata` immediately past the IAT, naming an NB10 CodeView record appended
past the last section. 1.00 has neither.

Rather than copy those 0x1C bytes out of the original, the build makes the
linker emit them:

- `splits.txt` extends `.idata$5` over link.exe's IAT tail padding (`…99A8` →
  `…99C0`), so the leftover autogenerated `.rdata` unit is exactly the directory;
- `configure.py` holds that unit back (`linker_provided_units`) and links the
  base image with `/debug`, leaving a 0x1C hole;
- lld-link (openblack fork, `bw1-decomp-021`+) inserts its debug directory after
  the last `.idata$5` chunk, matching link.exe, and fills the hole exactly.

`post_link_patch.py` then restamps the entry to the shipped link time, size and
CodeView offset, and erases the RSDS record lld-link leaves in `.rdata`'s tail
slack — zero in the shipped image. 1.20's NB10 record is written past the last
section and then trimmed off by `force_size`; 1.10 keeps it.

The payoff is `build/<ver>/runblack-linked.exe`: the pre-patch artifact is now a
debuggable image whose debug directory points at `runblack-linked.pdb`, so it
loads in Ghidra or under a debugger with ~38k symbol names, while the patched
`runblack.exe` stays byte-identical. `--debug` adds `/Zi` types on top and is
layout-neutral — that build still matches.

The IAT tail padding itself is unexplained: link.exe's gap between IAT end and
debug directory is 0 on its own output and on 1.30, 0xC on LHMultiplayerR.dll,
but 0x18 on the 1.10/1.20 executables. Absorbing it into `.idata$5` sidesteps
needing the rule.

## What the disc image recovered

Fields where the SafeDisc2Cleaner copy was wrong and the disc image is not, all
now visible in `config/<ver>/config.yml`:

| | 1.00 | 1.10 | 1.20 |
|---|---|---|---|
| link timestamp | `2001-03-09T14:56:38Z` | `2001-06-26T15:07:58Z` | unchanged |
| `size_of_image` | `0xAE4000` (was `0xAE493E`) | `0xBB3000` (was `0xBB493E`) | `0xBC4000` (was `0xBC493E`) |
| `force_size` | `0x762000` (was `0x81B58F`) | `0x83002C` (was `0x902A0B`) | `0x84102F` (was `0x843000`) |
| `.rsrc` VA | `0xAE0000` (was `0xAE1000`) | `0xBAF000` (was `0xBB1000`) | `0xBC0000` (was `0xBC2000`) |

The two timestamps had been overwritten with the cleaner's author handle
(`eYes`); 1.10's recovered value matches `BW1W110_LINK_TIME` in
`post_link_patch.py`, which was read out of the surviving debug directory —
independent confirmation. The `size_of_image` values are now section-aligned, as
link.exe computes them; the old unaligned ones were SafeDisc's. The 1.00/1.10
`force_size` values used to carry SafeDisc's entire appended payload, and 1.20's
cut the file 0x2F bytes short, orphaning the CodeView record the debug directory
points at.

The `.rsrc` row is the one the build caught rather than the reader. SafeDisc does
not append its sections, it *inserts* them: `SELFMOD` on 1.00, `.data1` and
`SELFMOD` on 1.10/1.20, all placed between `.data` and `.rsrc`, which pushes
`.rsrc` up one page per inserted section. Different counts in three builds of the
same program is not something one linker does, so the shift is SafeDisc's.

sd2unpack compacts: every section is repacked contiguously at its alignment and
everything that pointed into a moved one is rewritten — the RESOURCE data
directory, each `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData`, `SizeOfImage`, and the
debug record's file pointer at the trailing CodeView blob. lld independently
lands `.rsrc` at the same address, which is the confirmation that this is where
link.exe had it.

This repo carried its own `compact_dropped_sections()` for one day before
sd2unpack took the job over; the two implementations produced byte-identical
output on all three builds, which is a better cross-check than either alone.
Doing it in both places would double-shift, so it lives only in sd2unpack now.

## SHA verification

- `orig/<ver>/runblack.exe` — the disc image, checked by `build.sha1`
  and pinned again by `config.yml`'s `safedisc.expect_sha1`.
- `build/<ver>/runblack-decrypted.exe` — the target; deterministic, checked by
  `build.sha1` and by dtk against `config.yml`'s `hash` (the split input).
- `build/<ver>/runblack.exe` — final output, checked by `build.sha1` against the
  same hash as the target.
