"""
Headless command-line front end:

    python -m mechadec mechacon.bin
    python -m mechadec mechacon.bin -o mechacon.c
    python -m mechadec mechacon.bin --func 0xFC1986      # one function
    python -m mechadec mechacon.bin --entry 0xFC2000     # extra entry point
    python -m mechadec mechacon.bin --list               # recovered tables
    python -m mechadec mechacon.bin --asm 0xFC0000       # raw disassembly

No IDA required.  Accepts a raw 256 KiB MechaCon mask-ROM dump, or any flat
SPC970 image if ``--base`` is given.
"""

import argparse
import sys

from . import decompile_file, loader, isa
from .decoder import decode_one


def _int(s):
    return int(s, 0)


def _format_operand(op):
    m = op.mode
    if m in ("reg", "ctrl"):
        return op.reg
    if m == "imm":
        return "#0x%X" % op.value
    if m == "abs":
        return "io[0x%02X]" % op.addr if op.space == "io" else "[0x%06X]" % op.addr
    if m == "disp":
        return "@(%d,%s)" % (op.disp, op.base_reg)
    if m == "ind":
        return "@(%s)" % op.base_reg
    if m == "predec":
        return "@(-%s)" % op.base_reg
    if m == "postinc":
        return "@(%s+)" % op.base_reg
    if m == "pop":
        return "@(SP+)"
    if m == "code":
        return "0x%06X" % op.addr
    if m == "bit":
        return "%s.%d" % (_format_operand(op.base), op.bit)
    if m == "addrof":
        return "&%s" % _format_operand(op.base)
    if m == "reglist":
        return "{%s}" % ",".join(op.regs)
    return m


def disassemble(image, start, count):
    out = []
    ea = start
    for _ in range(count):
        ins = decode_one(image.data, ea, image.base)
        if ins is None or ins.size == 0:
            out.append("%06X  %-18s <undefined>" % (ea, "%02X" % image.u8(ea)))
            ea += 1
            continue
        mnem = ins.mnem + (isa.WIDTH_SUFFIX.get(ins.width, "") if ins.width else "")
        out.append("%06X  %-18s %-8s %s"
                   % (ea, ins.raw.hex(), mnem,
                      ", ".join(_format_operand(o) for o in ins.ops)))
        ea += ins.size
    return out


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(
        prog="mechadec",
        description="Decompile Sony SPC970 / PlayStation 2 MechaCon firmware to pseudo-C.")
    ap.add_argument("rom", help="raw SPC970 image (a 256 KiB MechaCon dump)")
    ap.add_argument("-o", "--out", help="write the listing here (default: stdout)")
    ap.add_argument("--base", type=_int, default=isa.ROM_BASE,
                    help="load address of the image (default 0xFC0000)")
    ap.add_argument("--entry", type=_int, action="append", default=None,
                    help="extra entry point (repeatable)")
    ap.add_argument("--func", type=_int, default=None,
                    help="only emit the function at this address")
    ap.add_argument("--asm", type=_int, default=None,
                    help="disassemble from this address instead of decompiling")
    ap.add_argument("--count", type=_int, default=40,
                    help="instruction count for --asm (default 40)")
    ap.add_argument("--list", action="store_true",
                    help="list the recovered MechaCon tables and named handlers")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args(argv)

    if args.asm is not None:
        image = loader.load(args.rom, args.base)
        print("\n".join(disassemble(image, args.asm, args.count)))
        return 0

    if args.list:
        image = loader.load(args.rom, args.base)
        entries, tables = loader.discover(image)
        print("image      : %s" % args.rom)
        print("base       : 0x%06X   primary bank 0x%06X" % (image.base, image.primary_bank))
        print("mechacon   : %s" % loader.is_mechacon(image))
        print("entries    : %d" % len(entries))
        for note in tables.notes:
            print("table      : %s" % note)
        for addr in sorted(tables.code_names):
            print("  %06X  %s" % (addr, tables.code_names[addr]))
        return 0

    extra = tuple(args.entry) if args.entry else ()
    prog = decompile_file(args.rom, extra_entries=extra, base=args.base)

    if args.func is not None:
        f = prog.funcs.get(args.func)
        if f is None:
            ap.error("no function decoded at 0x%06X (try --entry 0x%06X)"
                     % (args.func, args.func))
        text = "\n".join(f.lines)
    else:
        text = prog.listing(banner=not args.no_banner)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(text + "\n")
        print("mechadec: wrote %d functions to %s" % (len(prog.funcs), args.out),
              file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
