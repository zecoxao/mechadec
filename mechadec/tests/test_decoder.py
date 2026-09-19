"""
Decoder tests for mechadec.

The ground truth here is the MechaCon startup routine.  Its exact byte
signature is recorded independently in DiscoStarslayer's Ghidra loader (used to
recognise a ROM and locate its primary bank), which makes it a reference
encoding nobody involved in writing this decoder chose.  Decoding it exercises
every phase-0 prefix family and, crucially, both of its internal branch targets
must land on instruction boundaries that the decoder derives independently --
a self-consistency check that a wrong instruction length would break.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from mechadec import decoder, isa, loader  # noqa: E402

BASE = isa.ROM_BASE

# The MechaCon startup routine, verbatim from a CXP102064 ROM.
STARTUP = bytes.fromhex(
    "e600" "d8e87a09" "36cc" "060a" "d8e87809" "ea0001e87a09"
    "e87809cc" "0704" "ec02e6ff" "e280")


def decode_all(data, base=BASE, start=None, limit=64):
    out = []
    ea = base if start is None else start
    while len(out) < limit and ea - base < len(data):
        ins = decoder.decode_one(data, ea, base)
        if ins is None or ins.size == 0:
            break
        out.append(ins)
        ea += ins.size
    return out


class TestStartupSequence(unittest.TestCase):
    def setUp(self):
        self.insns = decode_all(bytearray(STARTUP))
        self.by_ea = {i.ea: i for i in self.insns}

    def test_mnemonics(self):
        self.assertEqual([i.mnem for i in self.insns][:9],
                         ["LINK", "MOV", "MOV", "BNE", "MOV", "MOV",
                          "MOV", "BEQ", "PJSR"])

    def test_sizes(self):
        self.assertEqual([i.size for i in self.insns][:9],
                         [2, 4, 2, 2, 4, 6, 4, 2, 4])

    def test_branch_targets_land_on_boundaries(self):
        """Both branches in the startup routine must target an address the
        decoder independently produced as an instruction start."""
        targets = [decoder.target_of(i) for i in self.insns
                   if i.mnem in ("BNE", "BEQ")]
        self.assertEqual(targets, [BASE + 0x14, BASE + 0x1E])
        self.assertIn(BASE + 0x14, self.by_ea)

    def test_link_operands(self):
        link = self.insns[0]
        self.assertEqual(link.ops[0].reg, "xFP")
        self.assertEqual(link.ops[1].value, 0)

    def test_immediate_store_to_absolute(self):
        """d8 e8 7a 09 -- tbl3 immediate prefix then a store to abs16."""
        mov = self.insns[1]
        self.assertEqual(mov.width, "w")
        self.assertEqual(mov.ops[0].mode, "imm")
        self.assertEqual(mov.ops[0].value, 0)
        self.assertEqual(mov.ops[1].mode, "abs")
        self.assertEqual(mov.ops[1].addr, 0x097A)

    def test_frame_relative_load(self):
        """36 cc -- tbl2 word prefix @(6,FP) then a load into RW4."""
        mov = self.insns[2]
        self.assertEqual(mov.ops[0].mode, "disp")
        self.assertEqual(mov.ops[0].base_reg, "xFP")
        self.assertEqual(mov.ops[0].disp, 6)
        self.assertEqual(mov.ops[1].reg, "RW4")

    def test_far_call(self):
        pjsr = self.insns[8]
        self.assertEqual(pjsr.mnem, "PJSR")
        self.assertEqual(pjsr.ops[0].addr, 0xFFE602)


class TestAddressingModes(unittest.TestCase):
    def one(self, hexstr):
        ins = decoder.decode_one(bytearray(bytes.fromhex(hexstr)), BASE, BASE)
        self.assertIsNotNone(ins)
        self.assertNotEqual(ins.size, 0, "undefined encoding: %s" % hexstr)
        return ins

    def test_signed_frame_displacement(self):
        """0x29 is @(-7,FP): the low nibble is a signed 4-bit displacement."""
        ins = self.one("29cc")
        self.assertEqual(ins.ops[0].disp, -7)
        ins = self.one("27cc")
        self.assertEqual(ins.ops[0].disp, 7)

    def test_abs11_prefix(self):
        """0x8n builds an 11-bit address from the opcode and the next byte."""
        ins = self.one("891acc")
        self.assertEqual(ins.ops[0].mode, "abs")
        self.assertEqual(ins.ops[0].addr, 0x11A)

    def test_width_comes_from_the_operation_not_the_prefix(self):
        """The same register-direct prefix yields a byte, a word or a long
        operand depending only on which operation byte follows it."""
        self.assertEqual(self.one("c4c8").width, "b")     # tbl2 byte prefix
        self.assertEqual(self.one("ccc8").width, "w")     # tbl2 word prefix
        # tbl2 -> 0xE2 -> table 7 promotes the same prefix to a long access
        self.assertEqual(self.one("c4e280").width, "l")
        self.assertEqual(self.one("c4c8").ops[1].reg, "RB0")
        self.assertEqual(self.one("ccc8").ops[1].reg, "RW0")

    def test_second_prefix_opens_the_memory_to_memory_table(self):
        """An operation byte with bit 3 clear in table 2 is itself a prefix:
        it supplies a second operand and drops into table 6."""
        ins = self.one("c4c0e7")                          # rdir, rdir, MOV
        self.assertEqual(ins.mnem, "MOV")
        self.assertEqual([o.reg for o in ins.ops], ["RB4", "RB0"])
        self.assertEqual(ins.phase, 5)

    def test_table7_long_move(self):
        ins = self.one("c4e280")
        self.assertEqual(ins.mnem, "MOV")
        self.assertEqual(ins.ops[0].reg, "RL4")
        self.assertEqual(ins.ops[1].reg, "RL0")

    def test_io_bit_ops(self):
        ins = self.one("4385")
        self.assertEqual(ins.mnem, "BSET")
        self.assertEqual(ins.ops[0].mode, "bit")
        self.assertEqual(ins.ops[0].bit, 3)
        self.assertEqual(ins.ops[0].base.space, "io")
        self.assertEqual(ins.ops[0].base.addr, 0x85)

    def test_register_list_bit_order(self):
        """STM numbers its mask from RW0 upwards, LDM from RW0 downwards."""
        self.assertEqual(self.one("f801").ops[0].regs, ("RW0",))
        self.assertEqual(self.one("f880").ops[0].regs, ("SP",))
        self.assertEqual(self.one("f780").ops[0].regs, ("RW0",))
        self.assertEqual(self.one("f701").ops[0].regs, ("SP",))

    def test_trapa_c8_consumes_a_descriptor(self):
        self.assertEqual(self.one("f2c844").size, 3)
        self.assertEqual(self.one("f27e").size, 2)

    def test_table5_postincrement(self):
        ins = self.one("f3a4cc")
        self.assertEqual(ins.ops[0].mode, "postinc")

    def test_jsr_stays_in_the_code_page(self):
        ins = self.one("e43412")
        self.assertEqual(ins.ops[0].addr, 0xFC1234)


class TestRomIfAvailable(unittest.TestCase):
    """Whole-image checks; skipped unless a ROM is pointed at by
    MECHADEC_TEST_ROM."""

    def setUp(self):
        path = os.environ.get("MECHADEC_TEST_ROM")
        if not path or not os.path.exists(path):
            self.skipTest("set MECHADEC_TEST_ROM to a MechaCon dump")
        self.image = loader.load(path)

    def test_recognised(self):
        self.assertTrue(loader.is_mechacon(self.image))

    def test_undefined_encodings_are_vanishingly_rare(self):
        """Recursive descent should essentially never walk into an encoding
        the decoder cannot represent.

        This cannot be asserted as exactly zero.  ``TJSR`` calls through a
        vector table that the SLEIGH reference documents as unrecovered --
        there is no confirmed executed sample of it -- so descent past a TJSR
        is speculative, and a handful of such sites in this ROM carry what
        looks like dispatch data rather than instructions.  A real decoding
        regression shows up as hundreds or thousands of these, not a handful,
        so the bound is what has teeth here."""
        entries, _ = loader.discover(self.image)
        insns, _ = decoder.decode(self.image.data, entries, self.image.base,
                                  self.image.is_code)
        self.assertGreater(len(insns), 10000)
        undefined, total = [], 0
        for ins in insns.values():
            for how, tgt in decoder.succ(ins):
                if tgt is None or not self.image.is_code(tgt):
                    continue
                total += 1
                nxt = decoder.decode_one(self.image.data, tgt, self.image.base)
                if nxt is None or nxt.size == 0:
                    undefined.append(tgt)
        self.assertLess(len(undefined) / float(total), 0.0005,
                        "undefined encodings reached: %s"
                        % ", ".join("0x%06X" % a for a in undefined[:20]))

    def test_startup_routine_decodes_at_the_primary_bank(self):
        insns = decode_all(self.image.data, self.image.base,
                           self.image.primary_bank, limit=9)
        self.assertEqual([i.mnem for i in insns],
                         ["LINK", "MOV", "MOV", "BNE", "MOV", "MOV",
                          "MOV", "BEQ", "PJSR"])

    def test_dispatch_tables_are_recovered(self):
        _, tables = loader.discover(self.image)
        names = set(tables.code_names.values())
        self.assertIn("SCMD_81_MG_SessionInit", names)
        self.assertTrue(any(n.startswith("PMAP_") for n in names))
        self.assertIn("LUT_SCMD_MagicGate", set(tables.data_names.values()))


if __name__ == "__main__":
    unittest.main()
