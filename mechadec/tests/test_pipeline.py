"""
End-to-end pipeline tests: lifter -> cfg -> opt -> structure -> cgen.

These build a small SPC970 program by hand so the expected pseudo-C is known
without needing a ROM, then check the whole-image path when one is available.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import mechadec  # noqa: E402
from mechadec import cfg, cgen, decoder, ir, isa, lifter, loader, opt, structure  # noqa: E402
from mechadec.names import Namer  # noqa: E402

BASE = isa.ROM_BASE


def build(hexstr, entry=BASE):
    data = bytearray(bytes.fromhex(hexstr))
    insns, calls = decoder.decode(data, [entry], BASE)
    funcs = cfg.build_functions(insns, calls, extra_entries=[entry])
    f = funcs[entry]
    opt.optimize(f)
    tree = structure.structure(f)
    return "\n".join(cgen.generate(f, tree, Namer()))


class TestLifting(unittest.TestCase):
    def lift(self, hexstr):
        ins = decoder.decode_one(bytearray(bytes.fromhex(hexstr)), BASE, BASE)
        return lifter.lift_insn(ins)

    def test_mov_destination_is_the_second_operand(self):
        """SPC970 reads source first, destination last."""
        st = self.lift("ccc8")                     # MOV.W RW4, RW0
        self.assertIsInstance(st[0], ir.Assign)
        self.assertEqual(st[0].dst.name, "RW0")
        self.assertEqual(st[0].src.name, "RW4")

    def test_cmp_recovers_a_relation_in_the_right_order(self):
        """CMP src,dst evaluates dst - src, so the comparison reads dst<rel>src."""
        st = self.lift("7210")                     # CMP.B #0x10, RB2
        self.assertIsInstance(st[0], ir.Compare)
        self.assertEqual(st[0].flag.kind, "cmp")
        self.assertEqual(st[0].flag.a.name, "RB2")
        self.assertEqual(st[0].flag.b.value, 0x10)

    def test_postincrement_emits_its_side_effect(self):
        st = self.lift("f3a4c8")                   # MOV.B @(RW4+), RB0
        self.assertEqual(len(st), 2)
        self.assertIsInstance(st[1], ir.Assign)    # the pointer bump
        self.assertEqual(st[1].dst.name, "RW4")
        self.assertEqual(st[1].src.op, "+")

    def test_variable_shift_targets_the_prefix_register(self):
        """Table 4 shifts the prefix register by the op-byte register."""
        st = self.lift("1330")                     # SHLR RB3, RB0
        self.assertEqual(st[0].dst.name, "RB3")
        self.assertEqual(st[0].src.op, ">>")
        self.assertEqual(st[0].src.r.name, "RB0")

    def test_bit_set_becomes_an_or(self):
        st = self.lift("4385")                     # BSET io[0x85].3
        self.assertEqual(st[0].src.op, "|")
        self.assertEqual(st[0].src.r.value, 0x08)


class TestCodegen(unittest.TestCase):
    def test_straight_line_and_return(self):
        # MOV.B #0x12,RB0 ; MOV.B #0x34,RB1 ; RTS
        text = build("6012" "6134" "fa")
        self.assertIn("RB0 = 0x12;", text)
        self.assertIn("RB1 = 0x34;", text)
        self.assertIn("return;", text)
        self.assertIn("void sub_FC0000(void)", text)

    def test_conditional_becomes_an_if(self):
        # CMP.B #5,RB0 ; BNE +2 ; MOV.B #1,RB1 ; RTS
        text = build("7005" "0602" "6101" "fa")
        self.assertIn("if (RB0 == 5)", text)
        self.assertIn("RB1 = 1;", text)

    def test_constant_propagation_folds_the_shift_count(self):
        # MOV.B #6,RB0 ; SHLR RB3,RB0 ; RTS
        text = build("d6c8" "1330" "fa")
        self.assertIn("RB3 = RB3 >> 6;", text)

    def test_named_io_port(self):
        # BSET io[0x18].0 ; RTS   -- 0x18 is a documented MechaCon port
        text = build("4018" "fa")
        self.assertIn("IO_Mech_Error_Flags", text)

    def test_call_renders_as_a_call(self):
        text = build("ec00a0fc" "fa")               # PJSR 0xFCA000 ; RTS
        self.assertIn("sub_FCA000();", text)


class TestWholeImage(unittest.TestCase):
    def setUp(self):
        path = os.environ.get("MECHADEC_TEST_ROM")
        if not path or not os.path.exists(path):
            self.skipTest("set MECHADEC_TEST_ROM to a MechaCon dump")
        self.path = path

    def test_decompiles_and_names_handlers(self):
        prog = mechadec.decompile_file(self.path)
        self.assertGreater(len(prog.funcs), 500)
        names = {f.name for f in prog.funcs.values()}
        self.assertIn("SCMD_81_MG_SessionInit", names)

        listing = prog.listing()
        self.assertIn("Decompiled by mechadec", listing)
        # every function must be emitted as a syntactically balanced body
        for f in prog.funcs.values():
            body = "\n".join(f.lines)
            self.assertEqual(body.count("{"), body.count("}"),
                             "unbalanced braces in %s" % f.name)


if __name__ == "__main__":
    unittest.main()
