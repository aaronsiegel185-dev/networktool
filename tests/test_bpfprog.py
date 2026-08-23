"""The kernel filter programs, verified by running them in a BPF interpreter."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nettool import bpfprog as bp

MAC_A = bytes.fromhex("001122334455")
MAC_B = bytes.fromhex("66778899aabb")


def frame(vlan=None, tpid=0x8100, inner=None, etype=0x0800, size=60):
    data = MAC_B + MAC_A
    if vlan is not None:
        data += struct.pack("!HH", tpid, vlan)
        if inner is not None:
            data += struct.pack("!HH", 0x8100, inner)
    data += struct.pack("!H", etype)
    return data + b"\x00" * max(0, size - len(data))


class TestAssembler(unittest.TestCase):
    def test_labels_become_relative_offsets(self):
        program = bp.assemble([
            (bp.LD | bp.H | bp.ABS, 0, 0, 12),
            (bp.JMP | bp.JEQ | bp.K, "hit", 0, 0x0800),
            (bp.RET | bp.K, 0, 0, 0),
            "hit",
            (bp.RET | bp.K, 0, 0, 262144),
        ])
        self.assertEqual(len(program), 4)
        self.assertEqual(program[1][1], 1)          # jt skips one instruction
        self.assertEqual(program[1][2], 0)

    def test_unknown_label_is_an_error(self):
        with self.assertRaises(bp.BpfError):
            bp.assemble([(bp.JMP | bp.JEQ | bp.K, "nowhere", 0, 1)])

    def test_duplicate_label_is_an_error(self):
        with self.assertRaises(bp.BpfError):
            bp.assemble(["twice", (bp.RET | bp.K, 0, 0, 0), "twice"])

    def test_packing_matches_the_kernel_struct(self):
        program = bp.snaplen_program(96)
        packed = bp.to_bytes(program)
        self.assertEqual(len(packed), 8 * len(program))
        code, jt, jf, k = struct.unpack("=HBBI", packed[:8])
        self.assertEqual((code, jt, jf, k), (bp.RET | bp.K, 0, 0, 96))


class TestVlanFilters(unittest.TestCase):
    def accepts(self, program, packet):
        return bp.run(program, packet) > 0

    def test_single_vlan(self):
        program = bp.vlan_program([30])
        self.assertTrue(self.accepts(program, frame(30)))
        self.assertFalse(self.accepts(program, frame(31)))
        self.assertFalse(self.accepts(program, frame(None)))

    def test_several_vlans(self):
        program = bp.vlan_program([10, 20, 4094])
        for vlan in (10, 20, 4094):
            self.assertTrue(self.accepts(program, frame(vlan)), vlan)
        for vlan in (11, 21, 4093):
            self.assertFalse(self.accepts(program, frame(vlan)), vlan)

    def test_qinq_matches_on_the_outer_tag(self):
        program = bp.vlan_program([100])
        self.assertTrue(self.accepts(program, frame(100, tpid=0x88A8, inner=30)))
        self.assertTrue(self.accepts(program, frame(100, tpid=0x9100, inner=30)))
        # The inner id is not what the outer filter matches.
        self.assertFalse(self.accepts(bp.vlan_program([30]),
                                      frame(100, tpid=0x88A8, inner=30)))

    def test_untagged_can_be_included(self):
        strict = bp.vlan_program([30])
        lenient = bp.vlan_program([30], include_untagged=True)
        self.assertFalse(self.accepts(strict, frame(None)))
        self.assertTrue(self.accepts(lenient, frame(None)))
        self.assertTrue(self.accepts(lenient, frame(30)))
        self.assertFalse(self.accepts(lenient, frame(40)))

    def test_priority_bits_do_not_affect_matching(self):
        program = bp.vlan_program([30])
        tagged = MAC_B + MAC_A + struct.pack("!HH", 0x8100, (5 << 13) | 30)
        tagged += struct.pack("!H", 0x0800) + b"\x00" * 40
        self.assertTrue(self.accepts(program, tagged))

    def test_snaplen_is_the_return_value(self):
        program = bp.vlan_program([30], snaplen=128)
        self.assertEqual(bp.run(program, frame(30)), 128)
        self.assertEqual(bp.run(program, frame(40)), 0)

    def test_any_tagged_frame(self):
        program = bp.tagged_program()
        self.assertTrue(self.accepts(program, frame(1)))
        self.assertTrue(self.accepts(program, frame(4094, tpid=0x88A8)))
        self.assertFalse(self.accepts(program, frame(None)))

    def test_rejects_bad_input(self):
        with self.assertRaises(bp.BpfError):
            bp.vlan_program([])
        with self.assertRaises(bp.BpfError):
            bp.vlan_program([4096])
        with self.assertRaises(bp.BpfError):
            bp.vlan_program([-1])

    def test_accept_and_reject_helpers(self):
        self.assertGreater(bp.run(bp.accept_all(), frame(None)), 0)
        self.assertEqual(bp.run(bp.reject_all(), frame(30)), 0)


class TestInterpreterSafety(unittest.TestCase):
    def test_reads_past_the_end_drop_the_packet(self):
        program = bp.vlan_program([30])
        self.assertEqual(bp.run(program, b"\x00" * 8), 0)
        self.assertEqual(bp.run(program, b""), 0)

    def test_jump_past_the_end_drops_rather_than_crashing(self):
        # Classic BPF only allows forward jumps, so running off the end is the worst
        # a malformed program can do - and it must be a drop, not an exception.
        program = [(bp.JMP | bp.JA | bp.K, 0, 0, 0xFFFFFFFF)]
        self.assertEqual(bp.run(program, frame(30)), 0)

    def test_unsupported_opcode_is_rejected(self):
        with self.assertRaises(bp.BpfError):
            bp.run([(bp.ALU | 0x00 | bp.K, 0, 0, 1), (bp.RET | bp.K, 0, 0, 1)], frame(30))


if __name__ == "__main__":
    unittest.main()
