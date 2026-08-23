"""A small classic-BPF assembler, for filtering in the kernel instead of in Python.

Userspace filtering is fine on a quiet link, but a switch mirror port delivers every
frame on the VLAN - often far more than a Python loop can keep up with. These programs
are attached to the capture socket so the kernel drops what we do not want before it
ever reaches us.

The instruction encoding is identical on Linux (`struct sock_filter`) and BSD/macOS
(`struct bpf_insn`), so one assembler serves both.
"""

import struct

# Instruction classes
LD = 0x00
LDX = 0x01
ALU = 0x04
JMP = 0x05
RET = 0x06

# Operand sizes
W = 0x00
H = 0x08
B = 0x10

# Addressing modes
IMM = 0x00
ABS = 0x20

# ALU operations
AND = 0x50

# Jump operations
JA = 0x00
JEQ = 0x10
JSET = 0x40

# Operand source
K = 0x00
X = 0x08

ETHERTYPE_OFFSET = 12
VLAN_TCI_OFFSET = 14
INNER_ETHERTYPE_OFFSET = 16
INNER_VLAN_TCI_OFFSET = 18

ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_QINQ_LEGACY = 0x9100

VLAN_TPIDS = (ETH_P_8021Q, ETH_P_8021AD, ETH_P_QINQ_LEGACY)

ACCEPT_ALL = 0x0007FFFF          # "keep the whole packet"


class BpfError(ValueError):
    """A program that could not be assembled."""


def assemble(instructions):
    """Turn labelled pseudo-instructions into (code, jt, jf, k) tuples.

    Each instruction is (code, jt, jf, k) where jt/jf may be a label string; labels are
    declared by a bare string in the list. Jumps are resolved to relative offsets.
    """
    labels = {}
    body = []
    for item in instructions:
        if isinstance(item, str):
            if item in labels:
                raise BpfError("duplicate label: %s" % item)
            labels[item] = len(body)
        else:
            body.append(list(item))

    resolved = []
    for index, (code, jt, jf, k) in enumerate(body):
        for slot, value in (("jt", jt), ("jf", jf)):
            if isinstance(value, str):
                if value not in labels:
                    raise BpfError("unknown label: %s" % value)
                offset = labels[value] - index - 1
                if offset < 0 or offset > 255:
                    raise BpfError("jump to %s is out of range (%d)" % (value, offset))
                if slot == "jt":
                    jt = offset
                else:
                    jf = offset
        resolved.append((code, jt, jf, k & 0xFFFFFFFF))
    return resolved


def to_bytes(program):
    """Pack a program into the array of instructions the kernel expects."""
    return b"".join(struct.pack("=HBBI", code, jt, jf, k) for code, jt, jf, k in program)


def accept_all(snaplen=ACCEPT_ALL):
    return assemble([(RET | K, 0, 0, snaplen)])


def reject_all():
    return assemble([(RET | K, 0, 0, 0)])


def vlan_program(vlan_ids, snaplen=ACCEPT_ALL, include_untagged=False):
    """Accept only frames carrying one of `vlan_ids` in their outer 802.1Q tag.

    QinQ frames match on the outer tag; pass the inner id as well if you need it.
    `include_untagged` also keeps frames with no tag at all, which is useful when a
    mirror session strips tags on the way out.
    """
    ids = sorted({int(v) for v in vlan_ids})
    for vid in ids:
        if not 0 <= vid <= 4095:
            raise BpfError("VLAN id out of range: %d" % vid)
    if not ids:
        raise BpfError("no VLAN ids given")

    instructions = [
        (LD | H | ABS, 0, 0, ETHERTYPE_OFFSET),
    ]
    # Any of the tag protocol identifiers means the next two bytes are the TCI.
    for tpid in VLAN_TPIDS:
        instructions.append((JMP | JEQ | K, "tagged", 0, tpid))
    # Falling past every TPID check means the frame carries no tag.
    instructions.append((RET | K, 0, 0, snaplen if include_untagged else 0))

    instructions.append("tagged")
    instructions.append((LD | H | ABS, 0, 0, VLAN_TCI_OFFSET))
    instructions.append((ALU | AND | K, 0, 0, 0x0FFF))
    for vid in ids:
        instructions.append((JMP | JEQ | K, "accept", 0, vid))
    instructions.append((RET | K, 0, 0, 0))
    instructions.append("accept")
    instructions.append((RET | K, 0, 0, snaplen))
    return assemble(instructions)


def tagged_program(snaplen=ACCEPT_ALL):
    """Accept every VLAN-tagged frame, whatever the id."""
    instructions = [(LD | H | ABS, 0, 0, ETHERTYPE_OFFSET)]
    for tpid in VLAN_TPIDS:
        instructions.append((JMP | JEQ | K, "accept", 0, tpid))
    instructions.append((RET | K, 0, 0, 0))
    instructions.append("accept")
    instructions.append((RET | K, 0, 0, snaplen))
    return assemble(instructions)


def snaplen_program(snaplen):
    """Keep every frame, truncated to `snaplen` bytes."""
    return assemble([(RET | K, 0, 0, max(1, int(snaplen)))])


# --- a tiny interpreter, so programs can be verified without a kernel ---------


def run(program, packet):
    """Execute a program against `packet`, returning the number of bytes to keep.

    This mirrors the kernel's classic-BPF virtual machine closely enough to prove a
    program does what it claims, which is how the filters here are tested.
    """
    accumulator = 0
    index = 0
    steps = 0
    while index < len(program):
        steps += 1
        if steps > 4096:
            raise BpfError("program does not terminate")
        code, jt, jf, k = program[index]
        instruction_class = code & 0x07
        if instruction_class == RET:
            if code & 0x18 == 0x10:          # RET | A
                return accumulator
            return k
        if instruction_class == LD:
            mode = code & 0xE0
            size = code & 0x18
            if mode == ABS:
                width = {W: 4, H: 2, B: 1}[size]
                if k + width > len(packet):
                    return 0                  # out of bounds is an implicit drop
                raw = packet[k:k + width]
                accumulator = int.from_bytes(raw, "big")
            elif mode == IMM:
                accumulator = k
            else:
                raise BpfError("unsupported load mode: 0x%02x" % mode)
        elif instruction_class == ALU:
            operation = code & 0xF0
            operand = k if (code & 0x08) == K else 0
            if operation == AND:
                accumulator &= operand
            else:
                raise BpfError("unsupported ALU operation: 0x%02x" % operation)
        elif instruction_class == JMP:
            operation = code & 0xF0
            if operation == JA:
                index += 1 + k
                continue
            operand = k
            if operation == JEQ:
                taken = accumulator == operand
            elif operation == JSET:
                taken = bool(accumulator & operand)
            else:
                raise BpfError("unsupported jump: 0x%02x" % operation)
            index += 1 + (jt if taken else jf)
            continue
        else:
            raise BpfError("unsupported instruction class: %d" % instruction_class)
        index += 1
    return 0
