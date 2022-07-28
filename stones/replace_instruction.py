import re

from keystone.keystone import KsError

import stones

ARITHMETIC_MNEMONICS = ["add", "adc", "sub", "sbb"]
MOVE_MNEMONICS = ["mov", "movzx", "movsx", "lea"]

SRC_PTR_PATTERN = re.compile(r"(\w+),\s*(byte|word|dword)?\s*(ptr)?\s*(\w+:)?\[(.+?)\]")
DST_PTR_PATTERN = re.compile(r"(byte|word|dword)?\s*(ptr)?\s*(\w+:)?\[(.+?)\],\s*(\w+)")


def create_replaced_insn_str(adjust, adjusted_insn_str, ptr_reg, no_after_incdec):
    new_insn_str = ""
    for _ in range(abs(adjust)):
        new_insn_str += f"\n{'dec' if adjust > 0 else 'inc'} {ptr_reg}"

    new_insn_str += f"\n{adjusted_insn_str}"

    if not no_after_incdec:
        for _ in range(abs(adjust)):
            new_insn_str += f"\n{'inc' if adjust > 0 else 'dec'} {ptr_reg}"
    return new_insn_str


def replace_with_incdec(
    adjust, adjusted_insn_str, mnemonic, ptr_reg, op_reg, bad_chars, ptr_is_src
):
    is_same_reg = ptr_reg.strip(" +-") == op_reg.strip(" +-")
    is_arithmetic = mnemonic in ARITHMETIC_MNEMONICS

    if is_same_reg:
        if not ptr_is_src:
            # example: mov [eax + 0x20], eax
            return None
        if mnemonic not in (MOVE_MNEMONICS + ARITHMETIC_MNEMONICS):
            return None

    new_insn_str = create_replaced_insn_str(
        adjust,
        adjusted_insn_str,
        ptr_reg,
        no_after_incdec=is_same_reg and not is_arithmetic,
    )

    new_shellcode = stones.assemble(new_insn_str)
    if not any(c in bad_chars for c in new_shellcode):
        return new_insn_str

    return None


def find_adjust(add_ptr, bad_chars):
    for i in range(1, 0x100 // 2):
        if (add_ptr + i) not in bad_chars and (add_ptr + i) < 0x100:
            return i
        elif ((add_ptr - i) & 0xFF) not in bad_chars:
            return -i


def parse_op_ptr(op_ptr, bad_chars):
    ptr_regs, nums = [], []
    for add_ptr in re.findall(r"([+-]?\s*\w+)", op_ptr):
        add_ptr = add_ptr.replace(" ", "")
        try:
            nums.append(int(add_ptr, 16) if "0x" in add_ptr else int(add_ptr, 10))
        except ValueError as e:
            ptr_regs.append(add_ptr[1:] if add_ptr[0] == "+" else add_ptr)

    add_ptr = nums[0] & 0xFF
    if add_ptr in bad_chars:
        return ptr_regs, add_ptr

    return None, None


def parse_insn(mnemonic, op_str):
    template = op_ptr = op_reg = ptr_is_src = None

    src_ptr_result = SRC_PTR_PATTERN.search(op_str)
    if src_ptr_result:
        op_reg, dat_type, is_ptr, seg_reg, op_ptr = map(
            lambda x: x if x else "", src_ptr_result.groups()
        )
        template = f"{mnemonic} {op_reg}, {dat_type} {is_ptr} {seg_reg}[{{}}]"
        ptr_is_src = True

    dst_ptr_result = DST_PTR_PATTERN.search(op_str)
    if dst_ptr_result:
        dat_type, is_ptr, seg_reg, op_ptr, op_reg = map(
            lambda x: x if x else "", dst_ptr_result.groups()
        )
        template = f"{mnemonic} {dat_type} {is_ptr} {seg_reg}[{{}}], {op_reg}"
        ptr_is_src = False

    return template, op_ptr, op_reg, ptr_is_src


def create_new_insn_str(mnemonic, op_str, bad_chars):
    template, op_ptr, op_reg, ptr_is_src = parse_insn(mnemonic, op_str)
    if not template:
        return None

    ptr_regs, add_ptr = parse_op_ptr(op_ptr, bad_chars)
    if not ptr_regs:
        return None

    adjust = find_adjust(add_ptr, bad_chars)
    if adjust is None:
        return None

    new_op = f"{'+'.join(ptr_regs)}{'%#+x' % (add_ptr + adjust)}"
    adjusted_insn_str = f"{template.format(new_op)}"

    for ptr_reg in ptr_regs:
        new_insn_str = replace_with_incdec(
            adjust, adjusted_insn_str, mnemonic, ptr_reg, op_reg, bad_chars, ptr_is_src
        )
        if new_insn_str:
            return new_insn_str

    return None


def replace_insn(insn_str, bad_chars):
    insn_str = insn_str.strip()

    try:
        insn_bytes = stones.assemble(insn_str)
    except KsError as e:
        return None
    if not insn_bytes:
        return None
    if not any(c in bad_chars for c in insn_bytes):
        return None
    if " " not in insn_str:
        return None

    mnemonic = insn_str[: insn_str.index(" ")].strip()
    op_str = insn_str[insn_str.index(" ") :].strip()
    return create_new_insn_str(mnemonic, op_str, bad_chars)
