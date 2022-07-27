import re

from keystone.keystone import KsError

import stones


def replace_with_inc_and_dec(add_ptr, template, ptr_reg, ptr_regs, op_reg, bad_chars):
    def find_adjust():
        for i in range(1, 0x100 // 2):
            if (add_ptr + i) not in bad_chars and (add_ptr + i) < 0x100:
                return i
            elif ((add_ptr - i) & 0xFF) not in bad_chars:
                return -i

    adjust = find_adjust()
    if adjust is None:
        return None

    new_op = f"{'+'.join(ptr_regs)}{'%#+x' % (add_ptr + adjust)}"

    new_insn_str = ""
    for _ in range(abs(adjust)):
        new_insn_str += f"\n{'dec' if adjust > 0 else 'inc'} {ptr_reg}"

    new_insn_str += f"\n{template.format(new_op)}"

    if ptr_reg.strip(" +") != op_reg.strip(" +"):
        for i in range(abs(adjust)):
            new_insn_str += f"\n{'inc' if adjust > 0 else 'dec'} {ptr_reg}"

    new_shellcode = stones.assemble(new_insn_str)
    if not any(c in bad_chars for c in new_shellcode):
        return new_insn_str

    return None


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


def generate_template(mnemonic, op_str):
    result_1 = re.search(
        r"\s*(\w+),\s*(byte|word|dword)?\s*(ptr)?\s*(\w\w:)?\[(.+?)\]",
        op_str,
    )
    if result_1:
        op_reg, dat_type, is_ptr, seg_reg, op_ptr = map(
            lambda x: x if x else "", result_1.groups()
        )
        return (
            f"{mnemonic} {op_reg}, {dat_type} {is_ptr} {seg_reg}[{{}}]",
            op_ptr,
            op_reg,
        )

    result_2 = re.search(
        r"\s*(byte|word|dword)?\s*(ptr)?\s*(\w\w:)?\[(.+?)\],\s*(\w+)", op_str
    )
    if result_2:
        dat_type, is_ptr, seg_reg, op_ptr, op_reg = map(
            lambda x: x if x else "", result_2.groups()
        )
        return (
            f"{mnemonic} {dat_type} {is_ptr} {seg_reg}[{{}}], {op_reg}",
            op_ptr,
            op_reg,
        )

    return None, None, None


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

    template, op_ptr, op_reg = generate_template(mnemonic, op_str)
    if not template:
        return None

    ptr_regs, add_ptr = parse_op_ptr(op_ptr, bad_chars)
    if not ptr_regs:
        return None

    for ptr_reg in ptr_regs:
        new_insn_str = replace_with_inc_and_dec(
            add_ptr, template, ptr_reg, ptr_regs, op_reg, bad_chars
        )
        if new_insn_str:
            return new_insn_str

    return None
