import re

from keystone.keystone import KsError

import stones


def replace_with_inc_and_dec(template, reg, regs, num, other_op, bad_chars, is_plus):
    new_op = f"{'+'.join(regs)}{'%#+x' % (num + (1 if is_plus else -1))}"

    new_insn_str = f"{'dec' if is_plus else 'inc'} {reg}\n{template.format(new_op)}"
    if reg.strip(" +") != other_op.strip(" +"):
        new_insn_str += f"\n{'inc' if is_plus else 'dec'} {reg}"

    new_shellcode = stones.assemble(new_insn_str)
    if not any(c in bad_chars for c in new_shellcode):
        return new_insn_str

    return None


def parse_op(op, bad_chars):
    regs, nums = [], []
    for num in re.findall(r"([+-]?\s*\w+)", op):
        num = num.replace(" ", "")
        try:
            nums.append(int(num, 16) if "0x" in num else int(num, 10))
        except ValueError as e:
            regs.append(num[1:] if num[0] == "+" else num)

    num = nums[0] & 0xFF
    if num in bad_chars:
        return regs, num

    return None, None


def generate_template(mnemonic, op_str):
    result_1 = re.search(
        r"\s*(\w+),\s*(byte|word|dword)?\s*(ptr)?\s*(\w\w:)?\[(.+?)\]",
        op_str,
    )
    if result_1:
        op_1, dat_type, is_ptr, seg_reg, op_2 = map(
            lambda x: x if x else "", result_1.groups()
        )
        return f"{mnemonic} {op_1}, {dat_type} {is_ptr} {seg_reg}[{{}}]", op_2, op_1

    result_2 = re.search(
        r"\s*(byte|word|dword)?\s*(ptr)?\s*(\w\w:)?\[(.+?)\],\s*(\w+)", op_str
    )
    if result_2:
        dat_type, is_ptr, seg_reg, op_1, op_2 = map(
            lambda x: x if x else "", result_2.groups()
        )
        return f"{mnemonic} {dat_type} {is_ptr} {seg_reg}[{{}}], {op_2}", op_1, op_2

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

    template, op, other_op = generate_template(mnemonic, op_str)
    if not template:
        return None

    regs, num = parse_op(op, bad_chars)
    if not regs:
        return None

    for reg in regs:
        new_insn_str = replace_with_inc_and_dec(
            template, reg, regs, num, other_op, bad_chars, is_plus=True
        )
        if new_insn_str:
            return new_insn_str

        new_insn_str = replace_with_inc_and_dec(
            template, reg, regs, num, other_op, bad_chars, is_plus=False
        )
        if new_insn_str:
            return new_insn_str

    return None
